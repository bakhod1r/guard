package infrastructure

import (
	"context"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/bakhod1r/guard/identity/domain"
)

// writers returns every AccountWriter implementation holding account "1"
// (password hash "h", status active).
func writers(t *testing.T) map[string]interface {
	domain.UserRepository
	domain.AccountWriter
} {
	t.Helper()
	ctx := context.Background()
	out := map[string]interface {
		domain.UserRepository
		domain.AccountWriter
	}{"memory": NewMemoryUsers()}
	if pool := optionalPool(t); pool != nil {
		hostUsers(t, pool, 2)
		out["postgres"] = NewPostgresUsers(pool)
	}
	for name, w := range out {
		if err := w.Create(ctx, account("1", name+"@b.uz", time.Now().UTC())); err != nil {
			t.Fatal(err)
		}
	}
	return out
}

func TestAccountWriterReserveAttempt(t *testing.T) {
	ctx := context.Background()
	l := domain.Lockout{MaxAttempts: 2, Duration: time.Minute}
	now := time.Now().UTC().Truncate(time.Millisecond)
	for name, w := range writers(t) {
		t.Run(name, func(t *testing.T) {
			for i, want := range []bool{true, true, false} {
				ok, err := w.ReserveAttempt(ctx, "1", now, l)
				if err != nil || ok != want {
					t.Fatalf("attempt %d: ok=%v err=%v", i, ok, err)
				}
			}
			ok, err := w.ReserveAttempt(ctx, "1", now.Add(time.Minute), l)
			u, _ := w.ByID(ctx, "1")
			if !ok || err != nil || u.FailedAttempts != 1 {
				t.Fatalf("expired lock: ok=%v err=%v attempts=%d", ok, err, u.FailedAttempts)
			}
			if ok, err := w.ReserveAttempt(ctx, "1", now, domain.Lockout{Duration: time.Minute}); !ok || err != nil {
				t.Fatalf("lockout disabled: ok=%v err=%v", ok, err)
			}
			for _, id := range []domain.UserID{"2", "x"} {
				if ok, err := w.ReserveAttempt(ctx, id, now, l); ok || err != nil {
					t.Fatalf("missing %s: ok=%v err=%v", id, ok, err)
				}
			}
		})
	}
}

func TestAccountWriterReserveAttemptIsAtomic(t *testing.T) {
	ctx := context.Background()
	l := domain.Lockout{MaxAttempts: 5, Duration: time.Hour}
	for name, w := range writers(t) {
		t.Run(name, func(t *testing.T) {
			var granted atomic.Int32
			var wg sync.WaitGroup
			for range 40 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					if ok, err := w.ReserveAttempt(ctx, "1", time.Now().UTC(), l); err != nil {
						t.Error(err)
					} else if ok {
						granted.Add(1)
					}
				}()
			}
			wg.Wait()
			if granted.Load() != 5 {
				t.Fatalf("granted %d attempts, want 5", granted.Load())
			}
		})
	}
}

func TestAccountWriterRecordLogin(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)
	for name, w := range writers(t) {
		t.Run(name, func(t *testing.T) {
			_, _ = w.ReserveAttempt(ctx, "1", now, domain.DefaultLockout())
			if err := w.RecordLogin(ctx, "1", now, "stale", "h2"); !errors.Is(err, domain.ErrInvalidCredentials) {
				t.Fatalf("stale hash: %v", err)
			}
			if err := w.RecordLogin(ctx, "1", now, "h", "h2"); err != nil {
				t.Fatal(err)
			}
			u, _ := w.ByID(ctx, "1")
			if u.PasswordHash != "h2" || u.FailedAttempts != 0 || u.LastFailedAt != nil || u.LastLoginAt == nil {
				t.Fatalf("after login: %+v", u)
			}
			if err := w.SetStatus(ctx, "1", domain.StatusBanned, now); err != nil {
				t.Fatal(err)
			}
			if err := w.RecordLogin(ctx, "1", now, "h2", "h2"); !errors.Is(err, domain.ErrInvalidCredentials) {
				t.Fatalf("banned: %v", err)
			}
			for _, id := range []domain.UserID{"2", "x"} {
				if err := w.RecordLogin(ctx, id, now, "h", "h"); !errors.Is(err, domain.ErrInvalidCredentials) {
					t.Fatalf("missing %s: %v", id, err)
				}
			}
		})
	}
}

func TestAccountWriterSetters(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)
	for name, w := range writers(t) {
		t.Run(name, func(t *testing.T) {
			_, _ = w.ReserveAttempt(ctx, "1", now, domain.DefaultLockout())
			if err := w.SetSecret(ctx, "1", "wrong", "h2", now); !errors.Is(err, domain.ErrInvalidCredentials) {
				t.Fatalf("conditional mismatch: %v", err)
			}
			if err := w.SetSecret(ctx, "1", "h", "h2", now); err != nil {
				t.Fatal(err)
			}
			if err := w.SetSecret(ctx, "1", "", "h3", now); err != nil {
				t.Fatal(err)
			}
			if err := w.SetStatus(ctx, "1", domain.StatusSuspended, now); err != nil {
				t.Fatal(err)
			}
			if err := w.SetAttributes(ctx, "1", map[string]any{"dept": "ops"}, now); err != nil {
				t.Fatal(err)
			}
			u, _ := w.ByID(ctx, "1")
			if u.PasswordHash != "h3" || u.FailedAttempts != 0 || u.Status != domain.StatusSuspended || u.Attributes["dept"] != "ops" {
				t.Fatalf("after setters: %+v", u)
			}
			for _, id := range []domain.UserID{"2", "x"} {
				if err := w.SetSecret(ctx, id, "", "h", now); !errors.Is(err, domain.ErrUserNotFound) {
					t.Fatalf("secret %s: %v", id, err)
				}
				if err := w.SetStatus(ctx, id, domain.StatusActive, now); !errors.Is(err, domain.ErrUserNotFound) {
					t.Fatalf("status %s: %v", id, err)
				}
				if err := w.SetAttributes(ctx, id, nil, now); !errors.Is(err, domain.ErrUserNotFound) {
					t.Fatalf("attributes %s: %v", id, err)
				}
			}
			if err := w.SetAttributes(ctx, "1", map[string]any{"bad": make(chan int)}, now); err == nil && name == "postgres" {
				t.Fatal("unencodable attributes must fail")
			}
		})
	}
}

// optionalPool is freshPool, or nil without GUARD_TEST_DATABASE_URL.
func optionalPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	if os.Getenv("GUARD_TEST_DATABASE_URL") == "" {
		return nil
	}
	return freshPool(t)
}

func TestAccountWriterSurfacesStorageErrors(t *testing.T) {
	ctx := context.Background()
	pool := freshPool(t)
	r := NewPostgresUsers(pool)
	now := time.Now().UTC()
	pool.Close()
	if _, err := r.ReserveAttempt(ctx, "1", now, domain.DefaultLockout()); err == nil {
		t.Fatal("reserve closed pool: want error")
	}
	if err := r.RecordLogin(ctx, "1", now, "h", "h"); err == nil || errors.Is(err, domain.ErrInvalidCredentials) {
		t.Fatalf("login closed pool: %v", err)
	}
	if err := r.SetSecret(ctx, "1", "h", "h", now); err == nil || errors.Is(err, domain.ErrInvalidCredentials) {
		t.Fatalf("secret closed pool: %v", err)
	}
	if err := r.SetStatus(ctx, "1", domain.StatusActive, now); err == nil || errors.Is(err, domain.ErrUserNotFound) {
		t.Fatalf("status closed pool: %v", err)
	}
	if err := r.SetAttributes(ctx, "1", nil, now); err == nil || errors.Is(err, domain.ErrUserNotFound) {
		t.Fatalf("attributes closed pool: %v", err)
	}
}
