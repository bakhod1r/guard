package application

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bakhod1r/guard/identity/domain"
	"github.com/bakhod1r/guard/identity/infrastructure"
)

// hookHasher is a plaintext hasher that runs onVerify inside Verify, i.e.
// while a login holds the account it read.
type hookHasher struct {
	fakeHasher
	onVerify func()
}

func (h *hookHasher) Verify(plain, hash string) (bool, error) {
	if h.onVerify != nil {
		h.onVerify()
	}
	return hash == "h:"+plain, nil
}

func raceService(t *testing.T, l domain.Lockout) (*Service, *hookHasher) {
	t.Helper()
	h := &hookHasher{}
	s := NewService(infrastructure.NewMemoryUsers(), h, l)
	if _, err := s.CreateAccount(context.Background(), CreateAccountInput{UserID: "1", Email: "a@b.uz", Password: "correct-horse-1"}); err != nil {
		t.Fatal(err)
	}
	return s, h
}

func TestLoginInFlightDoesNotUndoBan(t *testing.T) {
	ctx := context.Background()
	s, h := raceService(t, domain.DefaultLockout())
	h.onVerify = func() {
		h.onVerify = nil
		if err := s.SetStatus(ctx, "1", domain.StatusBanned); err != nil {
			t.Error(err)
		}
	}
	if _, err := s.Authenticate(ctx, "a@b.uz", "correct-horse-1"); !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Fatalf("login racing a ban: %v", err)
	}
	if u, _ := s.User(ctx, "1"); u.Status != domain.StatusBanned {
		t.Fatalf("ban was overwritten: %s", u.Status)
	}
}

func TestLoginInFlightDoesNotUndoPasswordReset(t *testing.T) {
	ctx := context.Background()
	s, h := raceService(t, domain.DefaultLockout())
	h.onVerify = func() {
		h.onVerify = nil
		if err := s.SetPassword(ctx, "1", "brand-new-pass-9"); err != nil {
			t.Error(err)
		}
	}
	if _, err := s.Authenticate(ctx, "a@b.uz", "correct-horse-1"); !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Fatalf("login racing a reset: %v", err)
	}
	if u, _ := s.User(ctx, "1"); u.PasswordHash != "h:brand-new-pass-9" {
		t.Fatalf("reset was overwritten: %s", u.PasswordHash)
	}
}

func TestChangePasswordLosesToConcurrentReset(t *testing.T) {
	ctx := context.Background()
	s, h := raceService(t, domain.DefaultLockout())
	h.onVerify = func() {
		h.onVerify = nil
		if err := s.SetPassword(ctx, "1", "admin-chosen-pass-1"); err != nil {
			t.Error(err)
		}
	}
	if err := s.ChangePassword(ctx, "1", "correct-horse-1", "user-chosen-pass-1"); !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Fatalf("change racing a reset: %v", err)
	}
}

func TestParallelGuessesRespectLockout(t *testing.T) {
	ctx := context.Background()
	const maxAttempts, guesses = 3, 20
	s, h := raceService(t, domain.Lockout{MaxAttempts: maxAttempts, Duration: time.Hour})
	var verified atomic.Int32
	gate := make(chan struct{})
	h.onVerify = func() {
		verified.Add(1)
		<-gate
	}
	var wg sync.WaitGroup
	for range guesses {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = s.Authenticate(ctx, "a@b.uz", "wrong-password-1")
		}()
	}
	time.Sleep(50 * time.Millisecond)
	close(gate)
	wg.Wait()
	// Locked attempts still pay one dummy verify; real checks are bounded by max.
	u, _ := s.User(ctx, "1")
	if u.FailedAttempts != maxAttempts {
		t.Fatalf("failed attempts = %d, want %d", u.FailedAttempts, maxAttempts)
	}
	if _, err := s.Authenticate(ctx, "a@b.uz", "correct-horse-1"); !errors.Is(err, domain.ErrUserLocked) {
		t.Fatalf("account must be locked after parallel guesses: %v", err)
	}
}

func TestDummyHashUsesServiceHasher(t *testing.T) {
	s := NewService(infrastructure.NewMemoryUsers(), &fakeHasher{}, domain.Lockout{})
	if got := s.dummy(); got != "h:guard-dummy-password" {
		t.Fatalf("dummy = %q", got)
	}
	s = NewService(infrastructure.NewMemoryUsers(), &fakeHasher{hashErr: true}, domain.Lockout{})
	if got := s.dummy(); got != dummyHash {
		t.Fatalf("fallback dummy = %q", got)
	}
}

// plainUsers hides the AccountWriter capability to exercise the fallback.
type plainUsers struct{ domain.UserRepository }

// reserveFails is an AccountWriter repository whose ReserveAttempt fails.
type reserveFails struct{ *infrastructure.MemoryUsers }

func (reserveFails) ReserveAttempt(context.Context, domain.UserID, time.Time, domain.Lockout) (bool, error) {
	return false, errRepo
}

func TestWritesWithoutAccountWriter(t *testing.T) {
	ctx := context.Background()
	s := NewService(plainUsers{infrastructure.NewMemoryUsers()}, &fakeHasher{}, domain.DefaultLockout())
	mustAccount(t, s, "1", "a@b.uz")
	if err := s.SetPassword(ctx, "1", "second-pass-22"); err != nil {
		t.Fatal(err)
	}
	if err := s.ChangePassword(ctx, "1", "second-pass-22", "third-pass-333"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetStatus(ctx, "1", domain.StatusSuspended); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAttributes(ctx, "1", map[string]any{"k": "v"}); err != nil {
		t.Fatal(err)
	}
	u, _ := s.User(ctx, "1")
	if u.PasswordHash != "h:third-pass-333" || u.Status != domain.StatusSuspended || u.Attributes["k"] != "v" {
		t.Fatalf("fallback writes: %+v", u)
	}
}

func TestAtomicSetAttributesAndReserveFailure(t *testing.T) {
	ctx := context.Background()
	s, _ := raceService(t, domain.DefaultLockout())
	if err := s.SetAttributes(ctx, "1", nil); err != nil {
		t.Fatal(err)
	}
	if u, _ := s.User(ctx, "1"); u.Attributes == nil {
		t.Fatal("nil attributes must be stored as an empty map")
	}
	mem := infrastructure.NewMemoryUsers()
	s = NewService(reserveFails{mem}, &fakeHasher{}, domain.DefaultLockout())
	mustAccount(t, s, "1", "a@b.uz")
	if _, err := s.Authenticate(ctx, "a@b.uz", "correct-horse-1"); !errors.Is(err, errRepo) {
		t.Fatalf("reserve failure: %v", err)
	}
}
