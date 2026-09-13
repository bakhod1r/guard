package application

import (
	"context"
	"testing"
	"time"

	"github.com/bakhod1r/guard/identity/domain"
	"github.com/bakhod1r/guard/identity/infrastructure"
)

func newService(t *testing.T) *Service {
	t.Helper()
	h := &infrastructure.Argon2Hasher{Memory: 1024, Time: 1, Threads: 1, KeyLen: 32, SaltLen: 16}
	return NewService(infrastructure.NewMemoryUsers(), h, domain.Lockout{MaxAttempts: 2, Duration: time.Minute})
}

func TestRegisterAndAuthenticate(t *testing.T) {
	ctx := context.Background()
	s := newService(t)
	u, err := s.Register(ctx, RegisterInput{Email: "Ali@Mail.uz", Password: "password1"})
	if err != nil || u.Status != domain.StatusActive || len(u.ID) != 36 {
		t.Fatalf("register: %+v %v", u, err)
	}
	if _, err := s.Register(ctx, RegisterInput{Email: "ali@mail.uz", Password: "password1"}); err != domain.ErrEmailTaken {
		t.Fatalf("duplicate: %v", err)
	}
	if got, err := s.Authenticate(ctx, "ali@mail.uz", "password1"); err != nil || got.LastLoginAt == nil {
		t.Fatalf("login: %v", err)
	}
	if _, err := s.Authenticate(ctx, "nobody@mail.uz", "password1"); err != domain.ErrInvalidCredentials {
		t.Fatalf("unknown email: %v", err)
	}
}

func TestAuthenticateLockout(t *testing.T) {
	ctx := context.Background()
	s := newService(t)
	_, _ = s.Register(ctx, RegisterInput{Email: "a@b.uz", Password: "password1"})
	for i := 0; i < 2; i++ {
		if _, err := s.Authenticate(ctx, "a@b.uz", "wrong-pass"); err != domain.ErrInvalidCredentials {
			t.Fatal(err)
		}
	}
	if _, err := s.Authenticate(ctx, "a@b.uz", "password1"); err != domain.ErrUserLocked {
		t.Fatalf("want locked, got %v", err)
	}
	s.now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	if _, err := s.Authenticate(ctx, "a@b.uz", "password1"); err != nil {
		t.Fatalf("lock not lifted: %v", err)
	}
}

func TestBannedUserCannotLogin(t *testing.T) {
	ctx := context.Background()
	s := newService(t)
	u, _ := s.Register(ctx, RegisterInput{Email: "a@b.uz", Password: "password1"})
	if err := s.SetStatus(ctx, u.ID, domain.StatusBanned); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(ctx, "a@b.uz", "password1"); err != domain.ErrUserBlocked {
		t.Fatalf("banned login: %v", err)
	}
}

func TestChangePassword(t *testing.T) {
	ctx := context.Background()
	s := newService(t)
	u, _ := s.Register(ctx, RegisterInput{Email: "a@b.uz", Password: "password1"})
	if err := s.ChangePassword(ctx, u.ID, "bad", "password2"); err != domain.ErrInvalidCredentials {
		t.Fatal(err)
	}
	if err := s.ChangePassword(ctx, u.ID, "password1", "password2"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(ctx, "a@b.uz", "password2"); err != nil {
		t.Fatal(err)
	}
}
