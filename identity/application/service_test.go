package application

import (
	"context"
	"errors"
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

func mustAccount(t *testing.T, s *Service, id, email string) *domain.User {
	t.Helper()
	u, err := s.CreateAccount(context.Background(), CreateAccountInput{UserID: id, Email: email, Password: "correct-horse-1"})
	if err != nil {
		t.Fatalf("create account %s: %v", id, err)
	}
	return u
}

func TestCreateAccountAndAuthenticate(t *testing.T) {
	ctx := context.Background()
	s := newService(t)
	u, err := s.CreateAccount(ctx, CreateAccountInput{UserID: " 42 ", Email: "Ali@Mail.uz", Password: "correct-horse-1"})
	if err != nil || u.ID != "42" || u.Status != domain.StatusActive || u.Email != "ali@mail.uz" || u.Attributes == nil {
		t.Fatalf("create: %+v %v", u, err)
	}
	if u.CreatedAt.IsZero() || u.CreatedAt.Location() != time.UTC {
		t.Fatalf("created_at: %v", u.CreatedAt)
	}
	if _, err := s.CreateAccount(ctx, CreateAccountInput{UserID: "43", Email: "ali@mail.uz", Password: "correct-horse-1"}); !errors.Is(err, domain.ErrEmailTaken) {
		t.Fatalf("duplicate email: %v", err)
	}
	if got, err := s.Authenticate(ctx, "ali@mail.uz", "correct-horse-1"); err != nil || got.LastLoginAt == nil || got.ID != "42" {
		t.Fatalf("login: %v", err)
	}
	if _, err := s.Authenticate(ctx, "nobody@mail.uz", "correct-horse-1"); !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Fatalf("unknown email: %v", err)
	}
}

func TestCreateAccountUUIDUserID(t *testing.T) {
	s := newService(t)
	id := "0191f2a4-7c3e-7b1a-9d2f-3c4b5a6d7e8f"
	u := mustAccount(t, s, id, "u@b.uz")
	got, err := s.User(context.Background(), u.ID)
	if err != nil || string(got.ID) != id {
		t.Fatalf("by id: %+v %v", got, err)
	}
}

func TestCreateAccountInvalidUserID(t *testing.T) {
	s := newService(t)
	for _, id := range []string{"", "   "} {
		if _, err := s.CreateAccount(context.Background(), CreateAccountInput{UserID: id, Email: "a@b.uz", Password: "correct-horse-1"}); !errors.Is(err, domain.ErrInvalidUserID) {
			t.Fatalf("id %q: %v", id, err)
		}
	}
}

func TestCreateAccountValidation(t *testing.T) {
	s := newService(t)
	ctx := context.Background()
	if _, err := s.CreateAccount(ctx, CreateAccountInput{UserID: "1", Email: "bad", Password: "correct-horse-1"}); !errors.Is(err, domain.ErrInvalidEmail) {
		t.Fatalf("email: %v", err)
	}
	if _, err := s.CreateAccount(ctx, CreateAccountInput{UserID: "1", Email: "a@b.uz", Password: "short"}); !errors.Is(err, domain.ErrWeakPassword) {
		t.Fatalf("password: %v", err)
	}
}

func TestCreateAccountExists(t *testing.T) {
	s := newService(t)
	mustAccount(t, s, "42", "a@b.uz")
	if _, err := s.CreateAccount(context.Background(), CreateAccountInput{UserID: "42", Email: "other@b.uz", Password: "correct-horse-1"}); !errors.Is(err, domain.ErrAccountExists) {
		t.Fatalf("want ErrAccountExists, got %v", err)
	}
}

func TestAuthenticateLockout(t *testing.T) {
	ctx := context.Background()
	s := newService(t)
	mustAccount(t, s, "1", "a@b.uz")
	for i := 0; i < 2; i++ {
		if _, err := s.Authenticate(ctx, "a@b.uz", "wrong-pass"); !errors.Is(err, domain.ErrInvalidCredentials) {
			t.Fatal(err)
		}
	}
	if _, err := s.Authenticate(ctx, "a@b.uz", "correct-horse-1"); !errors.Is(err, domain.ErrUserLocked) {
		t.Fatalf("want locked, got %v", err)
	}
	s.now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	if _, err := s.Authenticate(ctx, "a@b.uz", "correct-horse-1"); err != nil {
		t.Fatalf("lock not lifted: %v", err)
	}
}

func TestBannedUserCannotLogin(t *testing.T) {
	ctx := context.Background()
	s := newService(t)
	u := mustAccount(t, s, "1", "a@b.uz")
	if err := s.SetStatus(ctx, u.ID, domain.StatusBanned); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(ctx, "a@b.uz", "correct-horse-1"); !errors.Is(err, domain.ErrUserBlocked) {
		t.Fatalf("banned login: %v", err)
	}
}

func TestChangePassword(t *testing.T) {
	ctx := context.Background()
	s := newService(t)
	u := mustAccount(t, s, "1", "a@b.uz")
	if err := s.ChangePassword(ctx, u.ID, "bad", "battery-staple-2"); !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Fatal(err)
	}
	if err := s.ChangePassword(ctx, u.ID, "correct-horse-1", "battery-staple-2"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(ctx, "a@b.uz", "battery-staple-2"); err != nil {
		t.Fatal(err)
	}
}

func TestSetPasswordResetsLockout(t *testing.T) {
	ctx := context.Background()
	s := newService(t)
	u := mustAccount(t, s, "7", "a@b.uz")
	for i := 0; i < 2; i++ {
		_, _ = s.Authenticate(ctx, "a@b.uz", "wrong-pass")
	}
	if _, err := s.Authenticate(ctx, "a@b.uz", "correct-horse-1"); !errors.Is(err, domain.ErrUserLocked) {
		t.Fatalf("want locked, got %v", err)
	}
	if err := s.SetPassword(ctx, u.ID, "short"); !errors.Is(err, domain.ErrWeakPassword) {
		t.Fatalf("weak: %v", err)
	}
	if err := s.SetPassword(ctx, u.ID, "new-password"); err != nil {
		t.Fatal(err)
	}
	got, _ := s.User(ctx, u.ID)
	if got.FailedAttempts != 0 || got.LastFailedAt != nil {
		t.Fatalf("lockout not reset: %+v", got)
	}
	if _, err := s.Authenticate(ctx, "a@b.uz", "correct-horse-1"); !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Fatalf("old password: %v", err)
	}
	if _, err := s.Authenticate(ctx, "a@b.uz", "new-password"); err != nil {
		t.Fatalf("new password: %v", err)
	}
	if err := s.SetPassword(ctx, "missing", "new-password"); !errors.Is(err, domain.ErrUserNotFound) {
		t.Fatalf("missing: %v", err)
	}
}

// listSpy records the query the service passes to the repository.
type listSpy struct {
	domain.UserRepository
	got domain.ListQuery
}

func (l *listSpy) List(_ context.Context, q domain.ListQuery) ([]domain.User, int, error) {
	l.got = q
	return nil, 0, nil
}

func TestListUsersClampsPaging(t *testing.T) {
	cases := []struct {
		in, want domain.ListQuery
	}{
		{domain.ListQuery{}, domain.ListQuery{Limit: 25}},
		{domain.ListQuery{Limit: -3, Offset: -1}, domain.ListQuery{Limit: 25}},
		{domain.ListQuery{Limit: 500, Offset: 10}, domain.ListQuery{Limit: 100, Offset: 10}},
		{domain.ListQuery{Limit: 7, Search: " a ", Status: domain.StatusBanned}, domain.ListQuery{Limit: 7, Search: "a", Status: domain.StatusBanned}},
	}
	for _, tc := range cases {
		spy := &listSpy{}
		s := NewService(spy, nil, domain.Lockout{})
		if _, _, err := s.ListUsers(context.Background(), tc.in); err != nil {
			t.Fatal(err)
		}
		if spy.got != tc.want {
			t.Fatalf("in %+v: got %+v want %+v", tc.in, spy.got, tc.want)
		}
	}
}

func TestListUsersMemory(t *testing.T) {
	s := newService(t)
	mustAccount(t, s, "1", "a@b.uz")
	mustAccount(t, s, "2", "c@d.uz")
	users, total, err := s.ListUsers(context.Background(), domain.ListQuery{Search: "A@B"})
	if err != nil || total != 1 || len(users) != 1 || users[0].ID != "1" {
		t.Fatalf("list: %+v %d %v", users, total, err)
	}
}
