package application

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bakhod1r/guard/identity/domain"
	"github.com/bakhod1r/guard/identity/infrastructure"
)

var (
	errRepo   = errors.New("repo down")
	errHasher = errors.New("hasher down")
)

// failingUsers wraps a working repository and fails the selected operations.
type failingUsers struct {
	domain.UserRepository
	create, byID, byEmail, update bool
}

func (f *failingUsers) Create(ctx context.Context, u *domain.User) error {
	if f.create {
		return errRepo
	}
	return f.UserRepository.Create(ctx, u)
}

func (f *failingUsers) ByID(ctx context.Context, id domain.UserID) (*domain.User, error) {
	if f.byID {
		return nil, errRepo
	}
	return f.UserRepository.ByID(ctx, id)
}

func (f *failingUsers) ByEmail(ctx context.Context, e domain.Email) (*domain.User, error) {
	if f.byEmail {
		return nil, errRepo
	}
	return f.UserRepository.ByEmail(ctx, e)
}

func (f *failingUsers) Update(ctx context.Context, u *domain.User) error {
	if f.update {
		return errRepo
	}
	return f.UserRepository.Update(ctx, u)
}

// fakeHasher is a plaintext hasher with switchable failures.
type fakeHasher struct {
	hashErr, verifyErr bool
}

func (h *fakeHasher) Hash(plain string) (string, error) {
	if h.hashErr {
		return "", errHasher
	}
	return "h:" + plain, nil
}

func (h *fakeHasher) Verify(plain, hash string) (bool, error) {
	if h.verifyErr {
		return false, errHasher
	}
	return hash == "h:"+plain, nil
}

// seeded returns a service with account 1/a@b.uz (password "password1") and
// handles to toggle repository and hasher failures afterwards.
func seeded(t *testing.T) (*Service, *failingUsers, *fakeHasher) {
	t.Helper()
	repo := &failingUsers{UserRepository: infrastructure.NewMemoryUsers()}
	h := &fakeHasher{}
	s := NewService(repo, h, domain.Lockout{MaxAttempts: 3, Duration: time.Minute})
	if _, err := s.CreateAccount(context.Background(), CreateAccountInput{UserID: "1", Email: "a@b.uz", Password: "password1"}); err != nil {
		t.Fatal(err)
	}
	return s, repo, h
}

func TestServicePropagatesDependencyErrors(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name string
		arm  func(*failingUsers, *fakeHasher)
		call func(*Service) error
		want error
	}{
		{"create account hasher fails", func(_ *failingUsers, h *fakeHasher) { h.hashErr = true },
			func(s *Service) error {
				_, err := s.CreateAccount(ctx, CreateAccountInput{UserID: "2", Email: "c@d.uz", Password: "password1"})
				return err
			}, errHasher},
		{"create account repository fails", func(r *failingUsers, _ *fakeHasher) { r.create = true },
			func(s *Service) error {
				_, err := s.CreateAccount(ctx, CreateAccountInput{UserID: "2", Email: "c@d.uz", Password: "password1"})
				return err
			}, errRepo},
		{"set password hasher fails", func(_ *failingUsers, h *fakeHasher) { h.hashErr = true },
			func(s *Service) error { return s.SetPassword(ctx, "1", "password2") }, errHasher},
		{"authenticate lookup fails", func(r *failingUsers, _ *fakeHasher) { r.byEmail = true },
			func(s *Service) error { _, err := s.Authenticate(ctx, "a@b.uz", "password1"); return err }, errRepo},
		{"authenticate invalid email", nil,
			func(s *Service) error { _, err := s.Authenticate(ctx, "bad", "password1"); return err }, domain.ErrInvalidCredentials},
		{"authenticate verify fails", func(_ *failingUsers, h *fakeHasher) { h.verifyErr = true },
			func(s *Service) error { _, err := s.Authenticate(ctx, "a@b.uz", "password1"); return err }, errHasher},
		{"authenticate failed-attempt update fails", func(r *failingUsers, _ *fakeHasher) { r.update = true },
			func(s *Service) error { _, err := s.Authenticate(ctx, "a@b.uz", "wrong-pass"); return err }, errRepo},
		{"authenticate success update fails", func(r *failingUsers, _ *fakeHasher) { r.update = true },
			func(s *Service) error { _, err := s.Authenticate(ctx, "a@b.uz", "password1"); return err }, errRepo},
		{"change password lookup fails", func(r *failingUsers, _ *fakeHasher) { r.byID = true },
			func(s *Service) error { return s.ChangePassword(ctx, "1", "password1", "password2") }, errRepo},
		{"change password verify fails", func(_ *failingUsers, h *fakeHasher) { h.verifyErr = true },
			func(s *Service) error { return s.ChangePassword(ctx, "1", "password1", "password2") }, errHasher},
		{"change password weak new password", nil,
			func(s *Service) error { return s.ChangePassword(ctx, "1", "password1", "short") }, domain.ErrWeakPassword},
		{"change password hasher fails", func(_ *failingUsers, h *fakeHasher) { h.hashErr = true },
			func(s *Service) error { return s.ChangePassword(ctx, "1", "password1", "password2") }, errHasher},
		{"set status lookup fails", func(r *failingUsers, _ *fakeHasher) { r.byID = true },
			func(s *Service) error { return s.SetStatus(ctx, "1", domain.StatusBanned) }, errRepo},
		{"set attributes lookup fails", func(r *failingUsers, _ *fakeHasher) { r.byID = true },
			func(s *Service) error { return s.SetAttributes(ctx, "1", nil) }, errRepo},
		{"set attributes update fails", func(r *failingUsers, _ *fakeHasher) { r.update = true },
			func(s *Service) error { return s.SetAttributes(ctx, "1", nil) }, errRepo},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, repo, h := seeded(t)
			if tc.arm != nil {
				tc.arm(repo, h)
			}
			if err := tc.call(s); !errors.Is(err, tc.want) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
		})
	}
}

func TestSetAttributesReplacesAndDefaultsToEmptyMap(t *testing.T) {
	ctx := context.Background()
	s, _, _ := seeded(t)
	if err := s.SetAttributes(ctx, "1", map[string]any{"dept": "it"}); err != nil {
		t.Fatal(err)
	}
	if u, _ := s.User(ctx, "1"); u.Attributes["dept"] != "it" {
		t.Fatalf("attrs: %+v", u.Attributes)
	}
	if err := s.SetAttributes(ctx, "1", nil); err != nil {
		t.Fatal(err)
	}
	if u, _ := s.User(ctx, "1"); u.Attributes == nil || len(u.Attributes) != 0 {
		t.Fatalf("attrs: %+v", u.Attributes)
	}
}

func TestUserByEmailNormalizesAndHidesInvalidInput(t *testing.T) {
	ctx := context.Background()
	s, _, _ := seeded(t)
	if u, err := s.UserByEmail(ctx, " A@B.uz "); err != nil || u.ID != "1" {
		t.Fatalf("got %+v %v", u, err)
	}
	if _, err := s.UserByEmail(ctx, "not-an-email"); !errors.Is(err, domain.ErrUserNotFound) {
		t.Fatalf("invalid: %v", err)
	}
}
