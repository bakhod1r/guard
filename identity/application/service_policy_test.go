package application

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/bakhod1r/guard/identity/domain"
)

func TestLockedAccountStillRunsDummyVerify(t *testing.T) {
	ctx := context.Background()
	s, _, h := seeded(t)
	for i := 0; i < 3; i++ {
		_, _ = s.Authenticate(ctx, "a@b.uz", "wrong-pass")
	}
	h.verifies = 0
	if _, err := s.Authenticate(ctx, "a@b.uz", "correct-horse-1"); !errors.Is(err, domain.ErrUserLocked) {
		t.Fatalf("want locked got %v", err)
	}
	if h.verifies != 1 {
		t.Fatalf("locked path must verify once for timing, got %d", h.verifies)
	}
}

// rehashingHasher flags every "h:" hash as outdated; new hashes use "h2:".
type rehashingHasher struct{ fakeHasher }

func (r *rehashingHasher) NeedsRehash(hash string) bool { return !strings.HasPrefix(hash, "h2:") }
func (r *rehashingHasher) Hash(plain string) (string, error) {
	if r.hashErr {
		return "", errHasher
	}
	return "h2:" + plain, nil
}
func (r *rehashingHasher) Verify(plain, hash string) (bool, error) {
	return hash == "h:"+plain || hash == "h2:"+plain, nil
}

func TestAuthenticateRehashesOutdatedHash(t *testing.T) {
	ctx := context.Background()
	s, repo, _ := seeded(t) // stored as "h:correct-horse-1"
	rh := &rehashingHasher{}
	s.hasher = rh

	rh.hashErr = true
	if _, err := s.Authenticate(ctx, "a@b.uz", "correct-horse-1"); err != nil {
		t.Fatalf("rehash failure must not fail login: %v", err)
	}
	if u, _ := repo.ByID(ctx, "1"); u.PasswordHash != "h:correct-horse-1" || u.LastLoginAt == nil {
		t.Fatalf("after failed rehash: %+v", u)
	}

	rh.hashErr = false
	if _, err := s.Authenticate(ctx, "a@b.uz", "correct-horse-1"); err != nil {
		t.Fatal(err)
	}
	if u, _ := repo.ByID(ctx, "1"); u.PasswordHash != "h2:correct-horse-1" {
		t.Fatalf("not rehashed: %q", u.PasswordHash)
	}
}

func TestPasswordPolicyAppliedToAllWrites(t *testing.T) {
	ctx := context.Background()
	s, _, _ := seeded(t)
	if _, err := s.CreateAccount(ctx, CreateAccountInput{UserID: "2", Email: "c@d.uz", Password: "Password123"}); !errors.Is(err, domain.ErrCommonPassword) {
		t.Fatalf("create common: %v", err)
	}
	if _, err := s.CreateAccount(ctx, CreateAccountInput{UserID: "2", Email: "Longname@d.uz", Password: "LONGNAME"}); !errors.Is(err, domain.ErrPasswordMatchesEmail) {
		t.Fatalf("create local part: %v", err)
	}
	if _, err := s.CreateAccount(ctx, CreateAccountInput{UserID: "3", Email: "somebody@d.uz", Password: "correct-horse-1"}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetPassword(ctx, "3", "SomeBody"); !errors.Is(err, domain.ErrPasswordMatchesEmail) {
		t.Fatalf("set local part: %v", err)
	}
	if err := s.SetPassword(ctx, "3", "qwertyuiop"); !errors.Is(err, domain.ErrCommonPassword) {
		t.Fatalf("set common: %v", err)
	}
	if err := s.ChangePassword(ctx, "3", "correct-horse-1", "somebody"); !errors.Is(err, domain.ErrPasswordMatchesEmail) {
		t.Fatalf("change local part: %v", err)
	}
	if err := s.ChangePassword(ctx, "3", "correct-horse-1", "password"); !errors.Is(err, domain.ErrCommonPassword) {
		t.Fatalf("change common: %v", err)
	}
}
