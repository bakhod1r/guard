package domain

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestNewEmail(t *testing.T) {
	e, err := NewEmail("  Foo@Example.COM ")
	if err != nil || e != "foo@example.com" {
		t.Fatalf("got %q %v", e, err)
	}
	for _, bad := range []string{"", "nope", "a b@c.d", "name <a@b.c>"} {
		if _, err := NewEmail(bad); err != ErrInvalidEmail {
			t.Errorf("%q: want ErrInvalidEmail, got %v", bad, err)
		}
	}
}

func TestValidatePassword(t *testing.T) {
	if ValidatePassword("short") != ErrWeakPassword {
		t.Fatal("short password accepted")
	}
	if ValidatePassword(strings.Repeat("x", 129)) != ErrWeakPassword {
		t.Fatal("huge password accepted")
	}
	if ValidatePassword("long-enough") != nil {
		t.Fatal("valid password rejected")
	}
}

func TestCanLogin(t *testing.T) {
	for _, st := range []Status{StatusBanned, StatusSuspended} {
		if (&User{Status: st}).CanLogin() != ErrUserBlocked {
			t.Fatalf("%s user can login", st)
		}
	}
	if (&User{Status: StatusActive}).CanLogin() != nil {
		t.Fatal("active user blocked")
	}
}

func TestLockout(t *testing.T) {
	l := Lockout{MaxAttempts: 3, Duration: 10 * time.Minute}
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	u := &User{}
	for i := 0; i < 3; i++ {
		if u.Locked(t0, l) {
			t.Fatalf("locked after %d attempts", i)
		}
		u.RecordFailedLogin(t0, l)
	}
	if !u.Locked(t0.Add(9*time.Minute), l) {
		t.Fatal("not locked after max attempts")
	}
	if u.Locked(t0.Add(10*time.Minute), l) {
		t.Fatal("lock did not expire")
	}
	u.RecordFailedLogin(t0.Add(11*time.Minute), l)
	if u.FailedAttempts != 1 {
		t.Fatalf("window not reset: %d", u.FailedAttempts)
	}
	u.RecordLogin(t0.Add(12 * time.Minute))
	if u.FailedAttempts != 0 || u.LastLoginAt == nil {
		t.Fatal("successful login did not reset counter")
	}
}

func TestParseStatus(t *testing.T) {
	for _, s := range []Status{StatusPending, StatusActive, StatusBanned, StatusSuspended} {
		if got, err := ParseStatus(string(s)); err != nil || got != s {
			t.Fatalf("%s: %q %v", s, got, err)
		}
	}
	for _, bad := range []string{"", "ACTIVE", "deleted"} {
		if _, err := ParseStatus(bad); !errors.Is(err, ErrInvalidStatus) {
			t.Fatalf("%q: %v", bad, err)
		}
	}
}

func TestDefaultLockoutIsFiveAttemptsForFifteenMinutes(t *testing.T) {
	if l := DefaultLockout(); l.MaxAttempts != 5 || l.Duration != 15*time.Minute {
		t.Fatalf("got %+v", l)
	}
}

func TestNewEmailRejectsOverlongAddress(t *testing.T) {
	if _, err := NewEmail(strings.Repeat("a", 251) + "@b.uz"); !errors.Is(err, ErrInvalidEmail) {
		t.Fatalf("got %v", err)
	}
}
