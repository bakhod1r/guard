// Package domain holds identity business rules: users, credentials, lockout.
package domain

import (
	"context"
	"errors"
	"net/mail"
	"strings"
	"time"
)

var (
	ErrInvalidEmail       = errors.New("identity: invalid email")
	ErrWeakPassword       = errors.New("identity: password must be 8-128 characters")
	ErrUserNotFound       = errors.New("identity: user not found")
	ErrEmailTaken         = errors.New("identity: email already registered")
	ErrInvalidCredentials = errors.New("identity: invalid credentials")
	ErrUserBlocked        = errors.New("identity: user is banned or suspended")
	ErrUserLocked         = errors.New("identity: too many failed attempts, try later")
	ErrInvalidStatus      = errors.New("identity: invalid status")
	ErrInvalidUserID      = errors.New("identity: user id is required")
	ErrAccountExists      = errors.New("identity: user already has an account")
)

const (
	MinPasswordLength = 8
	MaxPasswordLength = 128
)

type UserID string

type Email string

// NewEmail normalizes and validates an email address.
func NewEmail(raw string) (Email, error) {
	e := strings.ToLower(strings.TrimSpace(raw))
	addr, err := mail.ParseAddress(e)
	if err != nil || addr.Address != e || len(e) > 255 {
		return "", ErrInvalidEmail
	}
	return Email(e), nil
}

type Status string

const (
	StatusPending   Status = "pending"
	StatusActive    Status = "active"
	StatusBanned    Status = "banned"
	StatusSuspended Status = "suspended"
)

func ParseStatus(s string) (Status, error) {
	switch st := Status(s); st {
	case StatusPending, StatusActive, StatusBanned, StatusSuspended:
		return st, nil
	}
	return "", ErrInvalidStatus
}

// Lockout throttles password guessing per account.
type Lockout struct {
	MaxAttempts int
	Duration    time.Duration
}

func DefaultLockout() Lockout { return Lockout{MaxAttempts: 5, Duration: 15 * time.Minute} }

type User struct {
	ID             UserID
	Email          Email
	Status         Status
	PasswordHash   string
	FailedAttempts int
	LastFailedAt   *time.Time
	Attributes     map[string]any
	LastLoginAt    *time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// Locked reports whether password login is temporarily refused.
func (u *User) Locked(now time.Time, l Lockout) bool {
	return l.MaxAttempts > 0 && u.FailedAttempts >= l.MaxAttempts &&
		u.LastFailedAt != nil && now.Before(u.LastFailedAt.Add(l.Duration))
}

func (u *User) RecordFailedLogin(now time.Time, l Lockout) {
	// An expired lock starts a fresh counting window.
	if u.LastFailedAt != nil && u.FailedAttempts >= l.MaxAttempts && !now.Before(u.LastFailedAt.Add(l.Duration)) {
		u.FailedAttempts = 0
	}
	u.FailedAttempts++
	u.LastFailedAt = &now
	u.UpdatedAt = now
}

func (u *User) RecordLogin(now time.Time) {
	u.FailedAttempts = 0
	u.LastFailedAt = nil
	u.LastLoginAt = &now
	u.UpdatedAt = now
}

// CanLogin reports whether the account status allows a session.
func (u *User) CanLogin() error {
	if u.Status == StatusBanned || u.Status == StatusSuspended {
		return ErrUserBlocked
	}
	return nil
}

// ValidatePassword enforces the password policy on a plaintext password.
func ValidatePassword(plain string) error {
	n := len([]rune(plain))
	if n < MinPasswordLength || n > MaxPasswordLength {
		return ErrWeakPassword
	}
	return nil
}

type UserRepository interface {
	Create(ctx context.Context, u *User) error
	ByID(ctx context.Context, id UserID) (*User, error)
	ByEmail(ctx context.Context, email Email) (*User, error)
	Update(ctx context.Context, u *User) error
	// List returns one page of accounts matching q plus the total match count.
	List(ctx context.Context, q ListQuery) ([]User, int, error)
}

// ListQuery filters account listings. Search matches an email substring
// (case-insensitive) or an exact user id; empty Status matches all.
type ListQuery struct {
	Search string
	Status Status
	Limit  int
	Offset int
}

type PasswordHasher interface {
	Hash(plain string) (string, error)
	Verify(plain, hash string) (bool, error)
}

// Rehasher is an optional PasswordHasher capability: report whether a stored
// hash uses outdated parameters or algorithms and should be replaced after a
// successful login.
type Rehasher interface {
	NeedsRehash(hash string) bool
}
