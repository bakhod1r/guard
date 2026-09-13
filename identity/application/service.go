// Package application contains identity use cases.
package application

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/bakhod1r/guard/identity/domain"
)

type Service struct {
	users   domain.UserRepository
	hasher  domain.PasswordHasher
	lockout domain.Lockout
	now     func() time.Time
}

func NewService(users domain.UserRepository, hasher domain.PasswordHasher, lockout domain.Lockout) *Service {
	return &Service{users: users, hasher: hasher, lockout: lockout, now: time.Now}
}

// CreateAccountInput attaches password credentials to a host-owned user.
type CreateAccountInput struct {
	UserID     string
	Email      string
	Password   string
	Attributes map[string]any
}

// CreateAccount stores credentials for an existing host user.
func (s *Service) CreateAccount(ctx context.Context, in CreateAccountInput) (*domain.User, error) {
	id := strings.TrimSpace(in.UserID)
	if id == "" {
		return nil, domain.ErrInvalidUserID
	}
	email, err := domain.NewEmail(in.Email)
	if err != nil {
		return nil, err
	}
	if err := domain.ValidatePassword(in.Password); err != nil {
		return nil, err
	}
	hash, err := s.hasher.Hash(in.Password)
	if err != nil {
		return nil, err
	}
	now := s.now().UTC()
	attrs := in.Attributes
	if attrs == nil {
		attrs = map[string]any{}
	}
	u := &domain.User{
		ID: domain.UserID(id), Email: email, Status: domain.StatusActive, PasswordHash: hash,
		Attributes: attrs, CreatedAt: now, UpdatedAt: now,
	}
	if err := s.users.Create(ctx, u); err != nil {
		return nil, err
	}
	return u, nil
}

// SetPassword is an administrative reset: no old password, clears lockout.
func (s *Service) SetPassword(ctx context.Context, id domain.UserID, newPassword string) error {
	if err := domain.ValidatePassword(newPassword); err != nil {
		return err
	}
	u, err := s.users.ByID(ctx, id)
	if err != nil {
		return err
	}
	if u.PasswordHash, err = s.hasher.Hash(newPassword); err != nil {
		return err
	}
	u.FailedAttempts = 0
	u.LastFailedAt = nil
	u.UpdatedAt = s.now().UTC()
	return s.users.Update(ctx, u)
}

// dummyHash equalizes timing when the email does not exist.
const dummyHash = "$argon2id$v=19$m=65536,t=3,p=2$c29tZXNhbHRzb21lc2FsdA$Zm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFy"

// Authenticate verifies credentials. Unknown email and wrong password
// return the same error to avoid account enumeration.
func (s *Service) Authenticate(ctx context.Context, rawEmail, password string) (*domain.User, error) {
	email, err := domain.NewEmail(rawEmail)
	if err != nil {
		return nil, domain.ErrInvalidCredentials
	}
	u, err := s.users.ByEmail(ctx, email)
	if errors.Is(err, domain.ErrUserNotFound) {
		_, _ = s.hasher.Verify(password, dummyHash)
		return nil, domain.ErrInvalidCredentials
	}
	if err != nil {
		return nil, err
	}
	now := s.now().UTC()
	if u.Locked(now, s.lockout) {
		return nil, domain.ErrUserLocked
	}
	ok, err := s.hasher.Verify(password, u.PasswordHash)
	if err != nil {
		return nil, err
	}
	if !ok {
		u.RecordFailedLogin(now, s.lockout)
		if err := s.users.Update(ctx, u); err != nil {
			return nil, err
		}
		return nil, domain.ErrInvalidCredentials
	}
	if err := u.CanLogin(); err != nil {
		return nil, err
	}
	u.RecordLogin(now)
	if err := s.users.Update(ctx, u); err != nil {
		return nil, err
	}
	return u, nil
}

func (s *Service) ChangePassword(ctx context.Context, id domain.UserID, oldPassword, newPassword string) error {
	u, err := s.users.ByID(ctx, id)
	if err != nil {
		return err
	}
	ok, err := s.hasher.Verify(oldPassword, u.PasswordHash)
	if err != nil {
		return err
	}
	if !ok {
		return domain.ErrInvalidCredentials
	}
	if err := domain.ValidatePassword(newPassword); err != nil {
		return err
	}
	if u.PasswordHash, err = s.hasher.Hash(newPassword); err != nil {
		return err
	}
	u.UpdatedAt = s.now().UTC()
	return s.users.Update(ctx, u)
}

func (s *Service) User(ctx context.Context, id domain.UserID) (*domain.User, error) {
	return s.users.ByID(ctx, id)
}

func (s *Service) UserByEmail(ctx context.Context, rawEmail string) (*domain.User, error) {
	email, err := domain.NewEmail(rawEmail)
	if err != nil {
		return nil, domain.ErrUserNotFound
	}
	return s.users.ByEmail(ctx, email)
}

func (s *Service) SetStatus(ctx context.Context, id domain.UserID, status domain.Status) error {
	u, err := s.users.ByID(ctx, id)
	if err != nil {
		return err
	}
	u.Status = status
	u.UpdatedAt = s.now().UTC()
	return s.users.Update(ctx, u)
}

func (s *Service) SetAttributes(ctx context.Context, id domain.UserID, attrs map[string]any) error {
	u, err := s.users.ByID(ctx, id)
	if err != nil {
		return err
	}
	if attrs == nil {
		attrs = map[string]any{}
	}
	u.Attributes = attrs
	u.UpdatedAt = s.now().UTC()
	return s.users.Update(ctx, u)
}

const (
	DefaultListLimit = 25
	MaxListLimit     = 100
)

// ListUsers returns a page of accounts; Limit is clamped to 1..100 (default 25).
func (s *Service) ListUsers(ctx context.Context, q domain.ListQuery) ([]domain.User, int, error) {
	q.Search = strings.TrimSpace(q.Search)
	if q.Limit <= 0 {
		q.Limit = DefaultListLimit
	}
	if q.Limit > MaxListLimit {
		q.Limit = MaxListLimit
	}
	if q.Offset < 0 {
		q.Offset = 0
	}
	return s.users.List(ctx, q)
}
