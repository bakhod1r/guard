package infrastructure

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/bakhod1r/guard/identity/domain"
)

// MemoryUsers is an in-process UserRepository for tests and prototypes.
type MemoryUsers struct {
	mu   sync.RWMutex
	byID map[domain.UserID]domain.User
}

func NewMemoryUsers() *MemoryUsers { return &MemoryUsers{byID: map[domain.UserID]domain.User{}} }

func (m *MemoryUsers) Create(_ context.Context, u *domain.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.byID[u.ID]; ok {
		return domain.ErrAccountExists
	}
	for _, x := range m.byID {
		if x.Email == u.Email {
			return domain.ErrEmailTaken
		}
	}
	m.byID[u.ID] = *u
	return nil
}

func (m *MemoryUsers) Update(_ context.Context, u *domain.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.byID[u.ID]; !ok {
		return domain.ErrUserNotFound
	}
	m.byID[u.ID] = *u
	return nil
}

// modify applies fn to the stored account under the write lock.
func (m *MemoryUsers) modify(id domain.UserID, fn func(u *domain.User) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.byID[id]
	if !ok {
		return domain.ErrUserNotFound
	}
	if err := fn(&u); err != nil {
		return err
	}
	m.byID[id] = u
	return nil
}

func (m *MemoryUsers) ReserveAttempt(_ context.Context, id domain.UserID, now time.Time, l domain.Lockout) (bool, error) {
	reserved := false
	err := m.modify(id, func(u *domain.User) error {
		reserved = u.ReserveAttempt(now, l)
		return nil
	})
	if errors.Is(err, domain.ErrUserNotFound) {
		return false, nil
	}
	return reserved, err
}

func (m *MemoryUsers) RecordLogin(_ context.Context, id domain.UserID, now time.Time, verifiedHash, newHash string) error {
	err := m.modify(id, func(u *domain.User) error {
		if u.PasswordHash != verifiedHash || u.CanLogin() != nil {
			return domain.ErrInvalidCredentials
		}
		u.RecordLogin(now)
		u.PasswordHash = newHash
		return nil
	})
	if errors.Is(err, domain.ErrUserNotFound) {
		return domain.ErrInvalidCredentials
	}
	return err
}

func (m *MemoryUsers) SetSecret(_ context.Context, id domain.UserID, oldHash, hash string, now time.Time) error {
	return m.modify(id, func(u *domain.User) error {
		if oldHash != "" && u.PasswordHash != oldHash {
			return domain.ErrInvalidCredentials
		}
		u.PasswordHash, u.FailedAttempts, u.LastFailedAt, u.UpdatedAt = hash, 0, nil, now
		return nil
	})
}

func (m *MemoryUsers) SetStatus(_ context.Context, id domain.UserID, status domain.Status, now time.Time) error {
	return m.modify(id, func(u *domain.User) error {
		u.Status, u.UpdatedAt = status, now
		return nil
	})
}

func (m *MemoryUsers) SetAttributes(_ context.Context, id domain.UserID, attrs map[string]any, now time.Time) error {
	return m.modify(id, func(u *domain.User) error {
		u.Attributes, u.UpdatedAt = attrs, now
		return nil
	})
}

func (m *MemoryUsers) ByID(_ context.Context, id domain.UserID) (*domain.User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	u, ok := m.byID[id]
	if !ok {
		return nil, domain.ErrUserNotFound
	}
	return &u, nil
}

func (m *MemoryUsers) ByEmail(_ context.Context, email domain.Email) (*domain.User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, u := range m.byID {
		if u.Email == email {
			return &u, nil
		}
	}
	return nil, domain.ErrUserNotFound
}

func (m *MemoryUsers) List(_ context.Context, q domain.ListQuery) ([]domain.User, int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	needle := strings.ToLower(q.Search)
	out := []domain.User{}
	for _, u := range m.byID {
		if q.Search != "" && !strings.Contains(strings.ToLower(string(u.Email)), needle) && string(u.ID) != q.Search {
			continue
		}
		if q.Status != "" && u.Status != q.Status {
			continue
		}
		out = append(out, u)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].ID < out[j].ID
	})
	total := len(out)
	start := min(q.Offset, total)
	end := min(start+q.Limit, total)
	return out[start:end], total, nil
}
