package infrastructure

import (
	"context"
	"sync"

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
