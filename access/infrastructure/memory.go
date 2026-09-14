package infrastructure

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/bakhod1r/guard/access/domain"
)

// Memory is an in-process role and policy store for tests and prototypes.
type Memory struct {
	mu          sync.RWMutex
	roles       map[string]*domain.Role
	permissions map[string]domain.Permission
	grants      map[string]map[string]*time.Time // user -> role -> expiry
	policies    map[string]domain.Policy
}

func NewMemory() *Memory {
	return &Memory{
		roles:       map[string]*domain.Role{},
		permissions: map[string]domain.Permission{},
		grants:      map[string]map[string]*time.Time{},
		policies:    map[string]domain.Policy{},
	}
}

func (m *Memory) CreateRole(_ context.Context, r *domain.Role) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.roles[r.Name]; ok {
		return domain.ErrRoleExists
	}
	cp := *r
	cp.Permissions = append([]domain.Permission{}, r.Permissions...)
	m.roles[r.Name] = &cp
	return nil
}

func (m *Memory) DeleteRole(_ context.Context, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.roles[name]; !ok {
		return domain.ErrRoleNotFound
	}
	delete(m.roles, name)
	for _, g := range m.grants {
		delete(g, name)
	}
	return nil
}

func (m *Memory) Role(_ context.Context, name string) (*domain.Role, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	r, ok := m.roles[name]
	if !ok {
		return nil, domain.ErrRoleNotFound
	}
	cp := *r
	cp.Permissions = append([]domain.Permission{}, r.Permissions...)
	return &cp, nil
}

func (m *Memory) ListRoles(ctx context.Context) ([]domain.Role, error) {
	m.mu.RLock()
	names := make([]string, 0, len(m.roles))
	for n := range m.roles {
		names = append(names, n)
	}
	m.mu.RUnlock()
	sort.Strings(names)
	out := make([]domain.Role, 0, len(names))
	for _, n := range names {
		if r, err := m.Role(ctx, n); err == nil {
			out = append(out, *r)
		}
	}
	return out, nil
}

func (m *Memory) CreatePermission(_ context.Context, p domain.Permission) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.permissions[p.Code()] = p
	return nil
}

func (m *Memory) ListPermissions(_ context.Context) ([]domain.Permission, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]domain.Permission, 0, len(m.permissions))
	for _, p := range m.permissions {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Code() < out[j].Code() })
	return out, nil
}

func (m *Memory) GrantPermission(_ context.Context, role string, p domain.Permission, _ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.roles[role]
	if !ok {
		return domain.ErrRoleNotFound
	}
	stored, ok := m.permissions[p.Code()]
	if !ok {
		return domain.ErrPermissionNotFound
	}
	for _, x := range r.Permissions {
		if x.Code() == p.Code() {
			return nil
		}
	}
	r.Permissions = append(r.Permissions, stored)
	return nil
}

func (m *Memory) RevokePermission(_ context.Context, role string, p domain.Permission) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.roles[role]
	if !ok {
		return nil
	}
	kept := r.Permissions[:0]
	for _, x := range r.Permissions {
		if x.Code() != p.Code() {
			kept = append(kept, x)
		}
	}
	r.Permissions = kept
	return nil
}

func (m *Memory) AssignRole(_ context.Context, userID, role, _ string, expiresAt *time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.roles[role]; !ok {
		return domain.ErrRoleNotFound
	}
	if m.grants[userID] == nil {
		m.grants[userID] = map[string]*time.Time{}
	}
	m.grants[userID][role] = expiresAt
	return nil
}

func (m *Memory) UnassignRole(_ context.Context, userID, role string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.grants[userID], role)
	return nil
}

func (m *Memory) GrantsOf(ctx context.Context, userID string) ([]domain.RoleGrant, error) {
	m.mu.RLock()
	names := map[string]*time.Time{}
	for n, exp := range m.grants[userID] {
		names[n] = exp
	}
	m.mu.RUnlock()
	out := []domain.RoleGrant{}
	for n, exp := range names {
		r, err := m.Role(ctx, n)
		if err != nil {
			continue
		}
		out = append(out, domain.RoleGrant{Role: *r, ExpiresAt: exp})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Role.Name < out[j].Role.Name })
	return out, nil
}

func (m *Memory) SavePolicy(_ context.Context, p *domain.Policy) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, x := range m.policies {
		if x.Name == p.Name && id != p.ID {
			return domain.ErrPolicyNameTaken
		}
	}
	m.policies[p.ID] = *p
	return nil
}

func (m *Memory) DeletePolicy(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.policies[id]; !ok {
		return domain.ErrPolicyNotFound
	}
	delete(m.policies, id)
	return nil
}

func (m *Memory) Policy(_ context.Context, id string) (*domain.Policy, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p, ok := m.policies[id]
	if !ok {
		return nil, domain.ErrPolicyNotFound
	}
	return &p, nil
}

func (m *Memory) ListPolicies(_ context.Context) ([]domain.Policy, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]domain.Policy, 0, len(m.policies))
	for _, p := range m.policies {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Priority != out[j].Priority {
			return out[i].Priority < out[j].Priority
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

func (m *Memory) ApplicablePolicies(ctx context.Context, resource, action string) ([]domain.Policy, error) {
	all, _ := m.ListPolicies(ctx)
	out := all[:0]
	for _, p := range all {
		if p.Enabled && (p.Resource == "*" || p.Resource == resource) && (p.Action == "*" || p.Action == action) {
			out = append(out, p)
		}
	}
	return out, nil
}

// RoleHolders returns users holding a non-expired grant of role, sorted.
func (m *Memory) RoleHolders(_ context.Context, role string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.holders(role), nil
}

func (m *Memory) holders(role string) []string {
	now := time.Now()
	out := []string{}
	for user, roles := range m.grants {
		if exp, ok := roles[role]; ok && (exp == nil || now.Before(*exp)) {
			out = append(out, user)
		}
	}
	sort.Strings(out)
	return out
}

// UnassignRoleChecked removes the grant only when check(holders) is nil; the
// store lock serialises it against every other write.
func (m *Memory) UnassignRoleChecked(_ context.Context, userID, role string, check func([]string) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.roles[role]; !ok {
		return nil
	}
	if err := check(m.holders(role)); err != nil {
		return err
	}
	delete(m.grants[userID], role)
	return nil
}
