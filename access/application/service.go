// Package application contains authorization use cases.
package application

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/bakhod1r/guard/access/domain"
)

type Service struct {
	roles    domain.RoleRepository
	policies domain.PolicyRepository
	now      func() time.Time
	sa       superAdminState
}

func NewService(roles domain.RoleRepository, policies domain.PolicyRepository) *Service {
	return &Service{roles: roles, policies: policies, now: time.Now}
}

// ActiveRoles returns the non-expired roles held by a user.
func (s *Service) ActiveRoles(ctx context.Context, userID string) ([]domain.Role, error) {
	grants, err := s.roles.GrantsOf(ctx, userID)
	if err != nil {
		return nil, err
	}
	now := s.now()
	roles := make([]domain.Role, 0, len(grants))
	for _, g := range grants {
		if g.Active(now) {
			roles = append(roles, g.Role)
		}
	}
	return roles, nil
}

// Authorize decides a request. Subject.Roles is loaded when nil.
func (s *Service) Authorize(ctx context.Context, r domain.Request) (domain.Decision, error) {
	if r.Subject.Roles == nil && r.Subject.ID != "" {
		roles, err := s.ActiveRoles(ctx, r.Subject.ID)
		if err != nil {
			return domain.Decision{}, err
		}
		r.Subject.Roles = roles
	}
	if r.Environment == nil {
		r.Environment = map[string]any{}
	}
	if _, ok := r.Environment["now"]; !ok {
		r.Environment["now"] = s.now().UTC().Format(time.RFC3339)
	}
	policies, err := s.policies.ApplicablePolicies(ctx, r.Resource.Type, r.Action)
	if err != nil {
		return domain.Decision{}, err
	}
	return domain.Decide(r, policies), nil
}

func (s *Service) CreateRole(ctx context.Context, name, title, description string, wildcard bool) (*domain.Role, error) {
	role, err := domain.NewRole(name, title, description, wildcard)
	if err != nil {
		return nil, err
	}
	if err := s.roles.CreateRole(ctx, role); err != nil {
		return nil, err
	}
	return role, nil
}

func (s *Service) DeleteRole(ctx context.Context, name string) error {
	role, err := s.roles.Role(ctx, name)
	if err != nil {
		return err
	}
	if role.IsSystem {
		return domain.ErrSystemRole
	}
	return s.roles.DeleteRole(ctx, name)
}

func (s *Service) Role(ctx context.Context, name string) (*domain.Role, error) {
	return s.roles.Role(ctx, name)
}

func (s *Service) ListRoles(ctx context.Context) ([]domain.Role, error) {
	return s.roles.ListRoles(ctx)
}

func (s *Service) CreatePermission(ctx context.Context, code, description string) (domain.Permission, error) {
	p, err := domain.ParsePermission(code)
	if err != nil {
		return p, err
	}
	p.Description = description
	return p, s.roles.CreatePermission(ctx, p)
}

func (s *Service) ListPermissions(ctx context.Context) ([]domain.Permission, error) {
	return s.roles.ListPermissions(ctx)
}

// GrantPermission adds code to role. A non-empty grantedBy is the acting
// user: a management permission then needs a super admin. An empty grantedBy
// is a trusted system call.
func (s *Service) GrantPermission(ctx context.Context, role, code, grantedBy string) error {
	p, err := domain.ParsePermission(code)
	if err != nil {
		return err
	}
	if grantedBy != "" {
		if err := s.requireSuperAdmin(ctx, grantedBy, domain.IsManagementPermission(p.Code())); err != nil {
			return err
		}
	}
	return s.roles.GrantPermission(ctx, role, p, grantedBy)
}

func (s *Service) RevokePermission(ctx context.Context, role, code string) error {
	p, err := domain.ParsePermission(code)
	if err != nil {
		return err
	}
	return s.roles.RevokePermission(ctx, role, p)
}

// AssignRole grants role. A non-empty grantedBy is the acting user: a
// privileged role (domain.Role.Privileged) then requires a super admin actor. An empty
// grantedBy is a trusted system call (bootstrap). super_admin never expires.
func (s *Service) AssignRole(ctx context.Context, userID, role, grantedBy string, expiresAt *time.Time) error {
	if role == domain.RoleSuperAdmin && expiresAt != nil {
		return domain.ErrSuperAdminExpiry
	}
	if grantedBy != "" {
		if err := s.authorizeActor(ctx, grantedBy, role); err != nil {
			return err
		}
	}
	return s.roles.AssignRole(ctx, userID, role, grantedBy, expiresAt)
}

// UnassignRole revokes role as a trusted system call. Removing super_admin
// from its last holder fails with domain.ErrLastSuperAdmin. Use
// UnassignRoleAs for user-initiated changes.
func (s *Service) UnassignRole(ctx context.Context, userID, role string) error {
	if role == domain.RoleSuperAdmin {
		return s.LockSuperAdmins(ctx, func(ctx context.Context) error { return s.unassignSuperAdmin(ctx, userID) })
	}
	return s.roles.UnassignRole(ctx, userID, role)
}

func (s *Service) Grants(ctx context.Context, userID string) ([]domain.RoleGrant, error) {
	return s.roles.GrantsOf(ctx, userID)
}

// SavePolicy creates (empty ID) or replaces a policy.
func (s *Service) SavePolicy(ctx context.Context, p *domain.Policy) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if p.ID == "" {
		p.ID = uuid.Must(uuid.NewV7()).String()
	}
	return s.policies.SavePolicy(ctx, p)
}

func (s *Service) DeletePolicy(ctx context.Context, id string) error {
	return s.policies.DeletePolicy(ctx, id)
}

func (s *Service) Policy(ctx context.Context, id string) (*domain.Policy, error) {
	return s.policies.Policy(ctx, id)
}

func (s *Service) ListPolicies(ctx context.Context) ([]domain.Policy, error) {
	return s.policies.ListPolicies(ctx)
}
