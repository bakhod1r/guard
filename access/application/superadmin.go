package application

import (
	"context"

	"github.com/bakhod1r/guard/access/domain"
)

// authorizeActor applies domain.AuthorizeRoleChange to actorID's active roles.
func (s *Service) authorizeActor(ctx context.Context, actorID, role string) error {
	if !domain.IsPrivilegedRole(role) {
		return nil
	}
	roles, err := s.ActiveRoles(ctx, actorID)
	if err != nil {
		return err
	}
	return domain.AuthorizeRoleChange(roles, role)
}

func (s *Service) holders() (domain.RoleHolderRepository, error) {
	h, ok := s.roles.(domain.RoleHolderRepository)
	if !ok {
		return nil, domain.ErrHoldersUnsupported
	}
	return h, nil
}

// UnassignRoleAs revokes role from userID on behalf of actorID: admin and
// super_admin need a super admin actor, and the last super admin is kept.
func (s *Service) UnassignRoleAs(ctx context.Context, actorID, userID, role string) error {
	if err := s.authorizeActor(ctx, actorID, role); err != nil {
		return err
	}
	return s.UnassignRole(ctx, userID, role)
}

// SuperAdmins returns the user ids holding super_admin.
func (s *Service) SuperAdmins(ctx context.Context) ([]string, error) {
	h, err := s.holders()
	if err != nil {
		return nil, err
	}
	return h.RoleHolders(ctx, domain.RoleSuperAdmin)
}

// IsSuperAdmin reports whether userID actively holds super_admin.
func (s *Service) IsSuperAdmin(ctx context.Context, userID string) (bool, error) {
	roles, err := s.ActiveRoles(ctx, userID)
	if err != nil {
		return false, err
	}
	return domain.HasSuperAdmin(roles), nil
}

// EnsureCanBlock fails with domain.ErrLastSuperAdmin when blocking userID
// would leave no unblocked super admin. isBlocked reports other holders' state.
func (s *Service) EnsureCanBlock(ctx context.Context, userID string, isBlocked func(context.Context, string) (bool, error)) error {
	all, err := s.SuperAdmins(ctx)
	if err != nil {
		return err
	}
	usable := make([]string, 0, len(all))
	for _, id := range all {
		if id != userID {
			blocked, err := isBlocked(ctx, id)
			if err != nil {
				return err
			}
			if blocked {
				continue
			}
		}
		usable = append(usable, id)
	}
	return domain.EnsureOtherSuperAdmin(usable, userID)
}
