package application

import (
	"context"
	"sync"

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

// AuthorizeAccountChange applies domain.AuthorizeAccountChange to actorID's
// and userID's active roles.
func (s *Service) AuthorizeAccountChange(ctx context.Context, actorID, userID string) error {
	if actorID == userID {
		return nil
	}
	actor, err := s.ActiveRoles(ctx, actorID)
	if err != nil {
		return err
	}
	target, err := s.ActiveRoles(ctx, userID)
	if err != nil {
		return err
	}
	return domain.AuthorizeAccountChange(actor, target, false)
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
// Revoking super_admin authorizes the actor under the super admin lock, so
// an actor demoted concurrently cannot still act.
func (s *Service) UnassignRoleAs(ctx context.Context, actorID, userID, role string) error {
	if role != domain.RoleSuperAdmin {
		if err := s.authorizeActor(ctx, actorID, role); err != nil {
			return err
		}
		return s.UnassignRole(ctx, userID, role)
	}
	return s.LockSuperAdmins(ctx, func(ctx context.Context) error {
		if err := s.authorizeActor(ctx, actorID, role); err != nil {
			return err
		}
		return s.unassignSuperAdmin(ctx, userID)
	})
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

// superAdminState is the process-wide half of the super admin lock and the
// holder status lookup installed by the host (Guard).
type superAdminState struct {
	mu      chan struct{} // 1-slot semaphore; lazily made under once
	once    sync.Once
	blocked domain.BlockedFunc
}

// SetSuperAdminBlocked installs how holder status is looked up so role
// removal counts only active super admins. Call once before serving; nil
// counts every holder as active.
func (s *Service) SetSuperAdminBlocked(f domain.BlockedFunc) { s.sa.blocked = f }

// LockSuperAdmins runs fn exclusively against every other operation that can
// shrink the active super admin set: in this process always, and across
// instances when the role repository implements domain.SuperAdminLocker.
// The process lock also caps lock-holding database connections at one per
// process. fn must not call LockSuperAdmins again (not reentrant).
func (s *Service) LockSuperAdmins(ctx context.Context, fn func(context.Context) error) error {
	s.sa.once.Do(func() { s.sa.mu = make(chan struct{}, 1) })
	select {
	case s.sa.mu <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-s.sa.mu }()
	if l, ok := s.roles.(domain.SuperAdminLocker); ok {
		return l.LockSuperAdmins(ctx, fn)
	}
	return fn(ctx)
}

// unassignSuperAdmin removes userID's super_admin unless they are the last
// active holder. Must run under LockSuperAdmins: holder status is read
// before the checked delete, which is only sound while no ban can interleave.
func (s *Service) unassignSuperAdmin(ctx context.Context, userID string) error {
	h, err := s.holders()
	if err != nil {
		return err
	}
	all, err := h.RoleHolders(ctx, domain.RoleSuperAdmin)
	if err != nil {
		return err
	}
	blocked := make(map[string]bool, len(all))
	for _, id := range all {
		if id == userID || s.sa.blocked == nil {
			continue
		}
		if blocked[id], err = s.sa.blocked(ctx, id); err != nil {
			return err
		}
	}
	return h.UnassignRoleChecked(ctx, userID, domain.RoleSuperAdmin, func(holders []string) error {
		return domain.EnsureOtherSuperAdmin(domain.ActiveSuperAdmins(holders, userID, func(id string) bool {
			b, known := blocked[id]
			// A holder granted after the snapshot is unverified: fail closed.
			return b || (!known && s.sa.blocked != nil)
		}), userID)
	})
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
