package domain

import (
	"context"
	"errors"
)

// Built-in privileged role names.
const (
	// RoleSuperAdmin is the system wildcard role that alone may grant or revoke
	// privileged roles. At least one holder must always remain.
	RoleSuperAdmin = "super_admin"
	// RoleAdmin is the system wildcard role for day-to-day administration.
	RoleAdmin = "admin"
)

var (
	ErrForbidden        = errors.New("access: only a super admin may grant or revoke admin roles")
	ErrLastSuperAdmin   = errors.New("access: the last super admin cannot be removed or blocked")
	ErrSuperAdminExpiry = errors.New("access: super admin grants cannot expire")
	// ErrHoldersUnsupported is returned when the role repository cannot
	// enforce the last-super-admin rule atomically (fail closed).
	ErrHoldersUnsupported = errors.New("access: role repository does not support holder checks")
)

// IsPrivilegedRole reports whether changing grants of role needs a super admin.
func IsPrivilegedRole(role string) bool { return role == RoleAdmin || role == RoleSuperAdmin }

// HasSuperAdmin reports whether roles contains super_admin.
func HasSuperAdmin(roles []Role) bool {
	for _, r := range roles {
		if r.Name == RoleSuperAdmin {
			return true
		}
	}
	return false
}

// AuthorizeRoleChange decides whether an actor holding actorRoles may grant
// or revoke role.
func AuthorizeRoleChange(actorRoles []Role, role string) error {
	if IsPrivilegedRole(role) && !HasSuperAdmin(actorRoles) {
		return ErrForbidden
	}
	return nil
}

// EnsureOtherSuperAdmin fails when userID is the only one of the active
// super admin holders, i.e. removing or blocking them leaves nobody.
func EnsureOtherSuperAdmin(holders []string, userID string) error {
	held := false
	for _, h := range holders {
		if h == userID {
			held = true
		}
	}
	if held && len(holders) == 1 {
		return ErrLastSuperAdmin
	}
	return nil
}

// RoleHolderRepository is implemented by role repositories that can list and
// safely remove role holders.
type RoleHolderRepository interface {
	// RoleHolders returns the user ids holding a non-expired grant of role.
	RoleHolders(ctx context.Context, role string) ([]string, error)
	// UnassignRoleChecked removes userID's grant of role only if check,
	// called with the current active holders while concurrent removals of the
	// same role are excluded, returns nil.
	UnassignRoleChecked(ctx context.Context, userID, role string, check func(holders []string) error) error
}

// SuperAdminLocker is implemented by role repositories that can serialise,
// across every instance sharing the store, all operations that may shrink
// the set of active super admins (ban/suspend, role removal).
type SuperAdminLocker interface {
	// LockSuperAdmins runs fn while holding the super admin lock. It returns
	// without calling fn when the lock cannot be acquired (ctx done, timeout).
	LockSuperAdmins(ctx context.Context, fn func(context.Context) error) error
}

// BlockedFunc reports whether a super admin holder can no longer act
// (banned, suspended or without an account).
type BlockedFunc func(ctx context.Context, userID string) (bool, error)

// ActiveSuperAdmins keeps the holders that are not blocked. userID, the
// subject of the change, is always kept so EnsureOtherSuperAdmin can decide.
func ActiveSuperAdmins(holders []string, userID string, blocked func(id string) bool) []string {
	out := make([]string, 0, len(holders))
	for _, h := range holders {
		if h == userID || !blocked(h) {
			out = append(out, h)
		}
	}
	return out
}
