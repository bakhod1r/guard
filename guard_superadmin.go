package guard

import (
	"context"
	"errors"
	"time"

	accessdomain "github.com/bakhod1r/guard/access/domain"
	"github.com/bakhod1r/guard/audit"
	identityapp "github.com/bakhod1r/guard/identity/application"
	identitydomain "github.com/bakhod1r/guard/identity/domain"
)

// RoleSuperAdmin is the system role that alone manages admin and super_admin grants.
const RoleSuperAdmin = accessdomain.RoleSuperAdmin

// Super admin errors, re-exported for HTTP error mapping.
var (
	ErrForbidden        = accessdomain.ErrForbidden
	ErrLastSuperAdmin   = accessdomain.ErrLastSuperAdmin
	ErrSuperAdminExpiry = accessdomain.ErrSuperAdminExpiry
)

// EnsureSuperAdmin gives the existing host user userID an account (if
// missing) and the super_admin role. Idempotent; intended for bootstrap
// (e.g. GUARD_SUPERADMIN_EMAIL / GUARD_SUPERADMIN_PASSWORD at startup).
// An existing account keeps its password.
func (g *Guard) EnsureSuperAdmin(ctx context.Context, userID, email, password string) (*User, error) {
	u, err := g.Identity.CreateAccount(ctx, identityapp.CreateAccountInput{UserID: userID, Email: email, Password: password})
	if errors.Is(err, identitydomain.ErrAccountExists) {
		u, err = g.Identity.User(ctx, identitydomain.UserID(userID))
	}
	if err == nil {
		err = g.Access.AssignRole(ctx, userID, RoleSuperAdmin, "", nil)
	}
	g.record(ctx, audit.Event{Action: "superadmin.ensure", Target: userID, Success: err == nil})
	if err != nil {
		return nil, err
	}
	return u, nil
}

// SuperAdmins returns the user ids holding super_admin.
func (g *Guard) SuperAdmins(ctx context.Context) ([]string, error) { return g.Access.SuperAdmins(ctx) }

// IsSuperAdmin reports whether userID actively holds super_admin.
func (g *Guard) IsSuperAdmin(ctx context.Context, userID string) (bool, error) {
	return g.Access.IsSuperAdmin(ctx, userID)
}

// AssignRole grants role to userID on behalf of actorID and audits it.
// Granting admin or super_admin requires a super admin actor (ErrForbidden).
func (g *Guard) AssignRole(ctx context.Context, actorID, userID, role string, expiresAt *time.Time) error {
	err := g.Access.AssignRole(ctx, userID, role, actorID, expiresAt)
	g.recordRoleChange(ctx, "assign", "role.assign", "superadmin.grant", actorID, userID, role, err)
	return err
}

// UnassignRole revokes role from userID on behalf of actorID and audits it.
// Revoking admin or super_admin requires a super admin actor (ErrForbidden);
// the last super admin keeps the role (ErrLastSuperAdmin).
func (g *Guard) UnassignRole(ctx context.Context, actorID, userID, role string) error {
	err := g.Access.UnassignRoleAs(ctx, actorID, userID, role)
	g.recordRoleChange(ctx, "unassign", "role.unassign", "superadmin.revoke", actorID, userID, role, err)
	return err
}

func (g *Guard) recordRoleChange(ctx context.Context, op, action, superAction, actorID, userID, role string, err error) {
	e := audit.Event{ActorID: actorID, Action: action, Target: userID, Success: err == nil, Metadata: map[string]any{"role": role}}
	switch {
	case errors.Is(err, accessdomain.ErrForbidden), errors.Is(err, accessdomain.ErrLastSuperAdmin):
		e.Action, e.Metadata["op"], e.Metadata["reason"] = "superadmin.denied", op, err.Error()
	case err == nil && role == RoleSuperAdmin:
		e.Action = superAction
	}
	g.record(ctx, e)
}

// authorizeAccountChange refuses (ErrForbidden) account changes on an admin
// or super admin by anyone but a super admin or the user themselves.
func (g *Guard) authorizeAccountChange(ctx context.Context, op, actorID, userID string) error {
	err := g.Access.AuthorizeAccountChange(ctx, actorID, userID)
	if errors.Is(err, accessdomain.ErrForbidden) {
		g.record(ctx, audit.Event{ActorID: actorID, Action: "superadmin.denied", Target: userID, Metadata: map[string]any{"op": op, "reason": err.Error()}})
	}
	return err
}

// SetAttributes replaces userID's ABAC attributes on behalf of actorID.
func (g *Guard) SetAttributes(ctx context.Context, actorID, userID string, attrs map[string]any) error {
	if err := g.authorizeAccountChange(ctx, "attributes", actorID, userID); err != nil {
		return err
	}
	return g.Identity.SetAttributes(ctx, identitydomain.UserID(userID), attrs)
}

// superAdminBlocked reports whether super admin id can no longer act: banned,
// suspended, or without an account.
func (g *Guard) superAdminBlocked(ctx context.Context, id string) (bool, error) {
	u, err := g.Identity.User(ctx, identitydomain.UserID(id))
	if errors.Is(err, identitydomain.ErrUserNotFound) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return u.CanLogin() != nil, nil
}

// changeStatus applies status. Blocking runs the last-super-admin check and
// the write under the super admin lock, so concurrent bans and role removals
// cannot each see another active super admin and leave none.
func (g *Guard) changeStatus(ctx context.Context, userID string, status Status) error {
	set := func(ctx context.Context) error {
		if err := g.checkSuperAdminStatus(ctx, userID, status); err != nil {
			return err
		}
		return g.Identity.SetStatus(ctx, identitydomain.UserID(userID), status)
	}
	if status != identitydomain.StatusBanned && status != identitydomain.StatusSuspended {
		return set(ctx)
	}
	return g.Access.LockSuperAdmins(ctx, set)
}

// checkSuperAdminStatus refuses to ban or suspend the last super admin whose
// account can still log in. Called by SetUserStatus before the change.
func (g *Guard) checkSuperAdminStatus(ctx context.Context, userID string, status Status) error {
	if status != identitydomain.StatusBanned && status != identitydomain.StatusSuspended {
		return nil
	}
	err := g.Access.EnsureCanBlock(ctx, userID, g.superAdminBlocked)
	switch {
	case errors.Is(err, accessdomain.ErrHoldersUnsupported):
		// Availability guard only: a custom role repository must not make bans impossible.
		g.logger.WarnContext(ctx, "guard: last-super-admin check skipped: role repository lacks holder support")
		return nil
	case errors.Is(err, accessdomain.ErrLastSuperAdmin):
		g.record(ctx, audit.Event{Action: "superadmin.denied", Target: userID, Metadata: map[string]any{"op": "status", "status": string(status), "reason": err.Error()}})
	}
	return err
}
