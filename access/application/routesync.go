package application

import (
	"context"
	"errors"
	"time"

	"github.com/bakhod1r/guard/access/domain"
)

// DefaultFullRoles receive every route permission unless RouteSyncOptions.FullRoles is set.
var DefaultFullRoles = []string{"admin", "super_admin"}

// RouteSyncOptions configures SyncRoutes.
type RouteSyncOptions struct {
	// Prefix is stripped before deriving the resource ("/api").
	Prefix string
	// FullRoles are granted every route permission on every sync. Roles that do
	// not exist are skipped (reported in MissingRoles); wildcard roles need no grants.
	// nil = DefaultFullRoles; []string{"-"} disables.
	FullRoles []string
	// UserRole receives UserActions for routes first seen by this sync. Default "user"; "-" disables.
	UserRole string
	// UserActions granted to UserRole. nil = ["read"].
	UserActions []string
	// Overrides maps "METHOD /path" to an explicit "resource.action".
	Overrides map[string]string
}

// RouteSyncResult reports what SyncRoutes did.
type RouteSyncResult struct {
	Permissions  []domain.Permission  // one per distinct code, in route order
	Created      []domain.Permission  // permissions that did not exist before
	Skipped      []Route              // routes without a derivable permission
	Stale        []domain.RouteRecord // routes newly marked stale (nil without a registry)
	GrantedRoles []string             // full roles that exist
	MissingRoles []string             // full roles that do not exist
}

func (o RouteSyncOptions) withDefaults() RouteSyncOptions {
	switch {
	case o.FullRoles == nil:
		o.FullRoles = DefaultFullRoles
	case len(o.FullRoles) == 1 && o.FullRoles[0] == "-":
		o.FullRoles = nil
	}
	switch o.UserRole {
	case "":
		o.UserRole = "user"
	case "-":
		o.UserRole = ""
	}
	if o.UserActions == nil {
		o.UserActions = []string{"read"}
	}
	return o
}

// SyncRoutes is the idempotent, production form of SeedRoutes:
//   - creates missing route permissions only; existing (manually created)
//     permissions are never modified or deleted;
//   - grants every route permission to FullRoles on each run;
//   - grants UserActions to UserRole only for permissions created now or routes
//     new to the registry, so an administrator's manual revoke is not undone on restart;
//   - with a registry, records routes and marks the ones not seen at now as stale.
//
// reg may be nil (no stale tracking).
func (s *Service) SyncRoutes(ctx context.Context, reg domain.RouteRegistry, routes []Route, o RouteSyncOptions, now time.Time) (RouteSyncResult, error) {
	o = o.withDefaults()
	var res RouteSyncResult
	existing, err := s.roles.ListPermissions(ctx)
	if err != nil {
		return res, err
	}
	have := make(map[string]bool, len(existing))
	for _, p := range existing {
		have[p.Code()] = true
	}
	known := map[string]bool{}
	if reg != nil {
		recs, err := reg.ListRoutes(ctx)
		if err != nil {
			return res, err
		}
		for _, r := range recs {
			known[r.Key()] = true
		}
	}

	seen := map[string]bool{}
	userGrant := map[string]bool{}
	records := make([]domain.RouteRecord, 0, len(routes))
	for _, r := range routes {
		p, err := domain.ResolveRoutePermission(r.Method, r.Path, o.Prefix, o.Overrides)
		if err != nil {
			if _, overridden := o.Overrides[domain.RouteKey(r.Method, r.Path)]; overridden {
				return res, err
			}
			res.Skipped = append(res.Skipped, r)
			continue
		}
		key := domain.RouteKey(r.Method, r.Path)
		records = append(records, domain.RouteRecord{Method: key[:len(key)-len(r.Path)-1], Path: r.Path, Permission: p.Code()})
		if !have[p.Code()] {
			p.Description = key
			if err := s.roles.CreatePermission(ctx, p); err != nil {
				return res, err
			}
			have[p.Code()] = true
			res.Created = append(res.Created, p)
			userGrant[p.Code()] = true
		} else if reg != nil && !known[key] {
			userGrant[p.Code()] = true
		}
		if !seen[p.Code()] {
			seen[p.Code()] = true
			res.Permissions = append(res.Permissions, p)
		}
	}

	for _, name := range o.FullRoles {
		role, err := s.roles.Role(ctx, name)
		if errors.Is(err, domain.ErrRoleNotFound) {
			res.MissingRoles = append(res.MissingRoles, name)
			continue
		}
		if err != nil {
			return res, err
		}
		res.GrantedRoles = append(res.GrantedRoles, name)
		if role.Wildcard {
			continue
		}
		for _, p := range res.Permissions {
			if err := s.roles.GrantPermission(ctx, name, p, ""); err != nil {
				return res, err
			}
		}
	}

	if o.UserRole != "" {
		actions := make(map[string]bool, len(o.UserActions))
		for _, a := range o.UserActions {
			actions[a] = true
		}
		for _, p := range res.Permissions {
			if !userGrant[p.Code()] || !actions[p.Action] {
				continue
			}
			err := s.roles.GrantPermission(ctx, o.UserRole, p, "")
			if errors.Is(err, domain.ErrRoleNotFound) {
				break
			}
			if err != nil {
				return res, err
			}
		}
	}

	if reg == nil {
		return res, nil
	}
	if err := reg.SaveRoutes(ctx, records, now); err != nil {
		return res, err
	}
	res.Stale, err = reg.MarkStale(ctx, now)
	return res, err
}
