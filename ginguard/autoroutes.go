package ginguard

import (
	"context"

	"github.com/gin-gonic/gin"

	"github.com/bakhod1r/guard"
)

// SyncOptions configures SyncRoutes and ProtectRoutes. Pass the same value to both
// so request-time checks use the permissions that were synced.
type SyncOptions struct {
	// Prefix is stripped before deriving the resource ("/api").
	Prefix string
	// SkipPrefixes lists path prefixes that are not synced (e.g. "/api/auth", "/api/guard").
	SkipPrefixes []string
	// FullRoles get every route permission. nil = admin, super_admin (missing roles skipped); {"-"} disables.
	FullRoles []string
	// UserRole gets UserActions for newly discovered routes. Default "user"; "-" disables.
	UserRole string
	// UserActions granted to UserRole. nil = ["read"]; empty non-nil = none.
	UserActions []string
	// Overrides maps "METHOD /full/path" to "resource.action".
	Overrides map[string]string
}

// SyncRoutes creates the permissions of every registered route (router.Routes())
// and grants them per SyncOptions. Idempotent: call at startup after all routes
// are registered. Never deletes permissions; vanished routes are marked stale
// (PostgreSQL-backed Guard only).
func SyncRoutes(ctx context.Context, g *guard.Guard, routes gin.RoutesInfo, o SyncOptions) (guard.RouteSyncResult, error) {
	in := make([]guard.Route, 0, len(routes))
	for _, r := range routes {
		if !excluded(r.Path, o.SkipPrefixes) {
			in = append(in, guard.Route{Method: r.Method, Path: r.Path})
		}
	}
	return g.SyncRoutes(ctx, in, guard.RouteSyncOptions{
		Prefix: o.Prefix, FullRoles: o.FullRoles, UserRole: o.UserRole, UserActions: o.UserActions, Overrides: o.Overrides,
	})
}

// ProtectRoutes is Protect honouring SyncOptions.Overrides: it authenticates and
// requires the permission of the matched route (method + c.FullPath()).
func ProtectRoutes(g *guard.Guard, opts Options, o SyncOptions) gin.HandlerFunc {
	return protect(g, opts, o.Prefix, o.Overrides)
}
