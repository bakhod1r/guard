package guard

import (
	"context"
	"errors"
	"time"

	accessapp "github.com/bakhod1r/guard/access/application"
	accessdomain "github.com/bakhod1r/guard/access/domain"
	accessinfra "github.com/bakhod1r/guard/access/infrastructure"
	"github.com/bakhod1r/guard/audit"
)

type (
	Route            = accessapp.Route
	RouteSyncOptions = accessapp.RouteSyncOptions
	RouteSyncResult  = accessapp.RouteSyncResult
	RouteRecord      = accessdomain.RouteRecord
)

// ErrNoRouteRegistry is returned by ListRoutes on a Guard without PostgreSQL.
var ErrNoRouteRegistry = errors.New("guard: route registry needs a PostgreSQL-backed Guard")

// routeRegistry returns the guard_route registry, or nil (no stale tracking) without PostgreSQL.
func (g *Guard) routeRegistry() accessdomain.RouteRegistry {
	if g.db == nil {
		return nil
	}
	return accessinfra.NewPostgresRoutes(g.db)
}

// SyncRoutes discovers route permissions (see accessapp.Service.SyncRoutes):
// admin and super_admin get every route permission, the user role gets
// UserActions (default read) for new routes, and removed routes are marked
// stale. Idempotent; safe to call at every startup. Records a routes.sync audit event.
func (g *Guard) SyncRoutes(ctx context.Context, routes []Route, o RouteSyncOptions) (RouteSyncResult, error) {
	res, err := g.Access.SyncRoutes(ctx, g.routeRegistry(), routes, o, time.Now().UTC())
	meta := map[string]any{"routes": len(routes), "permissions": len(res.Permissions), "created": len(res.Created),
		"skipped": len(res.Skipped), "stale": len(res.Stale), "missing_roles": res.MissingRoles}
	if err != nil {
		meta["error"] = err.Error()
	}
	g.record(ctx, audit.Event{Action: "routes.sync", Success: err == nil, Metadata: meta})
	if len(res.Stale) > 0 {
		g.logger.InfoContext(ctx, "guard: routes marked stale", "count", len(res.Stale))
	}
	return res, err
}

// ListRoutes returns the route registry, stale routes included.
func (g *Guard) ListRoutes(ctx context.Context) ([]RouteRecord, error) {
	reg := g.routeRegistry()
	if reg == nil {
		return nil, ErrNoRouteRegistry
	}
	return reg.ListRoutes(ctx)
}
