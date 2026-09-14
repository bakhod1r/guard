package domain

import (
	"context"
	"strings"
	"time"
)

// routeActions maps HTTP methods to permission actions. Other methods use the
// lowercased method name.
var routeActions = map[string]string{
	"GET": "read", "HEAD": "read", "POST": "create", "PUT": "update", "PATCH": "update", "DELETE": "delete",
}

// RoutePermission derives the permission an HTTP route requires: the static
// path segments after prefix become the resource ("/api/v1/invoices/:id" with
// prefix "/api" gives "v1_invoices"), the method becomes the action.
func RoutePermission(method, path, prefix string) (Permission, error) {
	method = strings.ToUpper(strings.TrimSpace(method))
	prefix = strings.TrimRight(prefix, "/")
	if prefix != "" && (path == prefix || strings.HasPrefix(path, prefix+"/")) {
		path = path[len(prefix):]
	}
	var parts []string
	for _, seg := range strings.Split(path, "/") {
		if seg == "" || seg[0] == ':' || seg[0] == '*' {
			continue
		}
		parts = append(parts, sanitizePart(seg))
	}
	action, ok := routeActions[method]
	if !ok {
		action = sanitizePart(method)
	}
	resource := strings.Join(parts, "_")
	if len(resource) > 64 {
		resource = resource[:64]
	}
	return ParsePermission(resource + "." + action)
}

func sanitizePart(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_', r == '-':
			return r
		case r >= 'A' && r <= 'Z':
			return r + ('a' - 'A')
		}
		return '_'
	}, s)
}

// RouteKey identifies a route as "METHOD /path" (the form used by overrides and the registry).
func RouteKey(method, path string) string {
	return strings.ToUpper(strings.TrimSpace(method)) + " " + path
}

// ResolveRoutePermission is RoutePermission with explicit overrides keyed by
// RouteKey ("GET /api/reports/:id/export" -> "reports.export"). An invalid
// override is an error, never a silent fallback to the derived permission.
func ResolveRoutePermission(method, path, prefix string, overrides map[string]string) (Permission, error) {
	if code, ok := overrides[RouteKey(method, path)]; ok {
		return ParsePermission(strings.ToLower(strings.TrimSpace(code)))
	}
	return RoutePermission(method, path, prefix)
}

// RouteRecord is a route remembered by the route registry. Routes that are no
// longer registered by the host are marked Stale, never deleted, so their
// permissions and grants survive a temporary removal.
type RouteRecord struct {
	Method     string
	Path       string
	Permission string
	Stale      bool
	SeenAt     time.Time
}

// Key returns RouteKey(Method, Path).
func (r RouteRecord) Key() string { return RouteKey(r.Method, r.Path) }

// RouteRegistry persists discovered routes.
type RouteRegistry interface {
	ListRoutes(ctx context.Context) ([]RouteRecord, error)
	// SaveRoutes upserts records as not stale with last seen = seenAt.
	SaveRoutes(ctx context.Context, routes []RouteRecord, seenAt time.Time) error
	// MarkStale flags every non-stale route last seen before seenAt and returns them.
	MarkStale(ctx context.Context, seenAt time.Time) ([]RouteRecord, error)
}
