package httpguard

import (
	"context"
	"net/http"
	"strings"

	"github.com/bakhod1r/guard"
	accessapp "github.com/bakhod1r/guard/access/application"
	accessdomain "github.com/bakhod1r/guard/access/domain"
)

// Route is a host route as SyncRoutes and Autoseed see it. net/http has no
// route registry, so the host passes its table in (or builds one with
// Routes/Collect below).
type Route struct {
	Method string
	Path   string
}

// SyncOptions configures SyncRoutes and ProtectRoutes. Pass the same value to
// both so request-time checks use the permissions that were synced.
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

// AutoseedOptions configures route-derived permissions.
type AutoseedOptions struct {
	// Prefix is stripped before deriving the resource ("/api").
	Prefix string
	// SuperRole receives every derived permission. Default "admin"; "-" disables.
	SuperRole string
	// Exclude lists path prefixes that are not seeded (e.g. Guard's own /auth, /guard).
	Exclude []string
}

// Protect authenticates and requires the permission derived from the matched
// route (method + Options.RoutePattern). Wrap it around a single route's
// handler; a router only records the matched pattern while dispatching, so a
// Protect placed around a whole *http.ServeMux would see the outer pattern
// instead — use ProtectMux for that.
func Protect(g *guard.Guard, opts Options, prefix string) Middleware {
	return protect(g, opts, prefix, nil, nil)
}

// ProtectMux guards every route of mux at once: it resolves the pattern the
// request will match (through mux.Handler) before the check, so the permission
// comes from the route, not from the concrete URL. Requests that match no route
// pass through to the mux's own 404.
//
//	api := http.NewServeMux()
//	api.Handle("GET /api/reports/{id}", reports)
//	srv.Handle("/api/", httpguard.ProtectMux(g, opts, "/api", api))
func ProtectMux(g *guard.Guard, opts Options, prefix string, mux *http.ServeMux) http.Handler {
	return protectMux(g, opts, prefix, nil, nil, mux)
}

// ProtectMuxRoutes is ProtectMux honouring SyncOptions.Overrides and SkipPrefixes.
func ProtectMuxRoutes(g *guard.Guard, opts Options, o SyncOptions, mux *http.ServeMux) http.Handler {
	return protectMux(g, opts, o.Prefix, o.Overrides, o.SkipPrefixes, mux)
}

func protectMux(g *guard.Guard, opts Options, prefix string, overrides map[string]string, skip []string, mux *http.ServeMux) http.Handler {
	o := opts.withDefaults()
	o.RoutePattern = func(r *http.Request) string {
		_, pattern := mux.Handler(r)
		return patternPath(pattern)
	}
	return protect(g, o, prefix, overrides, skip)(mux)
}

// ProtectRoutes is Protect honouring SyncOptions.Overrides and SkipPrefixes.
func ProtectRoutes(g *guard.Guard, opts Options, o SyncOptions) Middleware {
	return protect(g, opts, o.Prefix, o.Overrides, o.SkipPrefixes)
}

func protect(g *guard.Guard, opts Options, prefix string, overrides map[string]string, skip []string) Middleware {
	o := opts.withDefaults()
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if excluded(r.URL.Path, skip) {
				next.ServeHTTP(w, r)
				return
			}
			r, ok := authenticate(w, r, g, o)
			if !ok {
				return
			}
			path := o.RoutePattern(r)
			if path == "" {
				// No route matched (404 territory) or the router exposes no
				// pattern: nothing to derive a permission from.
				next.ServeHTTP(w, r)
				return
			}
			p, err := accessdomain.ResolveRoutePermission(r.Method, path, prefix, overrides)
			if err != nil {
				abort(w, r, http.StatusForbidden, "forbidden", "route has no derivable permission")
				return
			}
			d, err := g.Authorize(r.Context(), PrincipalFrom(r), p.Action, guard.Resource{Type: p.Resource}, Environment(r, o))
			if err != nil {
				fail(w, r, err)
				return
			}
			if !d.Allowed {
				abort(w, r, http.StatusForbidden, "forbidden", "not allowed to "+p.Action+" "+p.Resource)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// SyncRoutes creates the permissions of every route passed in and grants them
// per SyncOptions. Idempotent: call at startup once the route table is known.
// Never deletes permissions; vanished routes are marked stale (PostgreSQL-backed
// Guard only).
func SyncRoutes(ctx context.Context, g *guard.Guard, routes []Route, o SyncOptions) (guard.RouteSyncResult, error) {
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

// Autoseed creates the permission of every route passed in and grants them to
// SuperRole. Call at startup, once the route table is known.
func Autoseed(ctx context.Context, g *guard.Guard, routes []Route, a AutoseedOptions) (accessapp.RouteSeed, error) {
	in := make([]accessapp.Route, 0, len(routes))
	for _, r := range routes {
		if excluded(r.Path, a.Exclude) {
			continue
		}
		in = append(in, accessapp.Route{Method: r.Method, Path: r.Path})
	}
	switch a.SuperRole {
	case "":
		a.SuperRole = "admin"
	case "-":
		a.SuperRole = ""
	}
	return g.Access.SeedRoutes(ctx, in, a.Prefix, a.SuperRole)
}

// Routes parses net/http route patterns ("GET /api/users/{id}") into the route
// table SyncRoutes and Autoseed take, so a host that registers its routes on a
// ServeMux can feed the same strings to both.
func Routes(patterns ...string) []Route {
	out := make([]Route, 0, len(patterns))
	for _, p := range patterns {
		method, path, ok := strings.Cut(strings.TrimSpace(p), " ")
		if !ok {
			out = append(out, Route{Method: http.MethodGet, Path: method})
			continue
		}
		out = append(out, Route{Method: method, Path: strings.TrimSpace(path)})
	}
	return out
}

// Collector records patterns as they are registered, so the host can hand the
// finished table to SyncRoutes or Autoseed:
//
//	rt := httpguard.NewCollector(mux)
//	rt.Handle("GET /api/invoices/{id}", h)
//	httpguard.Autoseed(ctx, g, rt.Routes(), httpguard.AutoseedOptions{Prefix: "/api"})
type Collector struct {
	r        Router
	patterns []string
}

// NewCollector wraps a router (usually *http.ServeMux); registrations pass
// through unchanged.
func NewCollector(r Router) *Collector { return &Collector{r: r} }

// Handle registers the pattern on the wrapped router and records it.
func (c *Collector) Handle(pattern string, h http.Handler) {
	c.patterns = append(c.patterns, pattern)
	c.r.Handle(pattern, h)
}

// HandleFunc is Handle for a handler function.
func (c *Collector) HandleFunc(pattern string, h http.HandlerFunc) { c.Handle(pattern, h) }

// Routes returns every recorded pattern as a route table.
func (c *Collector) Routes() []Route { return Routes(c.patterns...) }

func excluded(path string, prefixes []string) bool {
	for _, p := range prefixes {
		p = strings.TrimRight(p, "/")
		if p != "" && (path == p || strings.HasPrefix(path, p+"/")) {
			return true
		}
	}
	return false
}
