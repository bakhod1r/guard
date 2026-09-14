package ginguard

import (
	"context"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/bakhod1r/guard"
	accessapp "github.com/bakhod1r/guard/access/application"
	accessdomain "github.com/bakhod1r/guard/access/domain"
)

// AutoseedOptions configures route-derived permissions.
type AutoseedOptions struct {
	// Prefix is stripped before deriving the resource ("/api").
	Prefix string
	// SuperRole receives every derived permission. Default "admin"; "-" disables.
	SuperRole string
	// Exclude lists path prefixes that are not seeded (e.g. Guard's own /api/auth, /api/guard).
	Exclude []string
}

// Protect authenticates and requires the permission derived from the matched
// route (method + c.FullPath()). Mount it on a host route group before its routes.
func Protect(g *guard.Guard, opts Options, prefix string) gin.HandlerFunc {
	return protect(g, opts, prefix, nil)
}

func protect(g *guard.Guard, opts Options, prefix string, overrides map[string]string) gin.HandlerFunc {
	o := opts.withDefaults()
	return func(c *gin.Context) {
		if !authenticate(c, g, o) {
			return
		}
		path := c.FullPath()
		if path == "" {
			c.Next()
			return
		}
		p, err := accessdomain.ResolveRoutePermission(c.Request.Method, path, prefix, overrides)
		if err != nil {
			abort(c, http.StatusForbidden, "forbidden", "route has no derivable permission")
			return
		}
		d, err := g.Authorize(c.Request.Context(), PrincipalFrom(c), p.Action, guard.Resource{Type: p.Resource}, Environment(c))
		if err != nil {
			fail(c, err)
			return
		}
		if !d.Allowed {
			abort(c, http.StatusForbidden, "forbidden", "not allowed to "+p.Action+" "+p.Resource)
			return
		}
		c.Next()
	}
}

// Autoseed creates the permission of every registered route (router.Routes())
// and grants them to SuperRole. Call after all routes are registered, at startup.
func Autoseed(ctx context.Context, g *guard.Guard, routes gin.RoutesInfo, a AutoseedOptions) (accessapp.RouteSeed, error) {
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

func excluded(path string, prefixes []string) bool {
	for _, p := range prefixes {
		p = strings.TrimRight(p, "/")
		if p != "" && (path == p || strings.HasPrefix(path, p+"/")) {
			return true
		}
	}
	return false
}
