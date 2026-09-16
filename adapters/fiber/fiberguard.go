// Package fiberguard exposes Guard over Fiber: the same middleware and routes
// as httpguard, bridged onto fasthttp through Fiber's adaptor.
//
//	app := fiber.New()
//	fiberguard.Mount(app, g, fiberguard.Options{}, "/api")
//	fiberguard.MountAdmin(app, g, adminui.Options{})
//	app.Get("/api/invoices/:id", fiberguard.RequirePermission(g, opts, "invoice.read"), handler)
package fiberguard

import (
	"net/http"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/adaptor"

	"github.com/bakhod1r/guard"
	"github.com/bakhod1r/guard/adminui"
	"github.com/bakhod1r/guard/httpguard"
	"github.com/bakhod1r/guard/ratelimit"
)

// Options is httpguard.Options; Fiber path parameters are wired in by Wrap.
type Options = httpguard.Options

// principalKey holds the authenticated caller in Fiber's Locals.
const principalKey = "guard.principal"

// PrincipalFrom returns the authenticated caller, or nil.
func PrincipalFrom(c *fiber.Ctx) *guard.Principal {
	p, _ := c.Locals(principalKey).(*guard.Principal)
	return p
}

// withParams makes httpguard read path parameters through the Fiber context.
func withParams(o Options, c *fiber.Ctx) Options {
	o.PathValue = func(_ *http.Request, name string) string { return c.Params(name) }
	o.RoutePattern = func(*http.Request) string {
		if r := c.Route(); r != nil {
			return r.Path
		}
		return ""
	}
	o.ClientIP = func(*http.Request) string { return c.IP() }
	return o
}

// Wrap turns an httpguard middleware into a Fiber handler. build receives the
// per-request Options (path parameters, route pattern and client IP already
// wired to the Fiber context), so every httpguard constructor can be used as is.
// When Guard rejects the request the response is written and c.Next is not called.
func Wrap(opts Options, build func(Options) httpguard.Middleware) fiber.Handler {
	return func(c *fiber.Ctx) error {
		passed := false
		h := build(withParams(opts, c))(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			passed = true
			if p := httpguard.PrincipalFrom(r); p != nil {
				c.Locals(principalKey, p)
			}
		}))
		if err := adaptor.HTTPHandler(h)(c); err != nil {
			return err
		}
		if passed {
			return c.Next()
		}
		return nil
	}
}

// Authenticate attaches the principal when a valid token is present; never rejects.
func Authenticate(g *guard.Guard, opts Options) fiber.Handler {
	return Wrap(opts, func(o Options) httpguard.Middleware { return httpguard.Authenticate(g, o) })
}

// RequireAuth rejects requests without a valid credential with 401.
func RequireAuth(g *guard.Guard, opts Options) fiber.Handler {
	return Wrap(opts, func(o Options) httpguard.Middleware { return httpguard.RequireAuth(g, o) })
}

// RequireSession is RequireAuth that refuses API keys (account-level operations).
func RequireSession(g *guard.Guard, opts Options) fiber.Handler {
	return Wrap(opts, func(o Options) httpguard.Middleware { return httpguard.RequireSession(g, o) })
}

// Require authenticates and authorizes action on the resource built by fn.
func Require(g *guard.Guard, opts Options, resourceType, action string, fn httpguard.ResourceFunc) fiber.Handler {
	return Wrap(opts, func(o Options) httpguard.Middleware { return httpguard.Require(g, o, resourceType, action, fn) })
}

// RequirePermission is Require for a permission code like "invoice.read".
func RequirePermission(g *guard.Guard, opts Options, code string) fiber.Handler {
	return Wrap(opts, func(o Options) httpguard.Middleware { return httpguard.RequirePermission(g, o, code) })
}

// ParamResource uses a path parameter as the resource id.
func ParamResource(param string) httpguard.ResourceFunc { return httpguard.ParamResource(param) }

// RateLimit rejects requests over rule with 429 and sets X-RateLimit-* headers.
func RateLimit(g *guard.Guard, opts Options, name string, rule ratelimit.Rule, key httpguard.KeyFunc) fiber.Handler {
	return Wrap(opts, func(o Options) httpguard.Middleware { return httpguard.RateLimit(g, o, name, rule, key) })
}

// Protect authenticates and requires the permission derived from the matched
// route (method + Fiber route path).
func Protect(g *guard.Guard, opts Options, prefix string) fiber.Handler {
	return Wrap(opts, func(o Options) httpguard.Middleware { return httpguard.Protect(g, o, prefix) })
}

// Mount registers every Guard route (see httpguard.Mount) on app under prefix
// (""/"/" for the root, "/api" to serve /api/auth/... and /api/guard/...).
func Mount(app *fiber.App, g *guard.Guard, opts Options, prefix ...string) {
	p := ""
	if len(prefix) > 0 {
		p = trimSlash(prefix[0])
	}
	h := httpguard.Handler(g, opts)
	if p != "" {
		h = http.StripPrefix(p, h)
	}
	handler := adaptor.HTTPHandler(h)
	for _, group := range []string{orDefault(opts.AuthPath, "/auth"), orDefault(opts.AdminPath, "/guard")} {
		app.All(p+group, handler)
		app.All(p+group+"/+", handler)
	}
}

// MountAdmin serves the HTML admin panel at adminui.Options.Path
// (default /guard-admin).
func MountAdmin(app *fiber.App, g *guard.Guard, opts adminui.Options) {
	path := "/" + trimSlashes(orDefault(opts.Path, "/guard-admin"))
	handler := adaptor.HTTPHandler(adminui.Handler(g, opts))
	app.All(path, handler)
	app.All(path+"/+", handler)
}

// Routes reports the host's routes for httpguard.SyncRoutes and Autoseed.
func Routes(app *fiber.App) []httpguard.Route {
	var out []httpguard.Route
	for _, stack := range app.Stack() {
		for _, r := range stack {
			if r.Method == "HEAD" || strings.Contains(r.Path, "*") || strings.Contains(r.Path, "+") {
				continue
			}
			out = append(out, httpguard.Route{Method: r.Method, Path: r.Path})
		}
	}
	return out
}

func trimSlash(s string) string {
	if s == "" || s == "/" {
		return ""
	}
	return "/" + trimSlashes(s)
}

func trimSlashes(s string) string { return strings.Trim(s, "/") }

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
