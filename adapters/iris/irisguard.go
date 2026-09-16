// Package irisguard exposes Guard over Iris: the same middleware and routes as
// httpguard, wrapped for iris.Context.
//
//	app := iris.New()
//	irisguard.Mount(app, g, irisguard.Options{}, "/api")
//	irisguard.MountAdmin(app, g, adminui.Options{})
//	app.Get("/api/invoices/{id}", irisguard.RequirePermission(g, opts, "invoice.read"), handler)
package irisguard

import (
	"net/http"
	"strings"

	"github.com/kataras/iris/v12"
	"github.com/kataras/iris/v12/core/router"

	"github.com/bakhod1r/guard"
	"github.com/bakhod1r/guard/adminui"
	"github.com/bakhod1r/guard/httpguard"
	"github.com/bakhod1r/guard/ratelimit"
)

// Options is httpguard.Options; Iris path parameters are wired in by Wrap.
type Options = httpguard.Options

// PrincipalFrom returns the authenticated caller, or nil.
func PrincipalFrom(ctx iris.Context) *guard.Principal {
	return httpguard.PrincipalFrom(ctx.Request())
}

// withParams makes httpguard read path parameters through iris.Context.
func withParams(o Options, ctx iris.Context) Options {
	o.PathValue = func(_ *http.Request, name string) string { return ctx.Params().Get(name) }
	o.RoutePattern = func(*http.Request) string {
		if r := ctx.GetCurrentRoute(); r != nil {
			return r.Path()
		}
		return ""
	}
	o.ClientIP = func(*http.Request) string { return ctx.RemoteAddr() }
	return o
}

// Wrap turns an httpguard middleware into an Iris handler. build receives the
// per-request Options (path parameters, route pattern and client IP already
// wired to iris.Context), so every httpguard constructor can be used as is.
// When Guard rejects the request the response is written and the chain stops.
func Wrap(opts Options, build func(Options) httpguard.Middleware) iris.Handler {
	return func(ctx iris.Context) {
		passed := false
		h := build(withParams(opts, ctx))(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			passed = true
			ctx.ResetRequest(r) // carry the principal into the handler
		}))
		h.ServeHTTP(ctx.ResponseWriter(), ctx.Request())
		if !passed {
			ctx.StopExecution()
			return
		}
		ctx.Next()
	}
}

// Authenticate attaches the principal when a valid token is present; never rejects.
func Authenticate(g *guard.Guard, opts Options) iris.Handler {
	return Wrap(opts, func(o Options) httpguard.Middleware { return httpguard.Authenticate(g, o) })
}

// RequireAuth rejects requests without a valid credential with 401.
func RequireAuth(g *guard.Guard, opts Options) iris.Handler {
	return Wrap(opts, func(o Options) httpguard.Middleware { return httpguard.RequireAuth(g, o) })
}

// RequireSession is RequireAuth that refuses API keys (account-level operations).
func RequireSession(g *guard.Guard, opts Options) iris.Handler {
	return Wrap(opts, func(o Options) httpguard.Middleware { return httpguard.RequireSession(g, o) })
}

// Require authenticates and authorizes action on the resource built by fn.
func Require(g *guard.Guard, opts Options, resourceType, action string, fn httpguard.ResourceFunc) iris.Handler {
	return Wrap(opts, func(o Options) httpguard.Middleware { return httpguard.Require(g, o, resourceType, action, fn) })
}

// RequirePermission is Require for a permission code like "invoice.read".
func RequirePermission(g *guard.Guard, opts Options, code string) iris.Handler {
	return Wrap(opts, func(o Options) httpguard.Middleware { return httpguard.RequirePermission(g, o, code) })
}

// ParamResource uses a path parameter as the resource id.
func ParamResource(param string) httpguard.ResourceFunc { return httpguard.ParamResource(param) }

// RateLimit rejects requests over rule with 429 and sets X-RateLimit-* headers.
func RateLimit(g *guard.Guard, opts Options, name string, rule ratelimit.Rule, key httpguard.KeyFunc) iris.Handler {
	return Wrap(opts, func(o Options) httpguard.Middleware { return httpguard.RateLimit(g, o, name, rule, key) })
}

// Protect authenticates and requires the permission derived from the matched
// route (method + Iris route path).
func Protect(g *guard.Guard, opts Options, prefix string) iris.Handler {
	return Wrap(opts, func(o Options) httpguard.Middleware { return httpguard.Protect(g, o, prefix) })
}

// Mount registers every Guard route (see httpguard.Mount) on app under prefix
// (""/"/" for the root, "/api" to serve /api/auth/... and /api/guard/...).
func Mount(app router.Party, g *guard.Guard, opts Options, prefix ...string) {
	p := ""
	if len(prefix) > 0 {
		p = trimSlash(prefix[0])
	}
	h := httpguard.Handler(g, opts)
	if p != "" {
		h = http.StripPrefix(p, h)
	}
	handler := iris.FromStd(h)
	for _, group := range []string{orDefault(opts.AuthPath, "/auth"), orDefault(opts.AdminPath, "/guard")} {
		app.Any(p+group, handler)
		app.Any(p+group+"/{p:path}", handler)
	}
}

// MountAdmin serves the HTML admin panel at adminui.Options.Path
// (default /guard-admin).
func MountAdmin(app router.Party, g *guard.Guard, opts adminui.Options) {
	path := "/" + strings.Trim(orDefault(opts.Path, "/guard-admin"), "/")
	handler := iris.FromStd(adminui.Handler(g, opts))
	app.Any(path, handler)
	app.Any(path+"/{p:path}", handler)
}

// Routes reports the host's routes for httpguard.SyncRoutes and Autoseed.
func Routes(app *iris.Application) []httpguard.Route {
	routes := app.GetRoutes()
	out := make([]httpguard.Route, 0, len(routes))
	for _, r := range routes {
		out = append(out, httpguard.Route{Method: r.Method, Path: r.Path})
	}
	return out
}

func trimSlash(s string) string {
	if s == "" || s == "/" {
		return ""
	}
	return "/" + strings.Trim(s, "/")
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
