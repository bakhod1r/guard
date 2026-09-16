// Package beegoguard exposes Guard over Beego v2: the same middleware and
// routes as httpguard, wrapped as Beego filters.
//
//	web.Handler("/api/auth/*", beegoguard.Handler(g, opts))  // see Mount
//	beegoguard.Mount(g, opts, "/api")
//	beegoguard.MountAdmin(g, adminui.Options{})
//	web.InsertFilter("/api/invoices/*", web.BeforeRouter,
//	    beegoguard.RequirePermission(g, opts, "invoice.read"))
package beegoguard

import (
	"net/http"
	"strings"

	"github.com/beego/beego/v2/server/web"
	beecontext "github.com/beego/beego/v2/server/web/context"

	"github.com/bakhod1r/guard"
	"github.com/bakhod1r/guard/adminui"
	"github.com/bakhod1r/guard/httpguard"
	"github.com/bakhod1r/guard/ratelimit"
)

// Options is httpguard.Options; Beego path parameters are wired in by Wrap.
type Options = httpguard.Options

// PrincipalFrom returns the authenticated caller, or nil.
func PrincipalFrom(ctx *beecontext.Context) *guard.Principal {
	return httpguard.PrincipalFrom(ctx.Request)
}

// withParams makes httpguard read path parameters through the Beego context.
// Beego stores them as ":id", so both spellings are accepted.
func withParams(o Options, ctx *beecontext.Context) Options {
	o.PathValue = func(_ *http.Request, name string) string {
		if v := ctx.Input.Param(":" + name); v != "" {
			return v
		}
		return ctx.Input.Param(name)
	}
	o.RoutePattern = func(*http.Request) string { return ctx.Input.URL() }
	o.ClientIP = func(*http.Request) string { return ctx.Input.IP() }
	return o
}

// Wrap turns an httpguard middleware into a Beego filter. build receives the
// per-request Options (path parameters and client IP already wired to the Beego
// context), so every httpguard constructor can be used as is. When Guard
// rejects the request the response is written and the chain stops.
func Wrap(opts Options, build func(Options) httpguard.Middleware) web.FilterFunc {
	return func(ctx *beecontext.Context) {
		passed := false
		h := build(withParams(opts, ctx))(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			passed = true
			ctx.Request = r // carry the principal into the controller
		}))
		h.ServeHTTP(ctx.ResponseWriter, ctx.Request)
		if !passed {
			// Guard answered; stop Beego from running the controller.
			ctx.ResponseWriter.Started = true
		}
	}
}

// Authenticate attaches the principal when a valid token is present; never rejects.
func Authenticate(g *guard.Guard, opts Options) web.FilterFunc {
	return Wrap(opts, func(o Options) httpguard.Middleware { return httpguard.Authenticate(g, o) })
}

// RequireAuth rejects requests without a valid credential with 401.
func RequireAuth(g *guard.Guard, opts Options) web.FilterFunc {
	return Wrap(opts, func(o Options) httpguard.Middleware { return httpguard.RequireAuth(g, o) })
}

// RequireSession is RequireAuth that refuses API keys (account-level operations).
func RequireSession(g *guard.Guard, opts Options) web.FilterFunc {
	return Wrap(opts, func(o Options) httpguard.Middleware { return httpguard.RequireSession(g, o) })
}

// Require authenticates and authorizes action on the resource built by fn.
func Require(g *guard.Guard, opts Options, resourceType, action string, fn httpguard.ResourceFunc) web.FilterFunc {
	return Wrap(opts, func(o Options) httpguard.Middleware { return httpguard.Require(g, o, resourceType, action, fn) })
}

// RequirePermission is Require for a permission code like "invoice.read".
func RequirePermission(g *guard.Guard, opts Options, code string) web.FilterFunc {
	return Wrap(opts, func(o Options) httpguard.Middleware { return httpguard.RequirePermission(g, o, code) })
}

// ParamResource uses a path parameter as the resource id.
func ParamResource(param string) httpguard.ResourceFunc { return httpguard.ParamResource(param) }

// RateLimit rejects requests over rule with 429 and sets X-RateLimit-* headers.
func RateLimit(g *guard.Guard, opts Options, name string, rule ratelimit.Rule, key httpguard.KeyFunc) web.FilterFunc {
	return Wrap(opts, func(o Options) httpguard.Middleware { return httpguard.RateLimit(g, o, name, rule, key) })
}

// Protect authenticates and requires the permission derived from the request
// path. Beego filters run before routing, so the permission is derived from the
// concrete URL rather than from a route pattern.
func Protect(g *guard.Guard, opts Options, prefix string) web.FilterFunc {
	return Wrap(opts, func(o Options) httpguard.Middleware { return httpguard.Protect(g, o, prefix) })
}

// Mount registers every Guard route (see httpguard.Mount) on the Beego default
// application under prefix (""/"/" for the root, "/api" to serve
// /api/auth/... and /api/guard/...).
func Mount(g *guard.Guard, opts Options, prefix ...string) {
	p := ""
	if len(prefix) > 0 {
		p = trimSlash(prefix[0])
	}
	h := httpguard.Handler(g, opts)
	if p != "" {
		h = http.StripPrefix(p, h)
	}
	for _, group := range []string{orDefault(opts.AuthPath, "/auth"), orDefault(opts.AdminPath, "/guard")} {
		web.Handler(p+group, h, true)
	}
}

// MountAdmin serves the HTML admin panel at adminui.Options.Path
// (default /guard-admin).
func MountAdmin(g *guard.Guard, opts adminui.Options) {
	path := "/" + strings.Trim(orDefault(opts.Path, "/guard-admin"), "/")
	web.Handler(path, adminui.Handler(g, opts), true)
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
