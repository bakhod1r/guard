// Package echoguard exposes Guard over Echo: the same middleware and routes as
// httpguard, wrapped for echo.Context.
//
//	e := echo.New()
//	echoguard.Mount(e, g, echoguard.Options{})           // /auth/*, /guard/*
//	echoguard.MountAdmin(e, g, adminui.Options{})        // /guard-admin
//	e.GET("/invoices/:id", handler, echoguard.RequirePermission(g, opts, "invoice.read"))
package echoguard

import (
	"net/http"

	"github.com/labstack/echo/v4"

	"github.com/bakhod1r/guard"
	"github.com/bakhod1r/guard/adminui"
	"github.com/bakhod1r/guard/httpguard"
	"github.com/bakhod1r/guard/ratelimit"
)

// Options is httpguard.Options; Echo path parameters are wired in by Wrap.
type Options = httpguard.Options

// PrincipalFrom returns the authenticated caller, or nil.
func PrincipalFrom(c echo.Context) *guard.Principal {
	return httpguard.PrincipalFrom(c.Request())
}

// withParams makes httpguard read path parameters through echo.Context.
func withParams(o Options, c echo.Context) Options {
	o.PathValue = func(_ *http.Request, name string) string { return c.Param(name) }
	o.RoutePattern = func(*http.Request) string { return c.Path() }
	o.ClientIP = func(*http.Request) string { return c.RealIP() }
	return o
}

// Wrap turns an httpguard middleware into Echo middleware. build receives the
// per-request Options (path parameters, route pattern and client IP already
// wired to echo.Context) so every httpguard constructor can be used as is.
func Wrap(opts Options, build func(Options) httpguard.Middleware) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			var err error
			handled := false
			h := build(withParams(opts, c))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				handled = true
				c.SetRequest(r) // carry the principal into the handler
				err = next(c)
			}))
			h.ServeHTTP(c.Response(), c.Request())
			if !handled {
				// Guard answered (401/403/429/413); the response is already written.
				return nil
			}
			return err
		}
	}
}

// Authenticate attaches the principal when a valid token is present; never rejects.
func Authenticate(g *guard.Guard, opts Options) echo.MiddlewareFunc {
	return Wrap(opts, func(o Options) httpguard.Middleware { return httpguard.Authenticate(g, o) })
}

// RequireAuth rejects requests without a valid credential with 401.
func RequireAuth(g *guard.Guard, opts Options) echo.MiddlewareFunc {
	return Wrap(opts, func(o Options) httpguard.Middleware { return httpguard.RequireAuth(g, o) })
}

// RequireSession is RequireAuth that refuses API keys (account-level operations).
func RequireSession(g *guard.Guard, opts Options) echo.MiddlewareFunc {
	return Wrap(opts, func(o Options) httpguard.Middleware { return httpguard.RequireSession(g, o) })
}

// Require authenticates and authorizes action on the resource built by fn.
func Require(g *guard.Guard, opts Options, resourceType, action string, fn httpguard.ResourceFunc) echo.MiddlewareFunc {
	return Wrap(opts, func(o Options) httpguard.Middleware { return httpguard.Require(g, o, resourceType, action, fn) })
}

// RequirePermission is Require for a permission code like "invoice.read".
func RequirePermission(g *guard.Guard, opts Options, code string) echo.MiddlewareFunc {
	return Wrap(opts, func(o Options) httpguard.Middleware { return httpguard.RequirePermission(g, o, code) })
}

// ParamResource uses a path parameter as the resource id.
func ParamResource(param string) httpguard.ResourceFunc { return httpguard.ParamResource(param) }

// RateLimit rejects requests over rule with 429 and sets X-RateLimit-* headers.
func RateLimit(g *guard.Guard, opts Options, name string, rule ratelimit.Rule, key httpguard.KeyFunc) echo.MiddlewareFunc {
	return Wrap(opts, func(o Options) httpguard.Middleware { return httpguard.RateLimit(g, o, name, rule, key) })
}

// Protect authenticates and requires the permission derived from the matched
// route (method + echo route path).
func Protect(g *guard.Guard, opts Options, prefix string) echo.MiddlewareFunc {
	return Wrap(opts, func(o Options) httpguard.Middleware { return httpguard.Protect(g, o, prefix) })
}

// Mount registers every Guard route (see httpguard.Mount) on e under prefix
// (""/"/" for the root, "/api" to serve /api/auth/... and /api/guard/...).
func Mount(e *echo.Echo, g *guard.Guard, opts Options, prefix ...string) {
	p := ""
	if len(prefix) > 0 {
		p = trimSlash(prefix[0])
	}
	h := httpguard.Handler(g, opts)
	if p != "" {
		h = http.StripPrefix(p, h)
	}
	wrapped := echo.WrapHandler(h)
	o := opts
	for _, group := range []string{orDefault(o.AuthPath, "/auth"), orDefault(o.AdminPath, "/guard")} {
		e.Any(p+group, wrapped)
		e.Any(p+group+"/*", wrapped)
	}
}

// MountAdmin serves the HTML admin panel at adminui.Options.Path
// (default /guard-admin).
func MountAdmin(e *echo.Echo, g *guard.Guard, opts adminui.Options) {
	path := orDefault(opts.Path, "/guard-admin")
	path = "/" + trimSlashes(path)
	h := echo.WrapHandler(adminui.Handler(g, opts))
	e.Any(path, h)
	e.Any(path+"/*", h)
}

// Routes reports the host's routes for httpguard.SyncRoutes and Autoseed.
func Routes(e *echo.Echo) []httpguard.Route {
	out := make([]httpguard.Route, 0, len(e.Routes()))
	for _, r := range e.Routes() {
		out = append(out, httpguard.Route{Method: r.Method, Path: r.Path})
	}
	return out
}

func trimSlash(s string) string {
	if s == "" || s == "/" {
		return ""
	}
	return "/" + trimSlashes(s)
}

func trimSlashes(s string) string {
	for len(s) > 0 && s[0] == '/' {
		s = s[1:]
	}
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
