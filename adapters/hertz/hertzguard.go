// Package hertzguard exposes Guard over CloudWeGo Hertz: the same middleware
// and routes as httpguard, bridged onto Hertz's netpoll stack.
//
//	h := server.Default()
//	hertzguard.Mount(h, g, hertzguard.Options{}, "/api")
//	hertzguard.MountAdmin(h, g, adminui.Options{})
//	h.GET("/api/invoices/:id", hertzguard.RequirePermission(g, opts, "invoice.read"), handler)
package hertzguard

import (
	gocontext "context"
	"net/http"
	"strings"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/app/server"
	"github.com/cloudwego/hertz/pkg/common/adaptor"

	"github.com/bakhod1r/guard"
	"github.com/bakhod1r/guard/adminui"
	"github.com/bakhod1r/guard/httpguard"
	"github.com/bakhod1r/guard/ratelimit"
)

// Options is httpguard.Options; Hertz path parameters are wired in by Wrap.
type Options = httpguard.Options

// principalKey holds the authenticated caller in the RequestContext.
const principalKey = "guard.principal"

// PrincipalFrom returns the authenticated caller, or nil.
func PrincipalFrom(ctx *app.RequestContext) *guard.Principal {
	v, ok := ctx.Get(principalKey)
	if !ok {
		return nil
	}
	p, _ := v.(*guard.Principal)
	return p
}

// withParams makes httpguard read path parameters through the RequestContext.
func withParams(o Options, ctx *app.RequestContext) Options {
	o.PathValue = func(_ *http.Request, name string) string { return ctx.Param(name) }
	o.RoutePattern = func(*http.Request) string { return ctx.FullPath() }
	o.ClientIP = func(*http.Request) string { return ctx.ClientIP() }
	return o
}

// Wrap turns an httpguard middleware into a Hertz handler. build receives the
// per-request Options (path parameters, route pattern and client IP already
// wired to the RequestContext), so every httpguard constructor can be used as is.
// When Guard rejects the request the response is written and the chain aborts.
func Wrap(opts Options, build func(Options) httpguard.Middleware) app.HandlerFunc {
	return func(c gocontext.Context, ctx *app.RequestContext) {
		req, err := adaptor.GetCompatRequest(&ctx.Request)
		if err != nil {
			ctx.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		req = req.WithContext(c)
		w := adaptor.GetCompatResponseWriter(&ctx.Response)

		passed := false
		h := build(withParams(opts, ctx))(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			passed = true
			if p := httpguard.PrincipalFrom(r); p != nil {
				ctx.Set(principalKey, p)
			}
		}))
		h.ServeHTTP(w, req)
		if !passed {
			ctx.Abort()
			return
		}
		ctx.Next(c)
	}
}

// Authenticate attaches the principal when a valid token is present; never rejects.
func Authenticate(g *guard.Guard, opts Options) app.HandlerFunc {
	return Wrap(opts, func(o Options) httpguard.Middleware { return httpguard.Authenticate(g, o) })
}

// RequireAuth rejects requests without a valid credential with 401.
func RequireAuth(g *guard.Guard, opts Options) app.HandlerFunc {
	return Wrap(opts, func(o Options) httpguard.Middleware { return httpguard.RequireAuth(g, o) })
}

// RequireSession is RequireAuth that refuses API keys (account-level operations).
func RequireSession(g *guard.Guard, opts Options) app.HandlerFunc {
	return Wrap(opts, func(o Options) httpguard.Middleware { return httpguard.RequireSession(g, o) })
}

// Require authenticates and authorizes action on the resource built by fn.
func Require(g *guard.Guard, opts Options, resourceType, action string, fn httpguard.ResourceFunc) app.HandlerFunc {
	return Wrap(opts, func(o Options) httpguard.Middleware { return httpguard.Require(g, o, resourceType, action, fn) })
}

// RequirePermission is Require for a permission code like "invoice.read".
func RequirePermission(g *guard.Guard, opts Options, code string) app.HandlerFunc {
	return Wrap(opts, func(o Options) httpguard.Middleware { return httpguard.RequirePermission(g, o, code) })
}

// ParamResource uses a path parameter as the resource id.
func ParamResource(param string) httpguard.ResourceFunc { return httpguard.ParamResource(param) }

// RateLimit rejects requests over rule with 429 and sets X-RateLimit-* headers.
func RateLimit(g *guard.Guard, opts Options, name string, rule ratelimit.Rule, key httpguard.KeyFunc) app.HandlerFunc {
	return Wrap(opts, func(o Options) httpguard.Middleware { return httpguard.RateLimit(g, o, name, rule, key) })
}

// Protect authenticates and requires the permission derived from the matched
// route (method + Hertz route path).
func Protect(g *guard.Guard, opts Options, prefix string) app.HandlerFunc {
	return Wrap(opts, func(o Options) httpguard.Middleware { return httpguard.Protect(g, o, prefix) })
}

// Mount registers every Guard route (see httpguard.Mount) on h under prefix
// (""/"/" for the root, "/api" to serve /api/auth/... and /api/guard/...).
func Mount(h *server.Hertz, g *guard.Guard, opts Options, prefix ...string) {
	p := ""
	if len(prefix) > 0 {
		p = trimSlash(prefix[0])
	}
	std := httpguard.Handler(g, opts)
	if p != "" {
		std = http.StripPrefix(p, std)
	}
	handler := stdHandler(std)
	for _, group := range []string{orDefault(opts.AuthPath, "/auth"), orDefault(opts.AdminPath, "/guard")} {
		h.Any(p+group, handler)
		h.Any(p+group+"/*guardpath", handler)
	}
}

// MountAdmin serves the HTML admin panel at adminui.Options.Path
// (default /guard-admin).
func MountAdmin(h *server.Hertz, g *guard.Guard, opts adminui.Options) {
	path := "/" + strings.Trim(orDefault(opts.Path, "/guard-admin"), "/")
	handler := stdHandler(adminui.Handler(g, opts))
	h.Any(path, handler)
	h.Any(path+"/*guardpath", handler)
}

// stdHandler serves an http.Handler from Hertz, translating the request and
// response through the compatibility layer.
func stdHandler(h http.Handler) app.HandlerFunc {
	return func(c gocontext.Context, ctx *app.RequestContext) {
		req, err := adaptor.GetCompatRequest(&ctx.Request)
		if err != nil {
			ctx.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		h.ServeHTTP(adaptor.GetCompatResponseWriter(&ctx.Response), req.WithContext(c))
	}
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
