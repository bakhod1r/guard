// Package httpguard exposes Guard over net/http: ready-made auth/admin routes
// and middleware built on http.Handler, with no web framework dependency.
//
// Everything here is plain net/http, so it also drives any router that speaks
// http.Handler — chi, gorilla/mux, httprouter, ServeMux, negroni — and, through
// the thin adapters shipped as separate modules, Echo, Fiber, Iris and Hertz.
//
//	mux := http.NewServeMux()
//	httpguard.Mount(mux, g, httpguard.Options{})
//	mux.Handle("GET /api/invoices/{id}",
//	    httpguard.RequirePermission(g, opts, "invoice.read")(invoiceHandler))
package httpguard

import (
	"context"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/bakhod1r/guard"
	"github.com/bakhod1r/guard/ratelimit"
)

// Middleware is the standard net/http decorator shape.
type Middleware func(http.Handler) http.Handler

type Options struct {
	// CookieName carries the session token. Default "guard_session".
	CookieName string
	// InsecureCookie drops the Secure flag (local HTTP development only).
	InsecureCookie bool
	CookieDomain   string
	// AuthPath prefixes self-service routes. Default "/auth".
	AuthPath string
	// AdminPath prefixes management routes. Default "/guard".
	AdminPath string
	// CreateUser inserts a row into the host user table for self-registration
	// and returns its id. When nil, POST /register is not mounted and accounts
	// are created by an admin (POST /guard/users/{id}/account) or by the host
	// via Guard.CreateAccount.
	CreateUser func(ctx context.Context, email string) (userID string, err error)
	// AuthRateLimit throttles /login and /register per client IP.
	// Zero value: 10 requests per minute. Limit < 0 disables.
	AuthRateLimit ratelimit.Rule
	// TrustedOrigins lists origins: "https://app.example.com" also pins the
	// scheme, a bare "app.example.com" accepts any scheme, allowed to send
	// unsafe (POST/PUT/PATCH/DELETE) requests authenticated by the session
	// cookie. Empty: only the request's own Host; when set, the own Host is NOT
	// implied, so list it too if needed. Requests carrying X-Guard-CSRF: 1, a
	// Bearer token or an X-API-Key are exempt.
	TrustedOrigins []string
	// MaxBodyBytes caps request bodies on Guard routes (413 body_too_large).
	// Zero value: 1 MiB.
	MaxBodyBytes int64
	// HSTS sends Strict-Transport-Security even on plain-HTTP requests (set it
	// behind a TLS-terminating proxy). TLS requests always get it.
	HSTS bool
	// ErrorLogger receives internal errors and rate-limiter failures; response
	// bodies only ever say "internal error". Default: DefaultErrorLogger (slog).
	ErrorLogger func(r *http.Request, err error)
	// PathValue reads a path parameter of the matched route. Default:
	// (*http.Request).PathValue, which covers net/http's ServeMux patterns.
	// Routers with their own parameter store plug in here, e.g.
	//	Options{PathValue: chi.URLParam}
	PathValue func(r *http.Request, name string) string
	// RoutePattern reports the pattern of the matched route ("/api/users/{id}"),
	// used by Protect and Environment. Default: (*http.Request).Pattern with the
	// method and host stripped. Returns "" when no route matched.
	RoutePattern func(r *http.Request) string
	// ClientIP resolves the caller address. Default: RemoteAddr without the
	// port. Behind a proxy, plug in a parser you trust (never trust
	// X-Forwarded-For unless the proxy is under your control).
	ClientIP func(r *http.Request) string
	// TrustForwardedFor makes the default ClientIP read the left-most
	// X-Forwarded-For entry. Only enable behind a proxy that overwrites the
	// header on every request.
	TrustForwardedFor bool
}

func (o Options) withDefaults() Options {
	if o.CookieName == "" {
		o.CookieName = "guard_session"
	}
	if o.AuthPath == "" {
		o.AuthPath = "/auth"
	}
	if o.AdminPath == "" {
		o.AdminPath = "/guard"
	}
	if o.AuthRateLimit == (ratelimit.Rule{}) {
		o.AuthRateLimit = ratelimit.Rule{Limit: 10, Window: time.Minute}
	}
	if o.MaxBodyBytes <= 0 {
		o.MaxBodyBytes = DefaultMaxBodyBytes
	}
	if o.ErrorLogger == nil {
		o.ErrorLogger = DefaultErrorLogger
	}
	if o.PathValue == nil {
		o.PathValue = func(r *http.Request, name string) string { return r.PathValue(name) }
	}
	if o.RoutePattern == nil {
		o.RoutePattern = defaultRoutePattern
	}
	if o.ClientIP == nil {
		trust := o.TrustForwardedFor
		o.ClientIP = func(r *http.Request) string { return clientIP(r, trust) }
	}
	return o
}

// defaultRoutePattern strips the method and host from ServeMux's matched
// pattern: "GET example.com/api/users/{id}" -> "/api/users/{id}".
func defaultRoutePattern(r *http.Request) string { return patternPath(r.Pattern) }

// patternPath keeps only the path of a net/http route pattern.
func patternPath(p string) string {
	if p == "" {
		return ""
	}
	if i := strings.IndexByte(p, ' '); i >= 0 {
		p = p[i+1:]
	}
	if i := strings.IndexByte(p, '/'); i > 0 {
		p = p[i:]
	}
	if !strings.HasPrefix(p, "/") {
		return ""
	}
	return p
}

func clientIP(r *http.Request, trustForwarded bool) string {
	if trustForwarded {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			first, _, _ := strings.Cut(xff, ",")
			if ip := strings.TrimSpace(first); ip != "" {
				return ip
			}
		}
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

type ctxKey int

const (
	principalKey ctxKey = iota
	errorLoggerKey
)

// PrincipalFrom returns the authenticated caller, or nil.
func PrincipalFrom(r *http.Request) *guard.Principal {
	p, _ := r.Context().Value(principalKey).(*guard.Principal)
	return p
}

// withPrincipal returns r carrying p.
func withPrincipal(r *http.Request, p *guard.Principal) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), principalKey, p))
}

// credential reads, in order: X-API-Key, Authorization: Bearer, session cookie.
// fromCookie is true when the token came from the cookie (CSRF-exposed).
func credential(r *http.Request, o Options) (tok string, fromCookie bool) {
	if k := strings.TrimSpace(r.Header.Get("X-API-Key")); k != "" {
		return k, false
	}
	if h := r.Header.Get("Authorization"); len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:]), false
	}
	if c, err := r.Cookie(o.CookieName); err == nil {
		return c.Value, true
	}
	return "", false
}

func meta(r *http.Request, o Options) guard.RequestMeta {
	return guard.RequestMeta{IP: o.ClientIP(r), UserAgent: r.UserAgent()}
}

// Param reads a path parameter of the matched route through Options.PathValue.
func Param(r *http.Request, o Options, name string) string {
	return o.withDefaults().PathValue(r, name)
}
