// Package ginguard exposes Guard over Gin: ready-made auth/admin routes and middleware.
package ginguard

import (
	"context"
	"errors"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/bakhod1r/guard"
	accessdomain "github.com/bakhod1r/guard/access/domain"
	apikeydomain "github.com/bakhod1r/guard/apikey/domain"
	identitydomain "github.com/bakhod1r/guard/identity/domain"
	"github.com/bakhod1r/guard/ratelimit"
	sessiondomain "github.com/bakhod1r/guard/session/domain"
)

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
	// are created by an admin (POST /guard/users/:id/account) or by the host via
	// Guard.CreateAccount.
	CreateUser func(ctx context.Context, email string) (userID string, err error)
	// AuthRateLimit throttles /login and /register per client IP.
	// Zero value: 10 requests per minute. Limit < 0 disables.
	AuthRateLimit ratelimit.Rule
	// TrustedOrigins lists hosts ("app.example.com" or "https://app.example.com")
	// allowed to send unsafe (POST/PUT/PATCH/DELETE) requests authenticated by
	// the session cookie. Empty: only the request's own Host; when set, the own
	// Host is NOT implied, so list it too if needed. Requests carrying
	// X-Guard-CSRF: 1, a Bearer token or an X-API-Key are exempt.
	TrustedOrigins []string
	// MaxBodyBytes caps request bodies on Guard routes (413 body_too_large).
	// Zero value: 1 MiB.
	MaxBodyBytes int64
	// HSTS sends Strict-Transport-Security even on plain-HTTP requests (set it
	// behind a TLS-terminating proxy). TLS requests always get it.
	HSTS bool
	// ErrorLogger receives internal errors and rate-limiter failures; response
	// bodies only ever say "internal error". Default: DefaultErrorLogger (slog).
	ErrorLogger func(c *gin.Context, err error)
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
	return o
}

const principalKey = "guard.principal"

// PrincipalFrom returns the authenticated caller, or nil.
func PrincipalFrom(c *gin.Context) *guard.Principal {
	if v, ok := c.Get(principalKey); ok {
		return v.(*guard.Principal)
	}
	return nil
}

// credential reads, in order: X-API-Key, Authorization: Bearer, session cookie.
// fromCookie is true when the token came from the cookie (CSRF-exposed).
func credential(c *gin.Context, o Options) (tok string, fromCookie bool) {
	if k := strings.TrimSpace(c.GetHeader("X-API-Key")); k != "" {
		return k, false
	}
	if h := c.GetHeader("Authorization"); len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:]), false
	}
	if v, err := c.Cookie(o.CookieName); err == nil {
		return v, true
	}
	return "", false
}

// useErrorLogger installs o.ErrorLogger unless an outer layer already did.
func useErrorLogger(c *gin.Context, o Options) {
	if _, ok := c.Get(errorLoggerKey); !ok {
		c.Set(errorLoggerKey, o.ErrorLogger)
	}
}

func meta(c *gin.Context) guard.RequestMeta {
	return guard.RequestMeta{IP: c.ClientIP(), UserAgent: c.Request.UserAgent()}
}

// Authenticate attaches the principal when a valid token is present; never rejects.
func Authenticate(g *guard.Guard, opts Options) gin.HandlerFunc {
	o := opts.withDefaults()
	return func(c *gin.Context) {
		useErrorLogger(c, o)
		if PrincipalFrom(c) == nil {
			if tok, cookie := credential(c, o); tok != "" && (!cookie || csrfOK(c, o)) {
				if p, err := g.Authenticate(c.Request.Context(), tok); err == nil {
					c.Set(principalKey, p)
				}
			}
		}
		c.Next()
	}
}

// RequireAuth rejects requests without a valid session with 401.
func RequireAuth(g *guard.Guard, opts Options) gin.HandlerFunc {
	o := opts.withDefaults()
	return func(c *gin.Context) {
		if authenticate(c, g, o) {
			c.Next()
		}
	}
}

// authenticate attaches the principal or aborts; it never calls c.Next so
// callers can run further checks before the handler chain continues.
func authenticate(c *gin.Context, g *guard.Guard, o Options) bool {
	useErrorLogger(c, o)
	if PrincipalFrom(c) != nil {
		return true
	}
	tok, cookie := credential(c, o)
	if tok == "" {
		abort(c, http.StatusUnauthorized, "unauthenticated", "authentication required")
		return false
	}
	p, err := g.Authenticate(c.Request.Context(), tok)
	switch {
	case err == nil && cookie && !csrfOK(c, o):
		abort(c, http.StatusForbidden, "csrf_failed", "cross-site request rejected: send a trusted Origin or "+CSRFHeader+": 1")
	case err == nil:
		c.Set(principalKey, p)
		return true
	case errors.Is(err, sessiondomain.ErrSessionNotFound), errors.Is(err, sessiondomain.ErrSessionExpired),
		errors.Is(err, identitydomain.ErrUserBlocked), errors.Is(err, apikeydomain.ErrKeyInvalid):
		abort(c, http.StatusUnauthorized, "unauthenticated", "credential expired or invalid")
	default:
		fail(c, err)
	}
	return false
}

// RequireSession is RequireAuth that refuses API keys (account-level operations).
func RequireSession(g *guard.Guard, opts Options) gin.HandlerFunc {
	o := opts.withDefaults()
	return func(c *gin.Context) {
		if !authenticate(c, g, o) {
			return
		}
		if PrincipalFrom(c).Session == nil {
			fail(c, guard.ErrSessionRequired)
			return
		}
		c.Next()
	}
}

// KeyFunc derives the rate-limit bucket for a request.
type KeyFunc func(c *gin.Context) string

// ByIP buckets by client IP.
func ByIP(c *gin.Context) string { return "ip:" + c.ClientIP() }

// ByPrincipal buckets by API key, then user, falling back to IP.
// Place it after an authenticating middleware.
func ByPrincipal(c *gin.Context) string {
	if p := PrincipalFrom(c); p != nil {
		if p.APIKey != nil {
			return "key:" + p.APIKey.ID
		}
		return "user:" + string(p.User.ID)
	}
	return ByIP(c)
}

// RateLimit rejects requests over rule with 429 and sets X-RateLimit-* headers.
// name separates buckets of different routes. Limiter errors fail open
// (recorded via c.Error and the error logger) so a Redis outage does not take the API down.
func RateLimit(g *guard.Guard, name string, rule ratelimit.Rule, key KeyFunc) gin.HandlerFunc {
	if err := rule.Valid(); err != nil {
		panic("ginguard: " + err.Error())
	}
	return func(c *gin.Context) {
		if g.Limiter == nil {
			c.Next()
			return
		}
		res, err := g.Limiter.Allow(c.Request.Context(), name+":"+key(c), rule)
		if err != nil {
			logError(c, err)
			c.Next()
			return
		}
		c.Header("X-RateLimit-Limit", strconv.Itoa(res.Limit))
		c.Header("X-RateLimit-Remaining", strconv.Itoa(res.Remaining))
		c.Header("X-RateLimit-Reset", strconv.Itoa(int(math.Ceil(res.ResetAfter.Seconds()))))
		if !res.Allowed {
			c.Header("Retry-After", strconv.Itoa(int(math.Ceil(res.RetryAfter.Seconds()))))
			abort(c, http.StatusTooManyRequests, "rate_limited", "too many requests")
			return
		}
		c.Next()
	}
}

// ResourceFunc builds the ABAC resource from the request (path params, loaded entity...).
type ResourceFunc func(c *gin.Context) (guard.Resource, error)

// Require authenticates and authorizes action on the resource built by fn.
// fn may be nil: the resource then has only a Type.
func Require(g *guard.Guard, opts Options, resourceType, action string, fn ResourceFunc) gin.HandlerFunc {
	o := opts.withDefaults()
	return func(c *gin.Context) {
		if !authenticate(c, g, o) {
			return
		}
		res := guard.Resource{Type: resourceType}
		if fn != nil {
			var err error
			if res, err = fn(c); err != nil {
				fail(c, err)
				return
			}
			res.Type = resourceType
		}
		d, err := g.Authorize(c.Request.Context(), PrincipalFrom(c), action, res, Environment(c))
		if err != nil {
			fail(c, err)
			return
		}
		if !d.Allowed {
			abort(c, http.StatusForbidden, "forbidden", "not allowed to "+action+" "+resourceType)
			return
		}
		c.Next()
	}
}

// RequirePermission is Require for a permission code like "invoice.read".
func RequirePermission(g *guard.Guard, opts Options, code string) gin.HandlerFunc {
	p, err := accessdomain.ParsePermission(code)
	if err != nil {
		panic("ginguard: " + err.Error())
	}
	return Require(g, opts, p.Resource, p.Action, nil)
}

// ParamResource uses a path parameter as the resource id.
func ParamResource(param string) ResourceFunc {
	return func(c *gin.Context) (guard.Resource, error) {
		return guard.Resource{ID: c.Param(param)}, nil
	}
}

// Environment exposes request context to ABAC conditions as env.*.
func Environment(c *gin.Context) map[string]any {
	return map[string]any{
		"ip":     c.ClientIP(),
		"method": c.Request.Method,
		"path":   c.FullPath(),
		"now":    time.Now().UTC().Format(time.RFC3339),
	}
}

type errorBody struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func abort(c *gin.Context, status int, code, msg string) {
	var b errorBody
	b.Error.Code, b.Error.Message = code, msg
	c.AbortWithStatusJSON(status, b)
}

var errorMap = []struct {
	err    error
	status int
	code   string
}{
	{identitydomain.ErrInvalidEmail, http.StatusBadRequest, "invalid_email"},
	{identitydomain.ErrWeakPassword, http.StatusBadRequest, "weak_password"},
	{identitydomain.ErrInvalidStatus, http.StatusBadRequest, "invalid_status"},
	{identitydomain.ErrInvalidCredentials, http.StatusUnauthorized, "invalid_credentials"},
	{identitydomain.ErrUserLocked, http.StatusTooManyRequests, "account_locked"},
	{identitydomain.ErrUserBlocked, http.StatusForbidden, "account_blocked"},
	{identitydomain.ErrEmailTaken, http.StatusConflict, "email_taken"},
	{identitydomain.ErrUserNotFound, http.StatusNotFound, "user_not_found"},
	{identitydomain.ErrInvalidUserID, http.StatusBadRequest, "invalid_user_id"},
	{identitydomain.ErrAccountExists, http.StatusConflict, "account_exists"},
	{sessiondomain.ErrSessionNotFound, http.StatusNotFound, "session_not_found"},
	{accessdomain.ErrInvalidName, http.StatusBadRequest, "invalid_name"},
	{accessdomain.ErrInvalidPermission, http.StatusBadRequest, "invalid_permission"},
	{accessdomain.ErrInvalidPolicy, http.StatusBadRequest, "invalid_policy"},
	{accessdomain.ErrRoleExists, http.StatusConflict, "role_exists"},
	{accessdomain.ErrPolicyNameTaken, http.StatusConflict, "policy_name_taken"},
	{accessdomain.ErrSystemRole, http.StatusConflict, "system_role"},
	{accessdomain.ErrRoleNotFound, http.StatusNotFound, "role_not_found"},
	{accessdomain.ErrPermissionNotFound, http.StatusNotFound, "permission_not_found"},
	{accessdomain.ErrPolicyNotFound, http.StatusNotFound, "policy_not_found"},
	{accessdomain.ErrSubjectNotFound, http.StatusNotFound, "user_not_found"},
	{accessdomain.ErrForbidden, http.StatusForbidden, "forbidden"},
	{accessdomain.ErrLastSuperAdmin, http.StatusConflict, "last_super_admin"},
	{accessdomain.ErrSuperAdminExpiry, http.StatusBadRequest, "invalid_expiry"},
	{guard.ErrSessionRequired, http.StatusForbidden, "session_required"},
	{apikeydomain.ErrInvalidName, http.StatusBadRequest, "invalid_name"},
	{apikeydomain.ErrInvalidScope, http.StatusBadRequest, "invalid_scope"},
	{apikeydomain.ErrNoScopes, http.StatusBadRequest, "invalid_scope"},
	{apikeydomain.ErrBadExpiry, http.StatusBadRequest, "invalid_expiry"},
	{apikeydomain.ErrKeyNotFound, http.StatusNotFound, "api_key_not_found"},
	{apikeydomain.ErrOwnerNotFound, http.StatusNotFound, "user_not_found"},
	{apikeydomain.ErrKeyInvalid, http.StatusUnauthorized, "unauthenticated"},
}

func fail(c *gin.Context, err error) {
	for _, m := range errorMap {
		if errors.Is(err, m.err) {
			abort(c, m.status, m.code, err.Error())
			return
		}
	}
	logError(c, err)
	abort(c, http.StatusInternalServerError, "internal", "internal error")
}
