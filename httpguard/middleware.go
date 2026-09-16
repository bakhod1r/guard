package httpguard

import (
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/bakhod1r/guard"
	accessdomain "github.com/bakhod1r/guard/access/domain"
	apikeydomain "github.com/bakhod1r/guard/apikey/domain"
	identitydomain "github.com/bakhod1r/guard/identity/domain"
	"github.com/bakhod1r/guard/ratelimit"
	sessiondomain "github.com/bakhod1r/guard/session/domain"
)

// Authenticate attaches the principal when a valid token is present; never rejects.
func Authenticate(g *guard.Guard, opts Options) Middleware {
	o := opts.withDefaults()
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r = withErrorLogger(r, o.ErrorLogger)
			if PrincipalFrom(r) == nil {
				if tok, cookie := credential(r, o); tok != "" && (!cookie || csrfOK(r, o)) {
					if p, err := g.Authenticate(r.Context(), tok); err == nil {
						r = withPrincipal(r, p)
					}
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireAuth rejects requests without a valid session with 401.
func RequireAuth(g *guard.Guard, opts Options) Middleware {
	o := opts.withDefaults()
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r, ok := authenticate(w, r, g, o)
			if !ok {
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// authenticate attaches the principal or writes the rejection. The returned
// request carries the principal; ok is false when a response was already sent.
func authenticate(w http.ResponseWriter, r *http.Request, g *guard.Guard, o Options) (*http.Request, bool) {
	r = withErrorLogger(r, o.ErrorLogger)
	if PrincipalFrom(r) != nil {
		return r, true
	}
	tok, cookie := credential(r, o)
	if tok == "" {
		abort(w, r, http.StatusUnauthorized, "unauthenticated", "authentication required")
		return r, false
	}
	p, err := g.Authenticate(r.Context(), tok)
	switch {
	case err == nil && cookie && !csrfOK(r, o):
		abort(w, r, http.StatusForbidden, "csrf_failed", "cross-site request rejected: send a trusted Origin or "+CSRFHeader+": 1")
	case err == nil:
		return withPrincipal(r, p), true
	case errors.Is(err, sessiondomain.ErrSessionNotFound), errors.Is(err, sessiondomain.ErrSessionExpired),
		errors.Is(err, identitydomain.ErrUserBlocked), errors.Is(err, apikeydomain.ErrKeyInvalid):
		abort(w, r, http.StatusUnauthorized, "unauthenticated", "credential expired or invalid")
	default:
		fail(w, r, err)
	}
	return r, false
}

// RequireSession is RequireAuth that refuses API keys (account-level operations).
func RequireSession(g *guard.Guard, opts Options) Middleware {
	o := opts.withDefaults()
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r, ok := authenticate(w, r, g, o)
			if !ok {
				return
			}
			if PrincipalFrom(r).Session == nil {
				fail(w, r, guard.ErrSessionRequired)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// KeyFunc derives the rate-limit bucket for a request.
type KeyFunc func(r *http.Request, o Options) string

// ByIP buckets by client IP.
func ByIP(r *http.Request, o Options) string { return "ip:" + o.withDefaults().ClientIP(r) }

// ByPrincipal buckets by API key, then user, falling back to IP.
// Place it after an authenticating middleware.
func ByPrincipal(r *http.Request, o Options) string {
	if p := PrincipalFrom(r); p != nil {
		if p.APIKey != nil {
			return "key:" + p.APIKey.ID
		}
		return "user:" + string(p.User.ID)
	}
	return ByIP(r, o)
}

// RateLimit rejects requests over rule with 429 and sets X-RateLimit-* headers.
// name separates buckets of different routes. Limiter errors fail open
// (recorded through the error logger) so a Redis outage does not take the API down.
func RateLimit(g *guard.Guard, opts Options, name string, rule ratelimit.Rule, key KeyFunc) Middleware {
	if err := rule.Valid(); err != nil {
		panic("httpguard: " + err.Error())
	}
	o := opts.withDefaults()
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if g.Limiter == nil {
				next.ServeHTTP(w, r)
				return
			}
			res, err := g.Limiter.Allow(r.Context(), name+":"+key(r, o), rule)
			if err != nil {
				logError(r, err)
				next.ServeHTTP(w, r)
				return
			}
			h := w.Header()
			h.Set("X-RateLimit-Limit", strconv.Itoa(res.Limit))
			h.Set("X-RateLimit-Remaining", strconv.Itoa(res.Remaining))
			h.Set("X-RateLimit-Reset", strconv.Itoa(int(math.Ceil(res.ResetAfter.Seconds()))))
			if !res.Allowed {
				h.Set("Retry-After", strconv.Itoa(int(math.Ceil(res.RetryAfter.Seconds()))))
				abort(w, r, http.StatusTooManyRequests, "rate_limited", "too many requests")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ResourceFunc builds the ABAC resource from the request (path params, loaded entity...).
type ResourceFunc func(r *http.Request, o Options) (guard.Resource, error)

// Require authenticates and authorizes action on the resource built by fn.
// fn may be nil: the resource then has only a Type.
func Require(g *guard.Guard, opts Options, resourceType, action string, fn ResourceFunc) Middleware {
	o := opts.withDefaults()
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r, ok := authenticate(w, r, g, o)
			if !ok {
				return
			}
			res := guard.Resource{Type: resourceType}
			if fn != nil {
				var err error
				if res, err = fn(r, o); err != nil {
					fail(w, r, err)
					return
				}
				res.Type = resourceType
			}
			d, err := g.Authorize(r.Context(), PrincipalFrom(r), action, res, Environment(r, o))
			if err != nil {
				fail(w, r, err)
				return
			}
			if !d.Allowed {
				abort(w, r, http.StatusForbidden, "forbidden", "not allowed to "+action+" "+resourceType)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequirePermission is Require for a permission code like "invoice.read".
func RequirePermission(g *guard.Guard, opts Options, code string) Middleware {
	p, err := accessdomain.ParsePermission(code)
	if err != nil {
		panic("httpguard: " + err.Error())
	}
	return Require(g, opts, p.Resource, p.Action, nil)
}

// ParamResource uses a path parameter as the resource id.
func ParamResource(param string) ResourceFunc {
	return func(r *http.Request, o Options) (guard.Resource, error) {
		return guard.Resource{ID: o.PathValue(r, param)}, nil
	}
}

// Environment exposes request context to ABAC conditions as env.*.
func Environment(r *http.Request, opts Options) map[string]any {
	o := opts.withDefaults()
	return map[string]any{
		"ip":     o.ClientIP(r),
		"method": r.Method,
		"path":   o.RoutePattern(r),
		"now":    time.Now().UTC().Format(time.RFC3339),
	}
}

type errorBody struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func writeJSON(w http.ResponseWriter, r *http.Request, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		logError(r, err)
	}
}

func abort(w http.ResponseWriter, r *http.Request, status int, code, msg string) {
	var b errorBody
	b.Error.Code, b.Error.Message = code, msg
	writeJSON(w, r, status, b)
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

func fail(w http.ResponseWriter, r *http.Request, err error) {
	for _, m := range errorMap {
		if errors.Is(err, m.err) {
			abort(w, r, m.status, m.code, err.Error())
			return
		}
	}
	logError(r, err)
	abort(w, r, http.StatusInternalServerError, "internal", "internal error")
}
