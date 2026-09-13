// Package ginguard exposes Guard over Gin: ready-made auth/admin routes and middleware.
package ginguard

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/bakhod1r/guard"
	accessdomain "github.com/bakhod1r/guard/access/domain"
	identitydomain "github.com/bakhod1r/guard/identity/domain"
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

func token(c *gin.Context, o Options) guard.SessionToken {
	if h := c.GetHeader("Authorization"); len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return guard.SessionToken(strings.TrimSpace(h[7:]))
	}
	if v, err := c.Cookie(o.CookieName); err == nil {
		return guard.SessionToken(v)
	}
	return ""
}

func meta(c *gin.Context) guard.RequestMeta {
	return guard.RequestMeta{IP: c.ClientIP(), UserAgent: c.Request.UserAgent()}
}

// Authenticate attaches the principal when a valid token is present; never rejects.
func Authenticate(g *guard.Guard, opts Options) gin.HandlerFunc {
	o := opts.withDefaults()
	return func(c *gin.Context) {
		if PrincipalFrom(c) == nil {
			if tok := token(c, o); tok != "" {
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
	if PrincipalFrom(c) != nil {
		return true
	}
	tok := token(c, o)
	if tok == "" {
		abort(c, http.StatusUnauthorized, "unauthenticated", "authentication required")
		return false
	}
	p, err := g.Authenticate(c.Request.Context(), tok)
	switch {
	case err == nil:
		c.Set(principalKey, p)
		return true
	case errors.Is(err, sessiondomain.ErrSessionNotFound), errors.Is(err, sessiondomain.ErrSessionExpired),
		errors.Is(err, identitydomain.ErrUserBlocked):
		abort(c, http.StatusUnauthorized, "unauthenticated", "session expired or invalid")
	default:
		fail(c, err)
	}
	return false
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
}

func fail(c *gin.Context, err error) {
	for _, m := range errorMap {
		if errors.Is(err, m.err) {
			abort(c, m.status, m.code, err.Error())
			return
		}
	}
	_ = c.Error(err)
	abort(c, http.StatusInternalServerError, "internal", "internal error")
}
