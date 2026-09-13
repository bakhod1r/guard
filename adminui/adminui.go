// Package adminui is a server-rendered (html/template) admin panel for Guard:
// users, RBAC, ABAC policies, sessions, API keys and audit.
//
//	adminui.Mount(router, g, adminui.Options{Path: "/guard-admin"})
//
// Pages authenticate with the Guard session cookie (API keys are refused),
// check a permission per page and protect every POST with a CSRF token bound
// to the session.
package adminui

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"errors"
	"html/template"
	"io/fs"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/bakhod1r/guard"
	accessdomain "github.com/bakhod1r/guard/access/domain"
	apikeydomain "github.com/bakhod1r/guard/apikey/domain"
	identitydomain "github.com/bakhod1r/guard/identity/domain"
	sessiondomain "github.com/bakhod1r/guard/session/domain"
)

//go:embed templates
var templatesFS embed.FS

type Options struct {
	// Path where the panel is mounted. Default "/guard-admin".
	Path string
	// CookieName must match ginguard.Options.CookieName. Default "guard_session".
	CookieName string
	// InsecureCookie drops the Secure flag (local HTTP development only).
	InsecureCookie bool
	// CSRFSecret signs CSRF tokens. Default: random per process (tokens reset on restart).
	CSRFSecret []byte
}

type app struct {
	g      *guard.Guard
	o      Options
	pages  map[string]*template.Template
	secret []byte
}

// Mount registers the admin panel on r.
func Mount(r gin.IRouter, g *guard.Guard, opts Options) {
	if opts.Path == "" {
		opts.Path = "/guard-admin"
	}
	opts.Path = "/" + strings.Trim(opts.Path, "/")
	if opts.CookieName == "" {
		opts.CookieName = "guard_session"
	}
	a := &app{g: g, o: opts, secret: opts.CSRFSecret}
	if len(a.secret) == 0 {
		a.secret = make([]byte, 32)
		_, _ = rand.Read(a.secret) // never fails since Go 1.24 (crashes the process instead)
	}
	a.pages = mustParse()

	root := r.Group(opts.Path, a.noStore)
	root.GET("/login", a.loginPage)
	root.POST("/login", a.login)

	authed := root.Group("", a.requireSession, a.verifyCSRF)
	authed.POST("/logout", a.logout)
	a.registerDashboard(authed)
	a.registerUsers(authed)
	a.registerRBAC(authed)
	a.registerPolicies(authed)
	a.registerSecurity(authed)
	a.registerAudit(authed)
}

var funcs = template.FuncMap{
	"join": strings.Join,
	"time": func(t any) string {
		switch v := t.(type) {
		case time.Time:
			if v.IsZero() {
				return "—"
			}
			return v.Local().Format("2006-01-02 15:04")
		case *time.Time:
			if v == nil || v.IsZero() {
				return "—"
			}
			return v.Local().Format("2006-01-02 15:04")
		}
		return "—"
	},
	"short": func(s string) string {
		if len(s) > 12 {
			return s[:12] + "…"
		}
		return s
	},
}

// mustParse builds one template set per page: layout.html + pages/<name>.html.
// Each page defines {{define "content"}}.
func mustParse() map[string]*template.Template {
	layout := template.Must(template.New("layout.html").Funcs(funcs).ParseFS(templatesFS, "templates/layout.html"))
	out := map[string]*template.Template{}
	files, _ := fs.Glob(templatesFS, "templates/pages/*.html") // pattern is constant and valid
	for _, f := range files {
		name := strings.TrimSuffix(path.Base(f), ".html")
		out[name] = template.Must(template.Must(layout.Clone()).ParseFS(templatesFS, f))
	}
	return out
}

// View is passed to every template.
type View struct {
	Title  string
	Active string // nav key: dashboard, users, roles, permissions, policies, security, audit
	Base   string
	User   *guard.User
	CSRF   string
	Flash  string
	Error  string
	Nav    []NavItem
	Data   any
}

type NavItem struct {
	Key, Label, Href string
}

var navItems = []struct {
	key, label, href, perm string
}{
	{"dashboard", "Dashboard", "", ""},
	{"users", "Users", "/users", "user.read"},
	{"roles", "Roles", "/roles", "role.read"},
	{"permissions", "Permissions", "/permissions", "permission.read"},
	{"policies", "Policies", "/policies", "policy.read"},
	{"security", "My sessions & API keys", "/security", ""},
	{"audit", "Audit log", "/audit", "audit.read"},
}

func (a *app) render(c *gin.Context, status int, page, title, active string, data any) {
	t, ok := a.pages[page]
	if !ok {
		c.String(http.StatusInternalServerError, "adminui: unknown page "+page)
		return
	}
	v := View{Title: title, Active: active, Base: a.o.Path, Data: data,
		Flash: c.Query("flash"), Error: c.Query("error")}
	if p := ginPrincipal(c); p != nil {
		v.User = p.User
		v.CSRF = a.csrfToken(p.Session.ID)
		for _, n := range navItems {
			if n.perm == "" || a.can(c, n.perm) {
				v.Nav = append(v.Nav, NavItem{Key: n.key, Label: n.label, Href: a.o.Path + n.href})
			}
		}
	}
	c.Status(status)
	c.Header("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(c.Writer, "layout.html", v); err != nil {
		_ = c.Error(err)
	}
}

// redirect goes to path (relative to the panel) with an optional flash message.
func (a *app) redirect(c *gin.Context, p, flash string) {
	target := a.o.Path + p
	if flash != "" {
		target = withQuery(target, "flash", flash)
	}
	c.Redirect(http.StatusSeeOther, target)
}

// fail redirects to path with the error message shown as a banner.
func (a *app) fail(c *gin.Context, p string, err error) {
	msg := err.Error()
	if !isDomainError(err) {
		_ = c.Error(err)
		msg = "internal error"
	}
	c.Redirect(http.StatusSeeOther, withQuery(a.o.Path+p, "error", msg))
}

func withQuery(target, key, val string) string {
	sep := "?"
	if strings.Contains(target, "?") {
		sep = "&"
	}
	return target + sep + key + "=" + url.QueryEscape(val)
}

var domainErrors = []error{
	identitydomain.ErrInvalidEmail, identitydomain.ErrWeakPassword, identitydomain.ErrUserNotFound,
	identitydomain.ErrEmailTaken, identitydomain.ErrInvalidCredentials, identitydomain.ErrUserBlocked,
	identitydomain.ErrUserLocked, identitydomain.ErrInvalidStatus, identitydomain.ErrInvalidUserID,
	identitydomain.ErrAccountExists,
	accessdomain.ErrRoleNotFound, accessdomain.ErrRoleExists, accessdomain.ErrSystemRole,
	accessdomain.ErrPermissionNotFound, accessdomain.ErrPolicyNotFound, accessdomain.ErrPolicyNameTaken,
	accessdomain.ErrSubjectNotFound, accessdomain.ErrInvalidName, accessdomain.ErrInvalidPermission,
	accessdomain.ErrInvalidPolicy,
	apikeydomain.ErrKeyNotFound, apikeydomain.ErrOwnerNotFound, apikeydomain.ErrInvalidName,
	apikeydomain.ErrInvalidScope, apikeydomain.ErrNoScopes, apikeydomain.ErrBadExpiry,
	sessiondomain.ErrSessionNotFound, guard.ErrSessionRequired, errForbidden, errBadInput,
}

var (
	errForbidden = errors.New("you do not have permission for this action")
	errBadInput  = errors.New("invalid input")
)

func isDomainError(err error) bool {
	for _, d := range domainErrors {
		if errors.Is(err, d) {
			return true
		}
	}
	return false
}

// ---------- auth ----------

const principalKey = "adminui.principal"

func ginPrincipal(c *gin.Context) *guard.Principal {
	if v, ok := c.Get(principalKey); ok {
		return v.(*guard.Principal)
	}
	return nil
}

func (a *app) noStore(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.Header("X-Frame-Options", "DENY")
	c.Header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'")
	c.Header("Referrer-Policy", "same-origin")
	c.Next()
}

func (a *app) requireSession(c *gin.Context) {
	tok, err := c.Cookie(a.o.CookieName)
	if err == nil && tok != "" && !apikeydomain.LooksLikeKey(tok) {
		if p, err := a.g.Authenticate(c.Request.Context(), tok); err == nil && p.Session != nil {
			c.Set(principalKey, p)
			c.Next()
			return
		}
	}
	c.Redirect(http.StatusSeeOther, withQuery(a.o.Path+"/login", "next", c.Request.URL.RequestURI()))
	c.Abort()
}

func (a *app) csrfToken(sid sessiondomain.ID) string {
	m := hmac.New(sha256.New, a.secret)
	m.Write([]byte("adminui-csrf:" + string(sid)))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (a *app) verifyCSRF(c *gin.Context) {
	if c.Request.Method == http.MethodGet || c.Request.Method == http.MethodHead {
		c.Next()
		return
	}
	p := ginPrincipal(c)
	want := a.csrfToken(p.Session.ID)
	if !hmac.Equal([]byte(c.PostForm("_csrf")), []byte(want)) {
		c.AbortWithStatus(http.StatusForbidden)
		return
	}
	c.Next()
}

// can reports whether the current principal holds a permission code (resource.action).
func (a *app) can(c *gin.Context, code string) bool {
	return a.canOn(c, code, guard.Resource{})
}

// canOn checks code against a concrete resource (id/attributes feed ABAC).
func (a *app) canOn(c *gin.Context, code string, res guard.Resource) bool {
	p := ginPrincipal(c)
	perm, err := accessdomain.ParsePermission(code)
	if p == nil || err != nil {
		return false
	}
	res.Type = perm.Resource
	d, err := a.g.Authorize(c.Request.Context(), p, perm.Action, res, map[string]any{
		"ip": c.ClientIP(), "now": time.Now().UTC().Format(time.RFC3339),
	})
	return err == nil && d.Allowed
}

// require guards a route with a permission; renders 403 page when denied.
func (a *app) require(code string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !a.can(c, code) {
			a.render(c, http.StatusForbidden, "error", "Forbidden", "", map[string]string{
				"Message": "You need the " + code + " permission to open this page.",
			})
			c.Abort()
			return
		}
		c.Next()
	}
}

func (a *app) loginPage(c *gin.Context) {
	a.render(c, http.StatusOK, "login", "Sign in", "", map[string]string{"Next": safeNext(a.o.Path, c.Query("next"))})
}

// safeNext only allows redirects inside the panel.
func safeNext(base, next string) string {
	clean := path.Clean("/" + strings.TrimPrefix(next, "/"))
	if next == "" || strings.Contains(next, "//") || strings.Contains(next, "\\") || !strings.HasPrefix(clean, base) {
		return base
	}
	return next
}

func (a *app) login(c *gin.Context) {
	next := safeNext(a.o.Path, c.PostForm("next"))
	res, err := a.g.Login(c.Request.Context(), c.PostForm("email"), c.PostForm("password"),
		guard.RequestMeta{IP: c.ClientIP(), UserAgent: c.Request.UserAgent()})
	if err != nil {
		msg := "invalid email or password"
		if errors.Is(err, identitydomain.ErrUserLocked) || errors.Is(err, identitydomain.ErrUserBlocked) {
			msg = err.Error()
		} else if !isDomainError(err) {
			_ = c.Error(err)
			msg = "internal error"
		}
		c.Redirect(http.StatusSeeOther, withQuery(withQuery(a.o.Path+"/login", "error", msg), "next", next))
		return
	}
	c.SetSameSite(http.SameSiteStrictMode)
	c.SetCookie(a.o.CookieName, string(res.Token), int(time.Until(res.Session.ExpiresAt).Seconds()), "/", "", !a.o.InsecureCookie, true)
	c.Redirect(http.StatusSeeOther, next)
}

func (a *app) logout(c *gin.Context) {
	p := ginPrincipal(c)
	_ = a.g.Logout(c.Request.Context(), p, guard.RequestMeta{IP: c.ClientIP(), UserAgent: c.Request.UserAgent()})
	c.SetSameSite(http.SameSiteStrictMode)
	c.SetCookie(a.o.CookieName, "", -1, "/", "", !a.o.InsecureCookie, true)
	c.Redirect(http.StatusSeeOther, a.o.Path+"/login")
}

func (a *app) actor(c *gin.Context) string { return string(ginPrincipal(c).User.ID) }

func (a *app) meta(c *gin.Context) guard.RequestMeta {
	return guard.RequestMeta{IP: c.ClientIP(), UserAgent: c.Request.UserAgent()}
}

func (a *app) audit(c *gin.Context, action, target string, md map[string]any) {
	if a.g.Audit == nil {
		return
	}
	m := a.meta(c)
	_ = a.g.Audit.Record(c.Request.Context(), guard.AuditEvent{ActorID: a.actor(c), Action: action, Target: target,
		Success: true, IP: m.IP, UserAgent: m.UserAgent, Metadata: md})
}
