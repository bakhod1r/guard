package adminui_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"

	"github.com/bakhod1r/guard"
	"github.com/bakhod1r/guard/adminui"
	"github.com/bakhod1r/guard/guardtest"
)

// panel is a tiny browser: keeps the session cookie and the latest CSRF token.
type panel struct {
	t      *testing.T
	g      *guard.Guard
	r      *gin.Engine
	cookie *http.Cookie
	csrf   string
}

var csrfRe = regexp.MustCompile(`name="_csrf" value="([^"]+)"`)

func newPanel(t *testing.T) *panel {
	t.Helper()
	gin.SetMode(gin.TestMode)
	mr := miniredis.RunT(t)
	g := guardtest.New(redis.NewClient(&redis.Options{Addr: mr.Addr()}), guard.Config{})
	r := gin.New()
	adminui.Mount(r, g, adminui.Options{InsecureCookie: true})
	return &panel{t: t, g: g, r: r}
}

// account creates a host user account; admin=true grants the admin role.
func (p *panel) account(id, email string, admin bool) {
	p.t.Helper()
	ctx := context.Background()
	if admin {
		if _, err := p.g.EnsureAdmin(ctx, id, email, "password123"); err != nil {
			p.t.Fatal(err)
		}
		return
	}
	if _, err := p.g.CreateAccount(ctx, id, email, "password123", nil, guard.RequestMeta{}); err != nil {
		p.t.Fatal(err)
	}
}

func (p *panel) login(email string) {
	p.t.Helper()
	p.cookie = nil
	code, _, hdr := p.post("/guard-admin/login", url.Values{"email": {email}, "password": {"password123"}})
	if code != http.StatusSeeOther {
		p.t.Fatalf("login %s: %d", email, code)
	}
	for _, c := range (&http.Response{Header: hdr}).Cookies() {
		if c.Name == "guard_session" {
			p.cookie = c
		}
	}
	if p.cookie == nil {
		p.t.Fatal("no session cookie")
	}
	p.get("/guard-admin") // pick up CSRF token
}

func (p *panel) get(path string) (int, string) {
	p.t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	if p.cookie != nil {
		req.AddCookie(p.cookie)
	}
	w := httptest.NewRecorder()
	p.r.ServeHTTP(w, req)
	body := w.Body.String()
	if m := csrfRe.FindStringSubmatch(body); m != nil {
		p.csrf = m[1]
	}
	return w.Code, body
}

// post submits a form, adding the CSRF token unless form already has _csrf.
func (p *panel) post(path string, form url.Values) (int, string, http.Header) {
	p.t.Helper()
	if form == nil {
		form = url.Values{}
	}
	if _, ok := form["_csrf"]; !ok && p.csrf != "" {
		form.Set("_csrf", p.csrf)
	}
	req := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if p.cookie != nil {
		req.AddCookie(p.cookie)
	}
	w := httptest.NewRecorder()
	p.r.ServeHTTP(w, req)
	b, _ := io.ReadAll(w.Body)
	return w.Code, string(b), w.Header()
}

// location returns the redirect target of the last post response header.
func location(h http.Header) string { return h.Get("Location") }
