package adminui_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"

	"github.com/bakhod1r/guard"
	accessinfra "github.com/bakhod1r/guard/access/infrastructure"
	"github.com/bakhod1r/guard/adminui"
	apikeyinfra "github.com/bakhod1r/guard/apikey/infrastructure"
	"github.com/bakhod1r/guard/guardtest"
	identityinfra "github.com/bakhod1r/guard/identity/infrastructure"
	"github.com/bakhod1r/guard/ratelimit"
	sessiondomain "github.com/bakhod1r/guard/session/domain"
	sessioninfra "github.com/bakhod1r/guard/session/infrastructure"
)

const strongPassword = "tr0ub4dor-guard-42"

func serve(r *gin.Engine, req *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func formReq(path string, form url.Values) *http.Request {
	req := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

var (
	nonceRe  = regexp.MustCompile(`script-src 'nonce-([A-Za-z0-9_-]+)'`)
	inlineRe = regexp.MustCompile(`(?i)\s(on[a-z]+|style)\s*=`)
)

func TestNonceCSPAndNoInlineCode(t *testing.T) {
	p := newPanel(t)
	p.account("1", "admin@example.com", true)

	w := serve(p.r, httptest.NewRequest("GET", "/guard-admin/login", nil))
	csp := w.Header().Get("Content-Security-Policy")
	m := nonceRe.FindStringSubmatch(csp)
	if m == nil || strings.Contains(csp, "unsafe-inline") || !strings.Contains(csp, "style-src 'nonce-"+m[1]+"'") ||
		!strings.Contains(csp, "form-action 'self'") || !strings.Contains(csp, "base-uri 'none'") || !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Fatalf("csp: %q", csp)
	}
	body := w.Body.String()
	if !strings.Contains(body, `<style nonce="`+m[1]+`">`) || !strings.Contains(body, `<script nonce="`+m[1]+`">`) {
		t.Fatalf("nonce not applied to style/script")
	}
	if w.Header().Get("X-Robots-Tag") != "noindex, nofollow" || !strings.Contains(body, `<meta name="robots" content="noindex, nofollow">`) ||
		w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("robots/nosniff: %v", w.Header())
	}
	again := nonceRe.FindStringSubmatch(serve(p.r, httptest.NewRequest("GET", "/guard-admin/login", nil)).Header().Get("Content-Security-Policy"))
	if again[1] == m[1] {
		t.Fatal("nonce reused across requests")
	}

	p.login("admin@example.com")
	p.account("2", "user@example.com", false)
	if _, err := p.g.Login(context.Background(), "user@example.com", strongPassword, guard.RequestMeta{}); err != nil {
		t.Fatal(err)
	}
	_, _, _ = p.post("/guard-admin/users/2/roles", url.Values{"role": {"user"}})
	_, _, _ = p.post("/guard-admin/roles", url.Values{"name": {"ops"}, "title": {"Ops"}})
	_, _, _ = p.post("/guard-admin/roles/ops/permissions", url.Values{"code": {"user.read"}})
	pages := []string{"", "/users", "/users/2", "/roles", "/roles/admin", "/roles/ops", "/permissions", "/policies",
		"/policies/new", "/policies/00000000-0000-0000-0000-000000000001", "/security", "/audit", "/nope-404"}
	for _, pg := range pages {
		_, body := p.get("/guard-admin" + pg)
		if loc := inlineRe.FindString(body); loc != "" {
			t.Errorf("%s: inline attribute %q", pg, loc)
		}
	}
	_, _, _ = p.post("/guard-admin/security/api-keys", url.Values{"name": {"ci"}, "scopes": {"user.read"}})
	code, keyPage, _ := p.post("/guard-admin/security/api-keys", url.Values{"name": {"ci2"}, "scopes": {"user.read"}})
	if code != http.StatusCreated || inlineRe.MatchString(keyPage) || !strings.Contains(keyPage, `data-copy="new-key"`) {
		t.Fatalf("key page: %d inline=%v", code, inlineRe.FindString(keyPage))
	}

	confirms := map[string]int{"/users/2": 4, "/security": 3, "/roles/ops": 2, "/policies": 1}
	for pg, min := range confirms {
		_, body := p.get("/guard-admin" + pg)
		if n := strings.Count(body, "data-confirm="); n < min {
			t.Errorf("%s: %d data-confirm forms, want >= %d", pg, n, min)
		}
	}
}

func TestFormBodyLimit(t *testing.T) {
	p := newPanelWith(t, adminui.Options{InsecureCookie: true, MaxBodyBytes: 64})
	p.account("1", "admin@example.com", true)
	big := url.Values{"email": {"admin@example.com"}, "password": {strings.Repeat("x", 100)}}
	if w := serve(p.r, formReq("/guard-admin/login", big)); w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("declared length: %d", w.Code)
	}
	streamed := formReq("/guard-admin/login", big)
	streamed.Body = io.NopCloser(io.MultiReader(strings.NewReader(big.Encode())))
	streamed.ContentLength = -1
	if w := serve(p.r, streamed); w.Code != http.StatusRequestEntityTooLarge || !strings.Contains(w.Body.String(), "too large") {
		t.Fatalf("streamed: %d", w.Code)
	}
	bad := httptest.NewRequest("POST", "/guard-admin/login", strings.NewReader("%zz"))
	bad.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if w := serve(p.r, bad); w.Code != http.StatusBadRequest {
		t.Fatalf("malformed: %d", w.Code)
	}

	d := newPanel(t)
	d.account("1", "admin@example.com", true)
	huge := url.Values{"email": {"admin@example.com"}, "password": {strings.Repeat("x", 1<<20)}}
	if w := serve(d.r, formReq("/guard-admin/login", huge)); w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("default 1 MiB: %d", w.Code)
	}
	d.login("admin@example.com")
}

func TestLoginRateLimit(t *testing.T) {
	attempt := func(p *panel) *httptest.ResponseRecorder {
		return serve(p.r, formReq("/guard-admin/login", url.Values{"email": {"nobody@example.com"}, "password": {strongPassword}}))
	}
	t.Run("custom rule", func(t *testing.T) {
		p := newPanelWith(t, adminui.Options{LoginRateLimit: ratelimit.Rule{Limit: 2, Window: time.Minute}})
		for i := 0; i < 2; i++ {
			if w := attempt(p); w.Code != http.StatusSeeOther {
				t.Fatalf("attempt %d: %d", i, w.Code)
			}
		}
		w := attempt(p)
		if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" || !strings.Contains(w.Body.String(), "Too many sign-in attempts") {
			t.Fatalf("limited: %d %v", w.Code, w.Header())
		}
		if w := serve(p.r, httptest.NewRequest("GET", "/guard-admin/login", nil)); w.Code != 200 {
			t.Fatalf("GET login limited: %d", w.Code)
		}
	})
	t.Run("default 10 per minute", func(t *testing.T) {
		p := newPanel(t)
		for i := 0; i < 10; i++ {
			if w := attempt(p); w.Code != http.StatusSeeOther {
				t.Fatalf("attempt %d: %d", i, w.Code)
			}
		}
		if w := attempt(p); w.Code != http.StatusTooManyRequests {
			t.Fatalf("11th: %d", w.Code)
		}
	})
	t.Run("negative disables", func(t *testing.T) {
		p := newPanelWith(t, adminui.Options{LoginRateLimit: ratelimit.Rule{Limit: -1}})
		for i := 0; i < 12; i++ {
			if w := attempt(p); w.Code != http.StatusSeeOther {
				t.Fatalf("attempt %d: %d", i, w.Code)
			}
		}
	})
	t.Run("limiter error fails open and is logged", func(t *testing.T) {
		var logged []error
		p := newPanelWith(t, adminui.Options{ErrorLogger: func(_ *gin.Context, err error) { logged = append(logged, err) }})
		boom := errors.New("redis down")
		p.g.Limiter = limiterFunc(func(context.Context, string, ratelimit.Rule) (ratelimit.Result, error) {
			return ratelimit.Result{}, boom
		})
		if w := attempt(p); w.Code != http.StatusSeeOther || len(logged) != 1 || !errors.Is(logged[0], boom) {
			t.Fatalf("%d logged=%v", w.Code, logged)
		}
	})
	t.Run("bucket key", func(t *testing.T) {
		var keys []string
		p := newPanel(t)
		p.g.Limiter = limiterFunc(func(_ context.Context, key string, _ ratelimit.Rule) (ratelimit.Result, error) {
			keys = append(keys, key)
			return ratelimit.Result{Allowed: true}, nil
		})
		attempt(p)
		if len(keys) != 1 || keys[0] != "adminui-login:ip:192.0.2.1" {
			t.Fatalf("keys %v", keys)
		}
	})
	t.Run("invalid rule panics", func(t *testing.T) {
		defer func() {
			if v := recover(); v == nil || !strings.HasPrefix(v.(string), "adminui: ") {
				t.Fatalf("panic: %v", v)
			}
		}()
		newPanelWith(t, adminui.Options{LoginRateLimit: ratelimit.Rule{Limit: 1}})
	})
}

type limiterFunc func(ctx context.Context, key string, rule ratelimit.Rule) (ratelimit.Result, error)

func (l limiterFunc) Allow(ctx context.Context, key string, rule ratelimit.Rule) (ratelimit.Result, error) {
	return l(ctx, key, rule)
}

func TestLoginRevokesPreviousCookieSession(t *testing.T) {
	p := newPanel(t)
	p.account("1", "admin@example.com", true)
	loginWith := func(cookie *http.Cookie) *httptest.ResponseRecorder {
		req := formReq("/guard-admin/login", url.Values{"email": {"admin@example.com"}, "password": {strongPassword}})
		if cookie != nil {
			req.AddCookie(cookie)
		}
		return serve(p.r, req)
	}
	p.login("admin@example.com")
	old := p.cookie
	if w := loginWith(old); w.Code != http.StatusSeeOther {
		t.Fatalf("relogin: %d", w.Code)
	}
	if code, _ := p.get("/guard-admin"); code != http.StatusSeeOther {
		t.Fatalf("planted session survived login: %d", code)
	}
	if w := loginWith(&http.Cookie{Name: "guard_session", Value: "not-a-session"}); w.Code != http.StatusSeeOther ||
		!strings.Contains(w.Header().Get("Set-Cookie"), "guard_session=") {
		t.Fatalf("invalid cookie: %d", w.Code)
	}
	_, tok, err := p.g.IssueAPIKey(context.Background(), mustPrincipal(t, p), "k", []string{"*"}, nil, guard.RequestMeta{})
	if err != nil {
		t.Fatal(err)
	}
	if w := loginWith(&http.Cookie{Name: "guard_session", Value: string(tok)}); w.Code != http.StatusSeeOther {
		t.Fatalf("api key cookie: %d", w.Code)
	}
	if _, err := p.g.Authenticate(context.Background(), string(tok)); err != nil {
		t.Fatalf("api key revoked by login: %v", err)
	}
}

func mustPrincipal(t *testing.T, p *panel) *guard.Principal {
	t.Helper()
	res, err := p.g.Login(context.Background(), "admin@example.com", strongPassword, guard.RequestMeta{})
	if err != nil {
		t.Fatal(err)
	}
	pr, err := p.g.Authenticate(context.Background(), string(res.Token))
	if err != nil {
		t.Fatal(err)
	}
	return pr
}

type failingDelete struct {
	sessiondomain.Repository
	err *error
}

func (f failingDelete) Delete(ctx context.Context, id sessiondomain.ID) error {
	if *f.err != nil {
		return *f.err
	}
	return f.Repository.Delete(ctx, id)
}

func TestLoginRevokeFailureIsLoggedNotShown(t *testing.T) {
	gin.SetMode(gin.TestMode)
	rdb := redis.NewClient(&redis.Options{Addr: miniredis.RunT(t).Addr()})
	var deleteErr error
	store := accessinfra.NewMemory()
	g := guard.Build(guard.Repositories{
		Users:    identityinfra.NewMemoryUsers(),
		Hasher:   &identityinfra.Argon2Hasher{Memory: 1024, Time: 1, Threads: 1, KeyLen: 32, SaltLen: 16},
		Sessions: failingDelete{sessioninfra.NewRedisSessions(rdb, "rv:"), &deleteErr},
		Roles:    store, Policies: store, APIKeys: apikeyinfra.NewMemory(),
	}, guard.Config{})
	guardtest.Seed(context.Background(), store)
	var logged []error
	r := gin.New()
	adminui.Mount(r, g, adminui.Options{InsecureCookie: true, ErrorLogger: func(_ *gin.Context, err error) { logged = append(logged, err) }})
	p := &panel{t: t, g: g, r: r}
	p.account("1", "admin@example.com", true)
	p.login("admin@example.com")
	deleteErr = errors.New("redis: connection reset")
	req := formReq("/guard-admin/login", url.Values{"email": {"admin@example.com"}, "password": {strongPassword}})
	req.AddCookie(p.cookie)
	w := serve(r, req)
	if w.Code != http.StatusSeeOther || len(logged) != 1 || !errors.Is(logged[0], deleteErr) || strings.Contains(w.Header().Get("Location"), "redis") {
		t.Fatalf("%d %s logged=%v", w.Code, w.Header().Get("Location"), logged)
	}
}
