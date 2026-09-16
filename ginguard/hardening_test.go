package ginguard_test

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	accessdomain "github.com/bakhod1r/guard/access/domain"
	"github.com/bakhod1r/guard/ginguard"
	"github.com/bakhod1r/guard/ratelimit"
)

const strongPassword = "tr0ub4dor-guard-42"

// keyBody is a harmless unsafe request authenticated by whatever credential is sent.
const keyBody = `{"name":"ci","scopes":["*"]}`

func TestCookieUnsafeRequestsRequireTrustedOrigin(t *testing.T) {
	e := newEnv(t, envConfig{})
	e.router.POST("/opt", ginguard.Authenticate(e.g, ginguard.Options{}), func(c *gin.Context) {
		c.JSON(200, gin.H{"authed": ginguard.PrincipalFrom(c) != nil})
	})
	ginguard.Mount(e.router, e.g, ginguard.Options{AuthPath: "/t/auth", AdminPath: "/t/guard", AuthRateLimit: ratelimit.Rule{Limit: -1},
		TrustedOrigins: []string{"https://app.example.com", "api.example.com"}})
	cookie := "guard_session=" + e.admin
	cases := []struct {
		name, path string
		headers    map[string]string
		want       int
	}{
		{"no origin", "/auth/api-keys", map[string]string{"Cookie": cookie}, 403},
		{"cross-site origin", "/auth/api-keys", map[string]string{"Cookie": cookie, "Origin": "https://evil.test"}, 403},
		{"null origin", "/auth/api-keys", map[string]string{"Cookie": cookie, "Origin": "null"}, 403},
		{"unparsable referer", "/auth/api-keys", map[string]string{"Cookie": cookie, "Referer": "http://[::1"}, 403},
		{"same-host origin", "/auth/api-keys", map[string]string{"Cookie": cookie, "Origin": "http://example.com"}, 201},
		{"same-host referer", "/auth/api-keys", map[string]string{"Cookie": cookie, "Referer": "http://example.com/app/page"}, 201},
		{"csrf header", "/auth/api-keys", map[string]string{"Cookie": cookie, "X-Guard-CSRF": "1"}, 201},
		{"csrf header wrong value", "/auth/api-keys", map[string]string{"Cookie": cookie, "X-Guard-CSRF": "yes"}, 403},
		{"bearer exempt", "/auth/api-keys", map[string]string{"Authorization": "Bearer " + e.admin}, 201},
		{"trusted origin url form", "/t/auth/api-keys", map[string]string{"Cookie": cookie, "Origin": "https://app.example.com"}, 201},
		{"trusted origin wrong scheme", "/t/auth/api-keys", map[string]string{"Cookie": cookie, "Origin": "http://app.example.com"}, 403},
		{"trusted origin host form", "/t/auth/api-keys", map[string]string{"Cookie": cookie, "Origin": "https://API.example.com"}, 201},
		{"own host not implied when list set", "/t/auth/api-keys", map[string]string{"Cookie": cookie, "Origin": "http://example.com"}, 403},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := e.raw("POST", tc.path, keyBody, tc.headers)
			if r.code != tc.want {
				t.Fatalf("want %d got %d %v", tc.want, r.code, r.body)
			}
			if tc.want == 403 && r.errCode() != "csrf_failed" {
				t.Fatalf("code: %v", r.body)
			}
		})
	}
	t.Run("optional middleware ignores cross-site cookie", func(t *testing.T) {
		if r := e.raw("POST", "/opt", "", map[string]string{"Cookie": cookie}); r.code != 200 || r.body["authed"] != false {
			t.Fatalf("%d %v", r.code, r.body)
		}
		if r := e.raw("POST", "/opt", "", map[string]string{"Cookie": cookie, "X-Guard-CSRF": "1"}); r.body["authed"] != true {
			t.Fatalf("%d %v", r.code, r.body)
		}
	})
	t.Run("API key exempt", func(t *testing.T) {
		key := e.do("POST", "/auth/api-keys", e.admin, map[string]any{"name": "k", "scopes": []string{"*"}}).body["token"].(string)
		if r := e.raw("POST", "/auth/api-keys", keyBody, map[string]string{"X-API-Key": key}); r.errCode() == "csrf_failed" {
			t.Fatalf("api key hit csrf: %v", r.body)
		}
	})
}

func TestSecurityHeaders(t *testing.T) {
	e := newEnv(t, envConfig{})
	ginguard.Mount(e.router, e.g, ginguard.Options{AuthPath: "/h/auth", AdminPath: "/h/guard", HSTS: true, AuthRateLimit: ratelimit.Rule{Limit: -1}})
	check := func(t *testing.T, h http.Header, hsts bool) {
		t.Helper()
		if h.Get("X-Content-Type-Options") != "nosniff" || h.Get("Referrer-Policy") != "same-origin" || h.Get("X-Frame-Options") != "DENY" {
			t.Fatalf("headers: %v", h)
		}
		if (h.Get("Strict-Transport-Security") != "") != hsts {
			t.Fatalf("hsts=%v: %v", hsts, h)
		}
	}
	t.Run("plain http auth group", func(t *testing.T) { check(t, e.do("GET", "/auth/me", "", nil).w.Header(), false) })
	t.Run("admin group on 401", func(t *testing.T) { check(t, e.do("GET", "/guard/audit", "", nil).w.Header(), false) })
	t.Run("HSTS option", func(t *testing.T) { check(t, e.do("GET", "/h/auth/me", "", nil).w.Header(), true) })
	t.Run("TLS request", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/auth/me", nil)
		req.TLS = &tls.ConnectionState{}
		w := httptest.NewRecorder()
		e.router.ServeHTTP(w, req)
		check(t, w.Header(), true)
	})
	t.Run("standalone without options", func(t *testing.T) {
		r := gin.New()
		r.GET("/x", ginguard.SecurityHeaders(), func(c *gin.Context) { c.Status(204) })
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest("GET", "/x", nil))
		check(t, w.Header(), false)
	})
}

func TestBodyLimit(t *testing.T) {
	e := newEnv(t, envConfig{})
	ginguard.Mount(e.router, e.g, ginguard.Options{AuthPath: "/s/auth", AdminPath: "/s/guard", MaxBodyBytes: 64, AuthRateLimit: ratelimit.Rule{Limit: -1}})
	big := `{"email":"admin@example.com","password":"` + strings.Repeat("x", 100) + `"}`
	t.Run("declared length", func(t *testing.T) {
		if r := e.raw("POST", "/s/auth/login", big, nil); r.code != 413 || r.errCode() != "body_too_large" {
			t.Fatalf("%d %v", r.code, r.body)
		}
	})
	t.Run("streamed body", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/s/auth/login", io.MultiReader(strings.NewReader(big)))
		req.ContentLength = -1
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		e.router.ServeHTTP(w, req)
		if w.Code != 413 || !strings.Contains(w.Body.String(), "body_too_large") {
			t.Fatalf("%d %s", w.Code, w.Body)
		}
	})
	t.Run("default is 1 MiB", func(t *testing.T) {
		huge := `{"email":"a@example.com","password":"` + strings.Repeat("x", 1<<20) + `"}`
		if r := e.raw("POST", "/auth/login", huge, nil); r.code != 413 {
			t.Fatalf("%d %v", r.code, r.body)
		}
		if r := e.raw("POST", "/auth/login", `{"email":"nobody@example.com","password":"`+strongPassword+`"}`, nil); r.code != 401 {
			t.Fatalf("small body: %d %v", r.code, r.body)
		}
	})
}

func TestLoginRevokesPreviousCookieSession(t *testing.T) {
	e := newEnv(t, envConfig{})
	loginWith := func(cookie string) resp {
		return e.raw("POST", "/auth/login", `{"email":"admin@example.com","password":"admin-password"}`, map[string]string{"Cookie": "guard_session=" + cookie})
	}
	t.Run("valid session cookie is revoked", func(t *testing.T) {
		old := e.login("admin@example.com", "admin-password")
		if r := loginWith(old); r.code != 200 || r.body["token"] == old {
			t.Fatalf("%d %v", r.code, r.body)
		}
		if r := e.do("GET", "/auth/me", old, nil); r.code != 401 {
			t.Fatalf("old session still valid: %d", r.code)
		}
	})
	t.Run("invalid cookie ignored", func(t *testing.T) {
		if r := loginWith("not-a-session"); r.code != 200 {
			t.Fatalf("%d %v", r.code, r.body)
		}
	})
	t.Run("api key cookie is not revoked", func(t *testing.T) {
		key := e.do("POST", "/auth/api-keys", e.admin, map[string]any{"name": "k", "scopes": []string{"*"}}).body["token"].(string)
		if r := loginWith(key); r.code != 200 {
			t.Fatalf("%d %v", r.code, r.body)
		}
		if r := e.raw("GET", "/auth/me", "", map[string]string{"X-API-Key": key}); r.code != 200 {
			t.Fatalf("api key revoked: %d", r.code)
		}
	})
	t.Run("revoke failure is logged, login still succeeds", func(t *testing.T) {
		var logged []error
		ginguard.Mount(e.router, e.g, ginguard.Options{AuthPath: "/l/auth", AdminPath: "/l/guard", AuthRateLimit: ratelimit.Rule{Limit: -1},
			ErrorLogger: func(_ *gin.Context, err error) { logged = append(logged, err) }})
		old := e.login("admin@example.com", "admin-password")
		e.f.set("Sessions.Delete", "*", errBoom)
		defer e.f.set("Sessions.Delete", "*", nil)
		r := e.raw("POST", "/l/auth/login", `{"email":"admin@example.com","password":"admin-password"}`, map[string]string{"Cookie": "guard_session=" + old})
		if r.code != 200 || len(logged) != 1 || !errors.Is(logged[0], errBoom) {
			t.Fatalf("%d %v logged=%v", r.code, r.body, logged)
		}
	})
}

func TestErrorLoggerReceivesInternalErrorsWithoutLeaking(t *testing.T) {
	e := newEnv(t, envConfig{})
	var logged []error
	ginguard.Mount(e.router, e.g, ginguard.Options{AuthPath: "/e/auth", AdminPath: "/e/guard", AuthRateLimit: ratelimit.Rule{Limit: -1},
		ErrorLogger: func(_ *gin.Context, err error) { logged = append(logged, err) }})
	e.f.set("Audit.List", "*", errBoom)
	r := e.do("GET", "/e/guard/audit", e.admin, nil)
	if r.code != 500 || strings.Contains(r.w.Body.String(), "boom") || len(logged) != 1 || !errors.Is(logged[0], errBoom) {
		t.Fatalf("%d %s logged=%v", r.code, r.w.Body, logged)
	}

	t.Run("ErrorLogging wraps standalone limiter", func(t *testing.T) {
		var got error
		g := e.g
		g.Limiter = limiterFunc(func(context.Context, string, ratelimit.Rule) (ratelimit.Result, error) {
			return ratelimit.Result{}, errBoom
		})
		defer func() { g.Limiter = nil }()
		e.router.GET("/logged-rl", ginguard.ErrorLogging(func(_ *gin.Context, err error) { got = err }),
			ginguard.RateLimit(g, "x", ratelimit.Rule{Limit: 1, Window: 1e9}, ginguard.ByIP), func(c *gin.Context) { c.Status(204) })
		if r := e.do("GET", "/logged-rl", "", nil); r.code != 204 || !errors.Is(got, errBoom) {
			t.Fatalf("%d %v", r.code, got)
		}
	})
}

func TestSuperAdminErrorsMapToStatus(t *testing.T) {
	e := newEnv(t, envConfig{})
	e.account("2", "user@example.com")
	for _, tc := range []struct {
		err  error
		code int
		want string
	}{
		{accessdomain.ErrForbidden, 403, "forbidden"},
		{accessdomain.ErrLastSuperAdmin, 409, "last_super_admin"},
		{accessdomain.ErrSuperAdminExpiry, 400, "invalid_expiry"},
	} {
		e.f.set("Roles.AssignRole", "2", tc.err)
		if r := e.do("POST", "/guard/users/2/roles", e.admin, map[string]any{"role": "user"}); r.code != tc.code || r.errCode() != tc.want {
			t.Fatalf("%v: %d %v", tc.err, r.code, r.body)
		}
	}
}
