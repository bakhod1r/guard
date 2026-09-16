package httpguard_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bakhod1r/guard"
	"github.com/bakhod1r/guard/httpguard"
	"github.com/bakhod1r/guard/ratelimit"
)

func status(code int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(code) })
}

func TestAuthenticateMiddlewareIsOptional(t *testing.T) {
	e := newEnv(t, envConfig{})
	whoami := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		out := map[string]any{"user": nil, "bucket": httpguard.ByPrincipal(r, httpguard.Options{})}
		if p := httpguard.PrincipalFrom(r); p != nil {
			out["user"] = string(p.User.ID)
		}
		_ = json.NewEncoder(w).Encode(out)
	})
	opts := httpguard.Options{}
	e.router.Handle("GET /optional", httpguard.Authenticate(e.g, opts)(whoami))
	// Authenticate twice, then RequireAuth: an attached principal is reused.
	e.router.Handle("GET /double", httpguard.Authenticate(e.g, opts)(
		httpguard.Authenticate(e.g, opts)(httpguard.RequireAuth(e.g, opts)(whoami))))

	k := e.do("POST", "/auth/api-keys", e.admin, map[string]any{"name": "ci", "scopes": []string{"*"}})
	key := k.body["token"].(string)
	keyID := k.body["api_key"].(map[string]any)["id"].(string)

	cases := []struct {
		name, path, token string
		wantUser          any
		wantBucket        string
	}{
		{"anonymous", "/optional", "", nil, "ip:192.0.2.1"},
		{"invalid token ignored", "/optional", "not-a-session", nil, "ip:192.0.2.1"},
		{"valid session", "/optional", e.admin, "1", "user:1"},
		{"valid api key", "/optional", key, "1", "key:" + keyID},
		{"principal reused", "/double", e.admin, "1", "user:1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := e.do("GET", tc.path, tc.token, nil)
			if r.code != 200 || r.body["user"] != tc.wantUser || r.body["bucket"] != tc.wantBucket {
				t.Fatalf("%d %v", r.code, r.body)
			}
		})
	}
}

func TestRequireResourceFuncAndPanics(t *testing.T) {
	e := newEnv(t, envConfig{})
	e.router.Handle("GET /broken", httpguard.Require(e.g, httpguard.Options{}, "invoice", "read",
		func(*http.Request, httpguard.Options) (guard.Resource, error) { return guard.Resource{}, errBoom })(status(200)))
	if r := e.do("GET", "/broken", e.admin, nil); r.code != 500 || r.errCode() != "internal" {
		t.Fatalf("resource func error: %d %v", r.code, r.body)
	}
	e.router.Handle("GET /anon", httpguard.Require(e.g, httpguard.Options{}, "invoice", "read", nil)(status(200)))
	if r := e.do("GET", "/anon", "", nil); r.code != 401 {
		t.Fatalf("require without credential: %d", r.code)
	}

	mustPanic := func(name string, fn func()) {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if v := recover(); v == nil || !strings.HasPrefix(v.(string), "httpguard: ") {
					t.Fatalf("want httpguard panic, got %v", v)
				}
			}()
			fn()
		})
	}
	mustPanic("RequirePermission bad code", func() { httpguard.RequirePermission(e.g, httpguard.Options{}, "nodot") })
	mustPanic("RateLimit invalid rule", func() {
		httpguard.RateLimit(e.g, httpguard.Options{}, "x", ratelimit.Rule{}, httpguard.ByIP)
	})
}

func TestRateLimitFailsOpen(t *testing.T) {
	rule := ratelimit.Rule{Limit: 1, Window: time.Minute}

	t.Run("nil limiter", func(t *testing.T) {
		e := newEnv(t, envConfig{})
		e.router.Handle("GET /rl", httpguard.RateLimit(e.g, httpguard.Options{}, "rl", rule, httpguard.ByIP)(status(200)))
		for i := 0; i < 3; i++ {
			if r := e.do("GET", "/rl", "", nil); r.code != 200 || r.w.Header().Get("X-RateLimit-Limit") != "" {
				t.Fatalf("attempt %d: %d %v", i, r.code, r.w.Header())
			}
		}
	})
	t.Run("limiter error", func(t *testing.T) {
		var keys []string
		e := newEnv(t, envConfig{limiter: limiterFunc(func(_ context.Context, key string, _ ratelimit.Rule) (ratelimit.Result, error) {
			keys = append(keys, key)
			return ratelimit.Result{}, errBoom
		})})
		var seen error
		e.router.Handle("GET /rl2", httpguard.ErrorLogging(func(_ *http.Request, err error) { seen = err })(
			httpguard.RateLimit(e.g, httpguard.Options{}, "rl2", rule, httpguard.ByPrincipal)(status(200))))
		if r := e.do("GET", "/rl2", "", nil); r.code != 200 || !errors.Is(seen, errBoom) {
			t.Fatalf("fail-open: %d err=%v", r.code, seen)
		}
		if len(keys) != 1 || keys[0] != "rl2:ip:192.0.2.1" {
			t.Fatalf("bucket key: %v", keys)
		}
	})
	t.Run("limiter error without ErrorLogging falls back to the default logger", func(t *testing.T) {
		e := newEnv(t, envConfig{limiter: limiterFunc(func(context.Context, string, ratelimit.Rule) (ratelimit.Result, error) {
			return ratelimit.Result{}, errBoom
		})})
		e.router.Handle("GET /rl3", httpguard.RateLimit(e.g, httpguard.Options{}, "rl3", rule, httpguard.ByIP)(status(204)))
		if r := e.do("GET", "/rl3", "", nil); r.code != 204 {
			t.Fatalf("fail-open: %d", r.code)
		}
	})
}

// TestProtectRoutesAndSyncRoutes covers the route-registry helpers: skipped
// prefixes pass through untouched, and SyncRoutes reports the unsupported
// backend rather than pretending to have synced.
func TestProtectRoutesAndSyncRoutes(t *testing.T) {
	e := newEnv(t, envConfig{})
	o := httpguard.SyncOptions{Prefix: "/api", SkipPrefixes: []string{"/api/public"}}
	host := http.NewServeMux()
	host.Handle("GET /api/reports/{id}", status(200))
	host.Handle("GET /api/public/ping", status(200))
	e.router.Handle("/api/", httpguard.ProtectMuxRoutes(e.g, httpguard.Options{}, o, host))

	if r := e.do("GET", "/api/public/ping", "", nil); r.code != 200 {
		t.Fatalf("skipped prefix should not require auth: %d %v", r.code, r.body)
	}
	if r := e.do("GET", "/api/reports/1", "", nil); r.code != 401 {
		t.Fatalf("protected route without credential: %d", r.code)
	}
	if r := e.do("GET", "/api/reports/1", e.admin, nil); r.code != 200 {
		t.Fatalf("admin: %d %v", r.code, r.body)
	}
	// No route matches inside the host mux: nothing to derive a permission from,
	// so the request is passed through and the host answers 404.
	if r := e.do("GET", "/api/unknown", e.admin, nil); r.code != 404 {
		t.Fatalf("unknown route: %d %v", r.code, r.body)
	}

	// SkipPrefixes also keeps the skipped route out of the sync.
	routes := httpguard.Routes("GET /api/reports/{id}", "GET /api/public/ping")
	res, err := httpguard.SyncRoutes(context.Background(), e.g, routes, o)
	if err != nil {
		t.Fatalf("SyncRoutes: %v", err)
	}
	if len(res.Permissions) != 1 || res.Permissions[0].Code() != "reports.read" {
		t.Fatalf("synced permissions: %+v", res.Permissions)
	}
}

func TestProtectRejectsRoutesWithoutDerivablePermission(t *testing.T) {
	e := newEnv(t, envConfig{})
	host := http.NewServeMux()
	host.Handle("GET /api", status(200))
	e.router.Handle("/api", httpguard.ProtectMux(e.g, httpguard.Options{}, "/api", host))
	if r := e.do("GET", "/api", e.admin, nil); r.code != 403 || r.errCode() != "forbidden" {
		t.Fatalf("underivable route: %d %v", r.code, r.body)
	}
}

func TestProtectAuthorizeFailureIsInternal(t *testing.T) {
	e := newEnv(t, envConfig{})
	host := http.NewServeMux()
	host.Handle("GET /api/invoices/{id}", status(200))
	e.router.Handle("/api/", httpguard.ProtectMux(e.g, httpguard.Options{}, "/api", host))
	e.f.set("Policies.ApplicablePolicies", "invoices", errBoom)
	if r := e.do("GET", "/api/invoices/7", e.admin, nil); r.code != 500 || r.errCode() != "internal" {
		t.Fatalf("authorize failure: %d %v", r.code, r.body)
	}
}

func TestCollectorHandleFuncRecordsPattern(t *testing.T) {
	mux := http.NewServeMux()
	c := httpguard.NewCollector(mux)
	c.HandleFunc("POST /api/things", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) })
	got := c.Routes()
	if len(got) != 1 || got[0] != (httpguard.Route{Method: "POST", Path: "/api/things"}) {
		t.Fatalf("routes: %v", got)
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("POST", "/api/things", nil))
	if w.Code != 204 {
		t.Fatalf("handler not registered: %d", w.Code)
	}
}

func TestAutoseedSkipsExcludedPrefixesAndUnknownSuperRole(t *testing.T) {
	e := newEnv(t, envConfig{})
	ctx := context.Background()
	routes := httpguard.Routes("GET /api/reports/{id}", "GET /api/auth/me")
	seed, err := httpguard.Autoseed(ctx, e.g, routes, httpguard.AutoseedOptions{
		Prefix: "/api", Exclude: []string{"/api/auth"}, SuperRole: "-"})
	if err != nil {
		t.Fatalf("autoseed: %v", err)
	}
	if len(seed.Permissions) != 1 || seed.Permissions[0].Code() != "reports.read" {
		t.Fatalf("permissions: %+v", seed.Permissions)
	}
}

func TestParamReadsPathValue(t *testing.T) {
	mux := http.NewServeMux()
	var got string
	mux.HandleFunc("GET /things/{id}", func(_ http.ResponseWriter, r *http.Request) {
		got = httpguard.Param(r, httpguard.Options{}, "id")
	})
	mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/things/42", nil))
	if got != "42" {
		t.Fatalf("Param = %q", got)
	}
}

func TestClientIPSources(t *testing.T) {
	e := newEnv(t, envConfig{})
	var seen []string
	record := func(o httpguard.Options) http.Handler {
		return httpguard.Authenticate(e.g, o)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			seen = append(seen, httpguard.ByIP(r, o))
		}))
	}
	e.router.Handle("GET /ip/default", record(httpguard.Options{}))
	e.router.Handle("GET /ip/forwarded", record(httpguard.Options{TrustForwardedFor: true}))
	e.router.Handle("GET /ip/custom", record(httpguard.Options{ClientIP: func(*http.Request) string { return "9.9.9.9" }}))

	e.raw("GET", "/ip/default", "", map[string]string{"X-Forwarded-For": "203.0.113.7, 10.0.0.1"})
	e.raw("GET", "/ip/forwarded", "", map[string]string{"X-Forwarded-For": "203.0.113.7, 10.0.0.1"})
	e.raw("GET", "/ip/forwarded", "", nil)
	e.raw("GET", "/ip/custom", "", nil)

	want := []string{"ip:192.0.2.1", "ip:203.0.113.7", "ip:192.0.2.1", "ip:9.9.9.9"}
	for i, w := range want {
		if seen[i] != w {
			t.Fatalf("call %d: got %q want %q (all: %v)", i, seen[i], w, seen)
		}
	}

	t.Run("RemoteAddr without a port", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/ip/default", nil)
		req.RemoteAddr = "unix-socket"
		w := httptest.NewRecorder()
		e.router.ServeHTTP(w, req)
		if seen[len(seen)-1] != "ip:unix-socket" {
			t.Fatalf("got %q", seen[len(seen)-1])
		}
	})
}

func TestEnvironmentExposesMatchedRoute(t *testing.T) {
	e := newEnv(t, envConfig{})
	var env map[string]any
	e.router.Handle("GET /env/{id}", http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		env = httpguard.Environment(r, httpguard.Options{})
	}))
	e.do("GET", "/env/7", "", nil)
	if env["path"] != "/env/{id}" || env["method"] != "GET" || env["ip"] != "192.0.2.1" {
		t.Fatalf("environment: %v", env)
	}

	t.Run("no matched route", func(t *testing.T) {
		var out map[string]any
		h := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			out = httpguard.Environment(r, httpguard.Options{})
		})
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/loose", nil))
		if out["path"] != "" {
			t.Fatalf("want empty path, got %v", out["path"])
		}
	})

	t.Run("host-qualified pattern", func(t *testing.T) {
		var out map[string]any
		mux := http.NewServeMux()
		mux.HandleFunc("GET example.com/hosted/{id}", func(_ http.ResponseWriter, r *http.Request) {
			out = httpguard.Environment(r, httpguard.Options{})
		})
		req := httptest.NewRequest("GET", "http://example.com/hosted/3", nil)
		mux.ServeHTTP(httptest.NewRecorder(), req)
		if out["path"] != "/hosted/{id}" {
			t.Fatalf("host-qualified pattern: %v", out["path"])
		}
	})
}

// TestMountOnPrefixedRouter covers Mount's pattern joining, including a group
// prefix given without a leading slash and a trailing slash.
func TestMountOnPrefixedRouter(t *testing.T) {
	e := newEnv(t, envConfig{})
	httpguard.Mount(e.router, e.g, httpguard.Options{
		AuthPath: "/v2/auth/", AdminPath: "/v2/guard/", AuthRateLimit: ratelimit.Rule{Limit: -1}, InsecureCookie: true})
	if r := e.do("GET", "/v2/auth/me", e.admin, nil); r.code != 200 {
		t.Fatalf("me under /v2: %d %v", r.code, r.body)
	}
	if r := e.do("GET", "/v2/guard/roles", e.admin, nil); r.code != 200 {
		t.Fatalf("roles under /v2: %d %v", r.code, r.body)
	}
}

// TestBodyLimitOnAdminRoutes checks the streamed-body path of the routes that
// decode after a permission check.
func TestBodyLimitOnAdminRoutes(t *testing.T) {
	e := newEnv(t, envConfig{})
	e.account("2", "user@example.com")
	httpguard.Mount(e.router, e.g, httpguard.Options{AuthPath: "/b/auth", AdminPath: "/b/guard",
		MaxBodyBytes: 32, AuthRateLimit: ratelimit.Rule{Limit: -1}, InsecureCookie: true})
	big := `{"password":"` + strings.Repeat("x", 100) + `"}`
	for _, tc := range []struct{ method, path, body string }{
		{"POST", "/b/guard/users/2/account", `{"email":"a@b.co","password":"` + strings.Repeat("x", 100) + `"}`},
		{"PUT", "/b/guard/users/2/password", big},
		{"PUT", "/b/guard/users/2/attributes", `{"attributes":{"x":"` + strings.Repeat("y", 100) + `"}}`},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			req.ContentLength = -1
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+e.admin)
			w := httptest.NewRecorder()
			e.router.ServeHTTP(w, req)
			if w.Code != http.StatusRequestEntityTooLarge || !strings.Contains(w.Body.String(), "body_too_large") {
				t.Fatalf("%d %s", w.Code, w.Body)
			}
		})
	}
}

// TestWriteJSONEncodeFailureIsLogged: the response is already committed when
// encoding fails, so the error only reaches the logger.
func TestWriteJSONEncodeFailureIsLogged(t *testing.T) {
	e := newEnv(t, envConfig{})
	var logged []error
	httpguard.Mount(e.router, e.g, httpguard.Options{AuthPath: "/j/auth", AdminPath: "/j/guard",
		AuthRateLimit: ratelimit.Rule{Limit: -1}, InsecureCookie: true,
		ErrorLogger: func(_ *http.Request, err error) { logged = append(logged, err) }})
	// An attribute value that cannot be marshalled (a channel) is stored raw by
	// the memory repository and blows up when the user is serialised.
	e.account("2", "encode@example.com")
	if err := e.g.SetAttributes(context.Background(), "1", "2", map[string]any{"bad": make(chan int)}); err != nil {
		t.Fatalf("set attributes: %v", err)
	}
	r := e.do("GET", "/j/guard/users/2", e.admin, nil)
	if r.code != 200 || len(logged) == 0 {
		t.Fatalf("want a logged encode failure, got %d %v", r.code, logged)
	}
	var marshalErr *json.UnsupportedTypeError
	if !errors.As(logged[0], &marshalErr) {
		t.Fatalf("logged: %v", logged[0])
	}
}

// TestProtectOnASingleRoute covers the per-route form: the mux has already
// matched, so the pattern is on the request.
func TestProtectOnASingleRoute(t *testing.T) {
	e := newEnv(t, envConfig{})
	e.router.Handle("GET /api/reports/{id}", httpguard.Protect(e.g, httpguard.Options{}, "/api")(status(200)))
	e.router.Handle("GET /api/drafts/{id}", httpguard.ProtectRoutes(e.g, httpguard.Options{},
		httpguard.SyncOptions{Prefix: "/api", Overrides: map[string]string{"GET /api/drafts/{id}": "reports.read"}})(status(200)))

	if r := e.do("GET", "/api/reports/1", "", nil); r.code != 401 {
		t.Fatalf("without credential: %d", r.code)
	}
	if r := e.do("GET", "/api/reports/1", e.admin, nil); r.code != 200 {
		t.Fatalf("admin: %d %v", r.code, r.body)
	}
	if r := e.do("GET", "/api/drafts/1", e.admin, nil); r.code != 200 {
		t.Fatalf("override: %d %v", r.code, r.body)
	}
}

func TestAutoseedDefaultSuperRoleIsAdmin(t *testing.T) {
	e := newEnv(t, envConfig{})
	ctx := context.Background()
	if _, err := httpguard.Autoseed(ctx, e.g, httpguard.Routes("GET /api/ledgers/{id}"), httpguard.AutoseedOptions{Prefix: "/api"}); err != nil {
		t.Fatalf("autoseed: %v", err)
	}
	role, err := e.g.Access.Role(ctx, "admin")
	if err != nil {
		t.Fatalf("role: %v", err)
	}
	for _, p := range role.Permissions {
		if p.Code() == "ledgers.read" {
			return
		}
	}
	// A wildcard role holds every permission implicitly; the seed must still run.
	if !role.Wildcard {
		t.Fatalf("admin did not receive ledgers.read: %+v", role.Permissions)
	}
}

func TestOptionDefaultsAndPatternEdges(t *testing.T) {
	e := newEnv(t, envConfig{})
	t.Run("LimitBody falls back to the default cap", func(t *testing.T) {
		h := httpguard.LimitBody(0)(status(204))
		req := httptest.NewRequest("POST", "/x", strings.NewReader(strings.Repeat("x", 10)))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != 204 {
			t.Fatalf("small body under the default cap: %d", w.Code)
		}
		req = httptest.NewRequest("POST", "/x", strings.NewReader(strings.Repeat("x", int(httpguard.DefaultMaxBodyBytes)+1)))
		w = httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("oversized body: %d", w.Code)
		}
	})
	t.Run("204 responses carry no body", func(t *testing.T) {
		r := e.do("POST", "/auth/logout", e.admin, nil)
		if r.code != 204 || r.w.Body.Len() != 0 {
			t.Fatalf("%d %q", r.code, r.w.Body.String())
		}
	})
	t.Run("route pattern without a path", func(t *testing.T) {
		var out map[string]any
		mux := http.NewServeMux()
		// A host-only pattern has no path to report.
		mux.HandleFunc("example.com/", func(_ http.ResponseWriter, r *http.Request) {
			r.Pattern = "GET example.com"
			out = httpguard.Environment(r, httpguard.Options{})
		})
		mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "http://example.com/x", nil))
		if out["path"] != "" {
			t.Fatalf("path: %v", out["path"])
		}
	})
}

// TestMountJoinsGroupPrefix checks the patterns handed to a custom Router.
func TestMountJoinsGroupPrefix(t *testing.T) {
	rec := &patternRecorder{}
	httpguard.Mount(rec, newEnv(t, envConfig{}).g, httpguard.Options{AuthPath: "/a", AdminPath: "/g", AuthRateLimit: ratelimit.Rule{Limit: -1}})
	if len(rec.patterns) == 0 || !strings.HasPrefix(rec.patterns[0], "POST /a/") {
		t.Fatalf("patterns: %v", rec.patterns)
	}
}

type patternRecorder struct{ patterns []string }

func (p *patternRecorder) Handle(pattern string, _ http.Handler) {
	p.patterns = append(p.patterns, pattern)
}

// TestAdminAccountRoutesSucceed covers the success paths of the admin routes
// that create or replace credentials.
func TestAdminAccountRoutesSucceed(t *testing.T) {
	e := newEnv(t, envConfig{})
	if r := e.do("POST", "/guard/users/7/account", e.admin,
		map[string]any{"email": "linked@example.com", "password": password}); r.code != 201 || r.body["id"] != "7" {
		t.Fatalf("create account: %d %v", r.code, r.body)
	}
	if r := e.do("PUT", "/guard/users/7/password", e.admin, map[string]any{"password": "n3w-" + password}); r.code != 204 {
		t.Fatalf("reset password: %d %v", r.code, r.body)
	}
	if r := e.do("PUT", "/guard/users/7/attributes", e.admin,
		map[string]any{"attributes": map[string]any{"department": "finance"}}); r.code != 204 {
		t.Fatalf("set attributes: %d %v", r.code, r.body)
	}
	r := e.do("GET", "/guard/users/7", e.admin, nil)
	if attrs, _ := r.body["attributes"].(map[string]any); r.code != 200 || attrs["department"] != "finance" {
		t.Fatalf("read back: %d %v", r.code, r.body)
	}
	if r := e.do("POST", "/auth/login", "", map[string]any{"email": "linked@example.com", "password": "n3w-" + password}); r.code != 200 {
		t.Fatalf("login with the reset password: %d %v", r.code, r.body)
	}
}
