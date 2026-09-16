package httpguard_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/bakhod1r/guard"
	"github.com/bakhod1r/guard/guardtest"
	"github.com/bakhod1r/guard/httpguard"
	"github.com/bakhod1r/guard/ratelimit"
)

const password = "tr0ub4dor-guard-42"

// hostUsers simulates the host application's user table (bigint-like ids).
func hostUsers() func(context.Context, string) (string, error) {
	var mu sync.Mutex
	next := 100
	return func(context.Context, string) (string, error) {
		mu.Lock()
		defer mu.Unlock()
		next++
		return strconv.Itoa(next), nil
	}
}

type client struct {
	t      *testing.T
	router http.Handler
}

func (c client) do(method, path, token string, body any) (int, map[string]any) {
	c.t.Helper()
	return c.send(c.request(method, path, token, body))
}

func (c client) request(method, path, token string, body any) *http.Request {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req
}

func (c client) send(req *http.Request) (int, map[string]any) {
	c.t.Helper()
	w := httptest.NewRecorder()
	c.router.ServeHTTP(w, req)
	out := map[string]any{}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func options() httpguard.Options {
	return httpguard.Options{
		AuthPath: "/api/auth", AdminPath: "/api/guard",
		AuthRateLimit: ratelimit.Rule{Limit: -1}, CreateUser: hostUsers(),
	}
}

func setup(t *testing.T) (client, *guard.Guard, *http.ServeMux) {
	t.Helper()
	mr := miniredis.RunT(t)
	g := guardtest.New(redis.NewClient(&redis.Options{Addr: mr.Addr()}), guard.Config{})
	mux := http.NewServeMux()
	httpguard.Mount(mux, g, options())
	mux.Handle("GET /api/invoices/{id}", httpguard.RequirePermission(g, httpguard.Options{}, "invoice.read")(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{"id": r.PathValue("id")})
		})))
	return client{t: t, router: mux}, g, mux
}

func register(t *testing.T, c client, email string) (token, id string) {
	t.Helper()
	code, body := c.do("POST", "/api/auth/register", "", map[string]any{"email": email, "password": password})
	if code != http.StatusCreated {
		t.Fatalf("register %s: %d %v", email, code, body)
	}
	id, _ = body["id"].(string)
	return login(t, c, email), id
}

func login(t *testing.T, c client, email string) string {
	t.Helper()
	code, body := c.do("POST", "/api/auth/login", "", map[string]any{"email": email, "password": password})
	if code != http.StatusOK {
		t.Fatalf("login %s: %d %v", email, code, body)
	}
	tok, _ := body["token"].(string)
	if tok == "" {
		t.Fatalf("login %s: empty token", email)
	}
	return tok
}

// admin provisions the seeded wildcard admin account and logs it in.
func admin(t *testing.T, c client, g *guard.Guard, email string) (token, id string) {
	t.Helper()
	u, err := g.EnsureAdmin(context.Background(), "1", email, "admin-"+password)
	if err != nil {
		t.Fatalf("ensure admin: %v", err)
	}
	code, body := c.do("POST", "/api/auth/login", "", map[string]any{"email": email, "password": "admin-" + password})
	if code != http.StatusOK {
		t.Fatalf("admin login: %d %v", code, body)
	}
	return body["token"].(string), string(u.ID)
}

func TestRegisterLoginMe(t *testing.T) {
	c, _, _ := setup(t)
	token, id := register(t, c, "alice@example.com")

	code, body := c.do("GET", "/api/auth/me", token, nil)
	if code != http.StatusOK {
		t.Fatalf("me: %d %v", code, body)
	}
	user := body["user"].(map[string]any)
	if user["id"] != id || user["email"] != "alice@example.com" {
		t.Fatalf("me returned %v", user)
	}
}

func TestLoginSetsSessionCookie(t *testing.T) {
	c, _, _ := setup(t)
	register(t, c, "cookie@example.com")

	req := c.request("POST", "/api/auth/login", "", map[string]any{"email": "cookie@example.com", "password": password})
	w := httptest.NewRecorder()
	c.router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("login: %d %s", w.Code, w.Body)
	}
	var ck *http.Cookie
	for _, got := range w.Result().Cookies() {
		if got.Name == "guard_session" {
			ck = got
		}
	}
	if ck == nil {
		t.Fatal("no guard_session cookie")
	}
	if !ck.HttpOnly || !ck.Secure || ck.SameSite != http.SameSiteStrictMode {
		t.Fatalf("cookie flags: httpOnly=%v secure=%v samesite=%v", ck.HttpOnly, ck.Secure, ck.SameSite)
	}
}

func TestCookieAuthNeedsCSRFOnUnsafeMethods(t *testing.T) {
	c, _, _ := setup(t)
	register(t, c, "csrf@example.com")
	req := c.request("POST", "/api/auth/login", "", map[string]any{"email": "csrf@example.com", "password": password})
	w := httptest.NewRecorder()
	c.router.ServeHTTP(w, req)
	cookie := w.Result().Cookies()[0]

	// Cookie-authenticated POST with no Origin is rejected.
	req = c.request("POST", "/api/auth/logout", "", nil)
	req.AddCookie(cookie)
	if code, body := c.send(req); code != http.StatusForbidden {
		t.Fatalf("logout without origin: %d %v", code, body)
	}
	// Same request with the opt-out header succeeds.
	req = c.request("POST", "/api/auth/logout", "", nil)
	req.AddCookie(cookie)
	req.Header.Set(httpguard.CSRFHeader, "1")
	if code, body := c.send(req); code != http.StatusNoContent {
		t.Fatalf("logout with csrf header: %d %v", code, body)
	}
	// GET is safe and needs no header.
	req = c.request("GET", "/api/auth/me", "", nil)
	req.AddCookie(cookie)
	if code, _ := c.send(req); code != http.StatusUnauthorized {
		t.Fatalf("me after logout: %d", code)
	}
}

func TestRequirePermissionDeniesThenAllows(t *testing.T) {
	c, g, _ := setup(t)
	token, id := register(t, c, "bob@example.com")

	if code, _ := c.do("GET", "/api/invoices/7", token, nil); code != http.StatusForbidden {
		t.Fatalf("invoice without permission: %d", code)
	}
	if code, _ := c.do("GET", "/api/invoices/7", "", nil); code != http.StatusUnauthorized {
		t.Fatalf("invoice without token: %d", code)
	}

	ctx := context.Background()
	if _, err := g.Access.CreatePermission(ctx, "invoice.read", ""); err != nil {
		t.Fatalf("create permission: %v", err)
	}
	if _, err := g.Access.CreateRoleAs(ctx, "test", "accountant", "Accountant", "", false); err != nil {
		t.Fatalf("create role: %v", err)
	}
	if err := g.Access.GrantPermission(ctx, "accountant", "invoice.read", "test"); err != nil {
		t.Fatalf("grant: %v", err)
	}
	if err := g.Access.AssignRole(ctx, id, "accountant", "test", nil); err != nil {
		t.Fatalf("assign: %v", err)
	}
	code, body := c.do("GET", "/api/invoices/7", token, nil)
	if code != http.StatusOK || body["id"] != "7" {
		t.Fatalf("invoice with permission: %d %v", code, body)
	}
}

func TestSelfServicePolicyAllowsOwnUser(t *testing.T) {
	c, _, _ := setup(t)
	token, id := register(t, c, "self@example.com")
	other, otherID := register(t, c, "other@example.com")

	if code, body := c.do("GET", "/api/guard/users/"+id, token, nil); code != http.StatusOK {
		t.Fatalf("own user: %d %v", code, body)
	}
	if code, _ := c.do("GET", "/api/guard/users/"+otherID, token, nil); code != http.StatusForbidden {
		t.Fatalf("other user: %d", code)
	}
	if code, _ := c.do("GET", "/api/guard/users/"+id, other, nil); code != http.StatusForbidden {
		t.Fatalf("other user reversed: %d", code)
	}
}

func TestAdminRBACRoutes(t *testing.T) {
	c, g, _ := setup(t)
	root, _ := admin(t, c, g, "root@example.com")
	_, userID := register(t, c, "member@example.com")

	if code, body := c.do("POST", "/api/guard/roles", root, map[string]any{"name": "editor", "title": "Editor"}); code != http.StatusCreated {
		t.Fatalf("create role: %d %v", code, body)
	}
	if code, body := c.do("POST", "/api/guard/permissions", root, map[string]any{"code": "article.write"}); code != http.StatusCreated {
		t.Fatalf("create permission: %d %v", code, body)
	}
	if code, body := c.do("POST", "/api/guard/roles/editor/permissions", root, map[string]any{"code": "article.write"}); code != http.StatusNoContent {
		t.Fatalf("grant: %d %v", code, body)
	}
	if code, body := c.do("POST", "/api/guard/users/"+userID+"/roles", root, map[string]any{"role": "editor"}); code != http.StatusNoContent {
		t.Fatalf("assign: %d %v", code, body)
	}
	code, body := c.do("GET", "/api/guard/users/"+userID+"/roles", root, nil)
	if code != http.StatusOK {
		t.Fatalf("grants: %d %v", code, body)
	}
	if !strings.Contains(jsonString(body), "editor") {
		t.Fatalf("grants missing editor: %v", body)
	}
	if code, _ := c.do("DELETE", "/api/guard/users/"+userID+"/roles/editor", root, nil); code != http.StatusNoContent {
		t.Fatalf("unassign: %d", code)
	}
	if code, _ := c.do("DELETE", "/api/guard/roles/editor/permissions/article.write", root, nil); code != http.StatusNoContent {
		t.Fatalf("revoke permission: %d", code)
	}
	if code, _ := c.do("DELETE", "/api/guard/roles/editor", root, nil); code != http.StatusNoContent {
		t.Fatalf("delete role: %d", code)
	}
}

func TestAdminPolicyCRUDAndAudit(t *testing.T) {
	c, g, _ := setup(t)
	root, _ := admin(t, c, g, "policyadmin@example.com")

	policy := map[string]any{
		"name": "night shift", "resource": "invoice", "action": "read", "effect": "allow",
		"priority": 50, "enabled": true,
		"root": map[string]any{"operator": "and", "conditions": []map[string]any{
			{"field": "user.attributes.team", "operator": "eq", "value": []string{"night"}}}},
	}
	code, body := c.do("POST", "/api/guard/policies", root, policy)
	if code != http.StatusCreated {
		t.Fatalf("create policy: %d %v", code, body)
	}
	id, _ := body["id"].(string)
	if id == "" {
		t.Fatalf("policy has no id: %v", body)
	}
	if code, _ := c.do("GET", "/api/guard/policies/"+id, root, nil); code != http.StatusOK {
		t.Fatalf("get policy: %d", code)
	}
	policy["name"] = "night shift v2"
	if code, body := c.do("PUT", "/api/guard/policies/"+id, root, policy); code != http.StatusOK {
		t.Fatalf("update policy: %d %v", code, body)
	}
	if code, _ := c.do("DELETE", "/api/guard/policies/"+id, root, nil); code != http.StatusNoContent {
		t.Fatalf("delete policy: %d", code)
	}
	code, body = c.do("GET", "/api/guard/audit", root, nil)
	if code != http.StatusOK {
		t.Fatalf("audit: %d %v", code, body)
	}
	if !strings.Contains(jsonString(body), "policy.create") {
		t.Fatalf("audit missing policy.create: %v", body)
	}
}

func TestAPIKeyLifecycle(t *testing.T) {
	c, _, _ := setup(t)
	token, _ := register(t, c, "keys@example.com")

	code, body := c.do("POST", "/api/auth/api-keys", token, map[string]any{"name": "ci", "scopes": []string{"invoice.read"}})
	if code != http.StatusCreated {
		t.Fatalf("issue key: %d %v", code, body)
	}
	key, _ := body["token"].(string)
	if key == "" {
		t.Fatalf("no key token: %v", body)
	}
	// The key authenticates /me...
	req := c.request("GET", "/api/auth/me", "", nil)
	req.Header.Set("X-API-Key", key)
	if code, body := c.send(req); code != http.StatusOK {
		t.Fatalf("me with key: %d %v", code, body)
	}
	// ...but not account-level routes.
	req = c.request("GET", "/api/auth/api-keys", "", nil)
	req.Header.Set("X-API-Key", key)
	if code, _ := c.send(req); code != http.StatusForbidden {
		t.Fatalf("keys cannot list keys: %d", code)
	}

	code, body = c.do("GET", "/api/auth/api-keys", token, nil)
	if code != http.StatusOK {
		t.Fatalf("list keys: %d %v", code, body)
	}
	list := body["api_keys"].([]any)
	keyID := list[0].(map[string]any)["id"].(string)
	if code, _ := c.do("DELETE", "/api/auth/api-keys/"+keyID, token, nil); code != http.StatusNoContent {
		t.Fatalf("revoke key: %d", code)
	}
	req = c.request("GET", "/api/auth/me", "", nil)
	req.Header.Set("X-API-Key", key)
	if code, _ := c.send(req); code != http.StatusUnauthorized {
		t.Fatalf("revoked key still works: %d", code)
	}
}

func TestSessionsListAndRevoke(t *testing.T) {
	c, _, _ := setup(t)
	// register logs in once; two more logins make three sessions.
	first, _ := register(t, c, "sessions@example.com")
	login(t, c, "sessions@example.com")
	second := login(t, c, "sessions@example.com")

	code, body := c.do("GET", "/api/auth/sessions", second, nil)
	if code != http.StatusOK {
		t.Fatalf("sessions: %d %v", code, body)
	}
	list := body["sessions"].([]any)
	if len(list) != 3 {
		t.Fatalf("want 3 sessions, got %d", len(list))
	}
	current := 0
	for _, item := range list {
		if item.(map[string]any)["current"] == true {
			current++
		}
	}
	if current != 1 {
		t.Fatalf("want exactly one current session, got %d", current)
	}
	// Revoke the session behind the first token and check it stops working.
	otherID := sessionIDOf(t, c, first)
	if code, _ := c.do("DELETE", "/api/auth/sessions/"+otherID, second, nil); code != http.StatusNoContent {
		t.Fatalf("revoke session: %d", code)
	}
	if code, _ := c.do("GET", "/api/auth/me", first, nil); code != http.StatusUnauthorized {
		t.Fatalf("revoked session still valid: %d", code)
	}
	if code, _ := c.do("POST", "/api/auth/logout-all", second, nil); code != http.StatusNoContent {
		t.Fatalf("logout-all: %d", code)
	}
	if code, _ := c.do("GET", "/api/auth/me", second, nil); code != http.StatusUnauthorized {
		t.Fatalf("session survived logout-all: %d", code)
	}
}

func TestChangePasswordKeepsCurrentSessionOnly(t *testing.T) {
	c, _, _ := setup(t)
	old, _ := register(t, c, "pw@example.com")
	current := login(t, c, "pw@example.com")

	code, body := c.do("PUT", "/api/auth/password", current,
		map[string]any{"old_password": password, "new_password": "n3w-" + password})
	if code != http.StatusNoContent {
		t.Fatalf("change password: %d %v", code, body)
	}
	if code, _ := c.do("GET", "/api/auth/me", current, nil); code != http.StatusOK {
		t.Fatalf("current session lost: %d", code)
	}
	if code, _ := c.do("GET", "/api/auth/me", old, nil); code != http.StatusUnauthorized {
		t.Fatalf("other session survived: %d", code)
	}
}

func TestAuthorizeEndpoint(t *testing.T) {
	c, _, _ := setup(t)
	token, id := register(t, c, "authz@example.com")

	code, body := c.do("POST", "/api/auth/authorize", token,
		map[string]any{"action": "read", "resource": map[string]any{"type": "user", "id": id}})
	if code != http.StatusOK {
		t.Fatalf("authorize: %d %v", code, body)
	}
	if body["allowed"] != true {
		t.Fatalf("self read should be allowed: %v", body)
	}
	if code, _ := c.do("POST", "/api/auth/authorize", token, map[string]any{"resource": map[string]any{"type": "user"}}); code != http.StatusBadRequest {
		t.Fatalf("missing action: %d", code)
	}
}

func TestValidationAndBodyLimits(t *testing.T) {
	c, _, _ := setup(t)

	if code, body := c.do("POST", "/api/auth/login", "", map[string]any{"email": "x@example.com"}); code != http.StatusBadRequest {
		t.Fatalf("missing password: %d %v", code, body)
	}
	if code, _ := c.do("POST", "/api/auth/login", "", "not-an-object"); code != http.StatusBadRequest {
		t.Fatalf("bad json: %d", code)
	}
	big := map[string]any{"email": "x@example.com", "password": strings.Repeat("p", int(httpguard.DefaultMaxBodyBytes)+1)}
	if code, body := c.do("POST", "/api/auth/login", "", big); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body: %d %v", code, body)
	}
}

func TestRateLimitBlocksAfterLimit(t *testing.T) {
	mr := miniredis.RunT(t)
	g := guardtest.New(redis.NewClient(&redis.Options{Addr: mr.Addr()}), guard.Config{})
	mux := http.NewServeMux()
	o := httpguard.Options{AuthPath: "/api/auth", AdminPath: "/api/guard",
		AuthRateLimit: ratelimit.Rule{Limit: 2, Window: time.Minute}, CreateUser: hostUsers()}
	httpguard.Mount(mux, g, o)
	c := client{t: t, router: mux}

	var last int
	for i := 0; i < 3; i++ {
		last, _ = c.do("POST", "/api/auth/login", "", map[string]any{"email": "rl@example.com", "password": password})
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("third login: %d, want 429", last)
	}
	req := c.request("POST", "/api/auth/login", "", map[string]any{"email": "rl@example.com", "password": password})
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Header().Get("X-RateLimit-Limit") != "2" || w.Header().Get("Retry-After") == "" {
		t.Fatalf("rate limit headers: %v", w.Header())
	}
}

func TestRegisterNotMountedWithoutCreateUser(t *testing.T) {
	mr := miniredis.RunT(t)
	g := guardtest.New(redis.NewClient(&redis.Options{Addr: mr.Addr()}), guard.Config{})
	mux := http.NewServeMux()
	httpguard.Mount(mux, g, httpguard.Options{AuthPath: "/api/auth", AdminPath: "/api/guard", AuthRateLimit: ratelimit.Rule{Limit: -1}})
	c := client{t: t, router: mux}
	if code, _ := c.do("POST", "/api/auth/register", "", map[string]any{"email": "a@b.c", "password": password}); code != http.StatusNotFound {
		t.Fatalf("register mounted without CreateUser: %d", code)
	}
}

func TestLoginErrorsHideAccountState(t *testing.T) {
	c, _, _ := setup(t)
	register(t, c, "hide@example.com")
	code, body := c.do("POST", "/api/auth/login", "", map[string]any{"email": "hide@example.com", "password": "wrong-password-here"})
	if code != http.StatusUnauthorized {
		t.Fatalf("wrong password: %d %v", code, body)
	}
	if got := body["error"].(map[string]any)["code"]; got != "invalid_credentials" {
		t.Fatalf("error code %v", got)
	}
}

func TestHandlerMountedUnderPrefix(t *testing.T) {
	mr := miniredis.RunT(t)
	g := guardtest.New(redis.NewClient(&redis.Options{Addr: mr.Addr()}), guard.Config{})
	h := httpguard.Handler(g, httpguard.Options{AuthRateLimit: ratelimit.Rule{Limit: -1}, CreateUser: hostUsers()})
	outer := http.NewServeMux()
	outer.Handle("/api/", http.StripPrefix("/api", h))
	c := client{t: t, router: outer}

	if code, body := c.do("POST", "/api/auth/register", "", map[string]any{"email": "prefix@example.com", "password": password}); code != http.StatusCreated {
		t.Fatalf("register under prefix: %d %v", code, body)
	}
	token := login(t, c, "prefix@example.com")
	if code, _ := c.do("GET", "/api/auth/me", token, nil); code != http.StatusOK {
		t.Fatalf("me under prefix: %d", code)
	}
}

func jsonString(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// sessionIDOf returns the id of the session behind token.
func sessionIDOf(t *testing.T, c client, token string) string {
	t.Helper()
	code, body := c.do("GET", "/api/auth/sessions", token, nil)
	if code != http.StatusOK {
		t.Fatalf("sessions: %d %v", code, body)
	}
	for _, item := range body["sessions"].([]any) {
		s := item.(map[string]any)
		if s["current"] == true {
			return s["id"].(string)
		}
	}
	t.Fatal("no current session")
	return ""
}
