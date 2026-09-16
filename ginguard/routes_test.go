package ginguard_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"

	"github.com/bakhod1r/guard"
	"github.com/bakhod1r/guard/ginguard"
	"github.com/bakhod1r/guard/guardtest"
	"github.com/bakhod1r/guard/ratelimit"
)

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
	router *gin.Engine
}

func (c client) do(method, path, token string, body any) (int, map[string]any) {
	c.t.Helper()
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	c.router.ServeHTTP(w, req)
	out := map[string]any{}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func setup(t *testing.T) (client, *guard.Guard) {
	gin.SetMode(gin.TestMode)
	mr := miniredis.RunT(t)
	g := guardtest.New(redis.NewClient(&redis.Options{Addr: mr.Addr()}), guard.Config{})
	r := gin.New()
	api := r.Group("/api")
	ginguard.Mount(api, g, ginguard.Options{AuthRateLimit: ratelimit.Rule{Limit: -1}, CreateUser: hostUsers()})
	api.GET("/invoices/:id", ginguard.RequirePermission(g, ginguard.Options{}, "invoice.read"), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"id": c.Param("id")})
	})
	return client{t: t, router: r}, g
}

func login(t *testing.T, c client, email string) (token, id string) {
	t.Helper()
	code, body := c.do("POST", "/api/auth/register", "", map[string]any{"email": email, "password": "tr0ub4dor-guard-42"})
	if code != http.StatusCreated {
		t.Fatalf("register %s: %d %v", email, code, body)
	}
	id = body["id"].(string)
	code, body = c.do("POST", "/api/auth/login", "", map[string]any{"email": email, "password": "tr0ub4dor-guard-42"})
	if code != http.StatusOK {
		t.Fatalf("login %s: %d %v", email, code, body)
	}
	return body["token"].(string), id
}

func TestAuthFlow(t *testing.T) {
	c, _ := setup(t)
	tok, id := login(t, c, "ali@example.com")

	if code, _ := c.do("GET", "/api/auth/me", "", nil); code != http.StatusUnauthorized {
		t.Fatalf("anonymous me: %d", code)
	}
	code, me := c.do("GET", "/api/auth/me", tok, nil)
	if code != http.StatusOK || me["user"].(map[string]any)["id"] != id {
		t.Fatalf("me: %d %v", code, me)
	}
	if code, body := c.do("POST", "/api/auth/register", "", map[string]any{"email": "ALI@example.com", "password": "tr0ub4dor-guard-42"}); code != http.StatusConflict {
		t.Fatalf("duplicate register: %d %v", code, body)
	}
	if code, body := c.do("POST", "/api/auth/login", "", map[string]any{"email": "ali@example.com", "password": "nope-nope"}); code != http.StatusUnauthorized {
		t.Fatalf("bad password: %d %v", code, body)
	}

	// Self-service policy: own record readable, others not.
	if code, _ := c.do("GET", "/api/guard/users/"+id, tok, nil); code != http.StatusOK {
		t.Fatalf("self read: %d", code)
	}
	_, otherID := login(t, c, "vali@example.com")
	if code, _ := c.do("GET", "/api/guard/users/"+otherID, tok, nil); code != http.StatusForbidden {
		t.Fatalf("foreign read: %d", code)
	}
	if code, _ := c.do("GET", "/api/guard/users/"+id+"/roles", tok, nil); code != http.StatusOK {
		t.Fatalf("self roles: %d", code)
	}

	// Sessions + password change keeps current, drops others.
	_, body := c.do("POST", "/api/auth/login", "", map[string]any{"email": "ali@example.com", "password": "tr0ub4dor-guard-42"})
	tok2 := body["token"].(string)
	_, list := c.do("GET", "/api/auth/sessions", tok, nil)
	if n := len(list["sessions"].([]any)); n != 2 {
		t.Fatalf("want 2 sessions, got %d", n)
	}
	if code, _ := c.do("PUT", "/api/auth/password", tok, map[string]any{"old_password": "tr0ub4dor-guard-42", "new_password": "tr0ub4dor-guard-44"}); code != http.StatusNoContent {
		t.Fatalf("change password: %d", code)
	}
	if code, _ := c.do("GET", "/api/auth/me", tok2, nil); code != http.StatusUnauthorized {
		t.Fatalf("other session survived password change: %d", code)
	}
	if code, _ := c.do("POST", "/api/auth/logout", tok, nil); code != http.StatusNoContent {
		t.Fatalf("logout: %d", code)
	}
	if code, _ := c.do("GET", "/api/auth/me", tok, nil); code != http.StatusUnauthorized {
		t.Fatalf("session alive after logout: %d", code)
	}
}

func TestAdminRBACAndABAC(t *testing.T) {
	c, g := setup(t)
	ctx := context.Background()
	if _, err := g.EnsureAdmin(ctx, "1", "admin@example.com", "admin-password"); err != nil {
		t.Fatal(err)
	}
	_, body := c.do("POST", "/api/auth/login", "", map[string]any{"email": "admin@example.com", "password": "admin-password"})
	admin := body["token"].(string)
	userTok, userID := login(t, c, "user@example.com")

	// Host route protected by a custom permission.
	if code, _ := c.do("GET", "/api/invoices/1", userTok, nil); code != http.StatusForbidden {
		t.Fatalf("user invoice before grant: %d", code)
	}
	steps := []struct {
		method, path string
		body         any
		want         int
	}{
		{"POST", "/api/guard/permissions", map[string]any{"code": "invoice.read"}, http.StatusCreated},
		{"POST", "/api/guard/roles", map[string]any{"name": "accountant", "title": "Accountant"}, http.StatusCreated},
		{"POST", "/api/guard/roles", map[string]any{"name": "accountant"}, http.StatusConflict},
		{"POST", "/api/guard/roles/accountant/permissions", map[string]any{"code": "invoice.read"}, http.StatusNoContent},
		{"POST", "/api/guard/users/" + userID + "/roles", map[string]any{"role": "accountant"}, http.StatusNoContent},
		{"DELETE", "/api/guard/roles/admin", nil, http.StatusConflict},
	}
	for _, s := range steps {
		if code, b := c.do(s.method, s.path, admin, s.body); code != s.want {
			t.Fatalf("%s %s: want %d got %d %v", s.method, s.path, s.want, code, b)
		}
	}
	if code, _ := c.do("GET", "/api/invoices/1", userTok, nil); code != http.StatusOK {
		t.Fatalf("user invoice after grant: %d", code)
	}
	if code, _ := c.do("GET", "/api/guard/roles", userTok, nil); code != http.StatusForbidden {
		t.Fatalf("user listed roles: %d", code)
	}

	// ABAC: deny invoices outside working department, priority beats RBAC.
	policy := map[string]any{
		"name": "finance only", "resource": "invoice", "action": "read", "effect": "deny", "priority": 50, "enabled": true,
		"root": map[string]any{"operator": "and", "negate": true, "conditions": []any{
			map[string]any{"field": "user.department", "operator": "eq", "value": []string{"finance"}},
		}},
	}
	code, created := c.do("POST", "/api/guard/policies", admin, policy)
	if code != http.StatusCreated {
		t.Fatalf("create policy: %d %v", code, created)
	}
	if code, _ := c.do("GET", "/api/invoices/1", userTok, nil); code != http.StatusForbidden {
		t.Fatalf("deny policy ignored: %d", code)
	}
	if code, _ := c.do("PUT", "/api/guard/users/"+userID+"/attributes", admin, map[string]any{"attributes": map[string]any{"department": "finance"}}); code != http.StatusNoContent {
		t.Fatalf("set attributes: %d", code)
	}
	if code, _ := c.do("GET", "/api/invoices/1", userTok, nil); code != http.StatusOK {
		t.Fatalf("finance user denied: %d", code)
	}
	code, d := c.do("POST", "/api/auth/authorize", userTok, map[string]any{"action": "read", "resource": map[string]any{"type": "invoice"}})
	if code != http.StatusOK || d["allowed"] != true {
		t.Fatalf("authorize endpoint: %d %v", code, d)
	}
	if code, b := c.do("POST", "/api/guard/policies", admin, map[string]any{"name": "bad", "resource": "x", "action": "y", "effect": "maybe"}); code != http.StatusBadRequest {
		t.Fatalf("invalid policy accepted: %d %v", code, b)
	}

	// Ban: sessions revoked, login refused.
	if code, _ := c.do("PUT", "/api/guard/users/"+userID+"/status", admin, map[string]any{"status": "banned"}); code != http.StatusNoContent {
		t.Fatalf("ban: %d", code)
	}
	if code, _ := c.do("GET", "/api/invoices/1", userTok, nil); code != http.StatusUnauthorized {
		t.Fatalf("banned session still valid: %d", code)
	}
	if code, _ := c.do("POST", "/api/auth/login", "", map[string]any{"email": "user@example.com", "password": "tr0ub4dor-guard-42"}); code != http.StatusUnauthorized {
		t.Fatalf("banned login: %d", code)
	}

	if code, ev := c.do("GET", "/api/guard/audit", admin, nil); code != http.StatusOK || len(ev["events"].([]any)) == 0 {
		t.Fatalf("audit: %d %v", code, ev)
	}
}

func TestLockout(t *testing.T) {
	c, _ := setup(t)
	login(t, c, "x@example.com")
	for i := 0; i < 5; i++ {
		c.do("POST", "/api/auth/login", "", map[string]any{"email": "x@example.com", "password": "wrong-pass"})
	}
	if code, _ := c.do("POST", "/api/auth/login", "", map[string]any{"email": "x@example.com", "password": "tr0ub4dor-guard-42"}); code != http.StatusUnauthorized {
		t.Fatalf("lockout not enforced: %d", code)
	}
}

func TestAPIKeys(t *testing.T) {
	c, g := setup(t)
	if _, err := g.EnsureAdmin(context.Background(), "1", "admin@example.com", "admin-password"); err != nil {
		t.Fatal(err)
	}
	_, body := c.do("POST", "/api/auth/login", "", map[string]any{"email": "admin@example.com", "password": "admin-password"})
	admin := body["token"].(string)

	if code, b := c.do("POST", "/api/auth/api-keys", admin, map[string]any{"name": "ci", "scopes": []string{"Bad"}}); code != http.StatusBadRequest {
		t.Fatalf("bad scope: %d %v", code, b)
	}
	code, created := c.do("POST", "/api/auth/api-keys", admin, map[string]any{"name": "ci", "scopes": []string{"invoice.read"}})
	if code != http.StatusCreated {
		t.Fatalf("issue: %d %v", code, created)
	}
	key := created["token"].(string)
	keyID := created["api_key"].(map[string]any)["id"].(string)

	// Wildcard admin owner, but the key is scoped to invoice.read only.
	if code, _ := c.do("GET", "/api/invoices/7", key, nil); code != http.StatusOK {
		t.Fatalf("scoped route: %d", code)
	}
	if code, _ := c.do("GET", "/api/guard/roles", key, nil); code != http.StatusForbidden {
		t.Fatalf("key escaped its scope: %d", code)
	}
	// X-API-Key header works too.
	req := httptest.NewRequest("GET", "/api/auth/me", nil)
	req.Header.Set("X-API-Key", key)
	w := httptest.NewRecorder()
	c.router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("X-API-Key me: %d", w.Code)
	}
	// A key cannot manage the account or mint more keys.
	if code, _ := c.do("POST", "/api/auth/api-keys", key, map[string]any{"name": "x", "scopes": []string{"*"}}); code != http.StatusForbidden {
		t.Fatalf("key minted key: %d", code)
	}
	if code, _ := c.do("POST", "/api/auth/logout", key, nil); code != http.StatusForbidden {
		t.Fatalf("key logout: %d", code)
	}

	_, list := c.do("GET", "/api/auth/api-keys", admin, nil)
	if n := len(list["api_keys"].([]any)); n != 1 {
		t.Fatalf("list: %d", n)
	}
	if _, ok := list["api_keys"].([]any)[0].(map[string]any)["hash"]; ok {
		t.Fatal("hash leaked in response")
	}
	if code, _ := c.do("DELETE", "/api/auth/api-keys/"+keyID, admin, nil); code != http.StatusNoContent {
		t.Fatalf("revoke: %d", code)
	}
	if code, _ := c.do("GET", "/api/invoices/7", key, nil); code != http.StatusUnauthorized {
		t.Fatalf("revoked key works: %d", code)
	}
	if code, _ := c.do("GET", "/api/invoices/7", "gk_forged", nil); code != http.StatusUnauthorized {
		t.Fatalf("forged key: %d", code)
	}
}

func TestAuthRateLimit(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mr := miniredis.RunT(t)
	g := guardtest.New(redis.NewClient(&redis.Options{Addr: mr.Addr()}), guard.Config{})
	r := gin.New()
	ginguard.Mount(r, g, ginguard.Options{AuthRateLimit: ratelimit.Rule{Limit: 3, Window: time.Minute}, CreateUser: hostUsers()})
	c := client{t: t, router: r}
	for i := 0; i < 3; i++ {
		if code, _ := c.do("POST", "/auth/login", "", map[string]any{"email": "n@example.com", "password": "whatever1"}); code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: %d", i, code)
		}
	}
	req := httptest.NewRequest("POST", "/auth/login", bytes.NewBufferString(`{"email":"n@example.com","password":"whatever1"}`))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" || w.Header().Get("X-RateLimit-Limit") != "3" {
		t.Fatalf("rate limit: %d %v", w.Code, w.Header())
	}

	// Disabled with a negative limit.
	r2 := gin.New()
	ginguard.Mount(r2, g, ginguard.Options{AuthRateLimit: ratelimit.Rule{Limit: -1}})
	c2 := client{t: t, router: r2}
	for i := 0; i < 5; i++ {
		if code, _ := c2.do("POST", "/auth/login", "", map[string]any{"email": "z@example.com", "password": "whatever1"}); code == http.StatusTooManyRequests {
			t.Fatal("disabled limiter still limits")
		}
	}
}

func TestHostUserAccounts(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mr := miniredis.RunT(t)
	g := guardtest.New(redis.NewClient(&redis.Options{Addr: mr.Addr()}), guard.Config{})
	r := gin.New()
	ginguard.Mount(r, g, ginguard.Options{AuthRateLimit: ratelimit.Rule{Limit: -1}}) // no CreateUser
	c := client{t: t, router: r}

	if code, _ := c.do("POST", "/auth/register", "", map[string]any{"email": "a@example.com", "password": "tr0ub4dor-guard-42"}); code != http.StatusNotFound {
		t.Fatalf("register must not be mounted without CreateUser: %d", code)
	}
	if _, err := g.EnsureAdmin(context.Background(), "1", "admin@example.com", "admin-password"); err != nil {
		t.Fatal(err)
	}
	_, body := c.do("POST", "/auth/login", "", map[string]any{"email": "admin@example.com", "password": "admin-password"})
	admin := body["token"].(string)

	code, acc := c.do("POST", "/guard/users/555/account", admin, map[string]any{"email": "host@example.com", "password": "tr0ub4dor-guard-42"})
	if code != http.StatusCreated || acc["id"] != "555" {
		t.Fatalf("link account: %d %v", code, acc)
	}
	if code, _ := c.do("POST", "/guard/users/555/account", admin, map[string]any{"email": "x@example.com", "password": "tr0ub4dor-guard-42"}); code != http.StatusConflict {
		t.Fatalf("second account: %d", code)
	}
	_, body = c.do("POST", "/auth/login", "", map[string]any{"email": "host@example.com", "password": "tr0ub4dor-guard-42"})
	userTok := body["token"].(string)
	if code, _ := c.do("PUT", "/guard/users/555/password", userTok, map[string]any{"password": "hacked-password"}); code != http.StatusForbidden {
		t.Fatalf("user reset own password via admin route: %d", code)
	}
	if code, _ := c.do("PUT", "/guard/users/555/password", admin, map[string]any{"password": "reset-password"}); code != http.StatusNoContent {
		t.Fatalf("reset: %d", code)
	}
	if code, _ := c.do("GET", "/auth/me", userTok, nil); code != http.StatusUnauthorized {
		t.Fatalf("session survived reset: %d", code)
	}
	if code, _ := c.do("POST", "/auth/login", "", map[string]any{"email": "host@example.com", "password": "reset-password"}); code != http.StatusOK {
		t.Fatalf("login with reset password: %d", code)
	}
}
