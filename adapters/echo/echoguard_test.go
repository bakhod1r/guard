package echoguard_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"

	"github.com/bakhod1r/guard"
	echoguard "github.com/bakhod1r/guard/adapters/echo"
	"github.com/bakhod1r/guard/adminui"
	"github.com/bakhod1r/guard/guardtest"
	"github.com/bakhod1r/guard/httpguard"
	"github.com/bakhod1r/guard/ratelimit"
)

const password = "tr0ub4dor-guard-42"

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
	t *testing.T
	e *echo.Echo
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
	c.e.ServeHTTP(w, req)
	out := map[string]any{}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func setup(t *testing.T) (client, *guard.Guard) {
	t.Helper()
	mr := miniredis.RunT(t)
	g := guardtest.New(redis.NewClient(&redis.Options{Addr: mr.Addr()}), guard.Config{})
	e := echo.New()
	opts := echoguard.Options{AuthRateLimit: ratelimit.Rule{Limit: -1}, CreateUser: hostUsers()}
	echoguard.Mount(e, g, opts, "/api")
	echoguard.MountAdmin(e, g, adminui.Options{InsecureCookie: true})
	e.GET("/api/invoices/:id", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]any{"id": c.Param("id"), "user": string(echoguard.PrincipalFrom(c).User.ID)})
	}, echoguard.RequirePermission(g, opts, "invoice.read"))
	e.GET("/api/users/:id/profile", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]any{"id": c.Param("id")})
	}, echoguard.Require(g, opts, "user", "read", echoguard.ParamResource("id")))
	return client{t: t, e: e}, g
}

func register(t *testing.T, c client, email string) (token, id string) {
	t.Helper()
	code, body := c.do("POST", "/api/auth/register", "", map[string]any{"email": email, "password": password})
	if code != http.StatusCreated {
		t.Fatalf("register: %d %v", code, body)
	}
	id = body["id"].(string)
	code, body = c.do("POST", "/api/auth/login", "", map[string]any{"email": email, "password": password})
	if code != http.StatusOK {
		t.Fatalf("login: %d %v", code, body)
	}
	return body["token"].(string), id
}

func TestMountedRoutesWork(t *testing.T) {
	c, _ := setup(t)
	token, id := register(t, c, "echo@example.com")

	code, body := c.do("GET", "/api/auth/me", token, nil)
	if code != http.StatusOK {
		t.Fatalf("me: %d %v", code, body)
	}
	if body["user"].(map[string]any)["id"] != id {
		t.Fatalf("me: %v", body)
	}
	if code, _ := c.do("GET", "/api/guard/users/"+id, token, nil); code != http.StatusOK {
		t.Fatalf("self read through admin routes: %d", code)
	}
	if code, _ := c.do("GET", "/api/auth/me", "", nil); code != http.StatusUnauthorized {
		t.Fatalf("me without token: %d", code)
	}
}

func TestRequirePermissionOnEchoRoute(t *testing.T) {
	c, g := setup(t)
	token, id := register(t, c, "perm@example.com")

	if code, _ := c.do("GET", "/api/invoices/7", token, nil); code != http.StatusForbidden {
		t.Fatalf("without permission: %d", code)
	}
	ctx := context.Background()
	if _, err := g.Access.CreatePermission(ctx, "invoice.read", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Access.CreateRoleAs(ctx, "test", "accountant", "Accountant", "", false); err != nil {
		t.Fatal(err)
	}
	if err := g.Access.GrantPermission(ctx, "accountant", "invoice.read", "test"); err != nil {
		t.Fatal(err)
	}
	if err := g.Access.AssignRole(ctx, id, "accountant", "test", nil); err != nil {
		t.Fatal(err)
	}
	code, body := c.do("GET", "/api/invoices/7", token, nil)
	if code != http.StatusOK {
		t.Fatalf("with permission: %d %v", code, body)
	}
	if body["id"] != "7" || body["user"] != id {
		t.Fatalf("handler saw %v", body)
	}
}

// TestParamResourceUsesEchoParams proves the ABAC resource id comes from Echo's
// own path parameters: the seeded self-service policy allows only :id == caller.
func TestParamResourceUsesEchoParams(t *testing.T) {
	c, _ := setup(t)
	token, id := register(t, c, "abac@example.com")
	_, otherID := register(t, c, "abac2@example.com")

	if code, body := c.do("GET", "/api/users/"+id+"/profile", token, nil); code != http.StatusOK {
		t.Fatalf("own profile: %d %v", code, body)
	}
	if code, _ := c.do("GET", "/api/users/"+otherID+"/profile", token, nil); code != http.StatusForbidden {
		t.Fatalf("other profile: %d", code)
	}
}

func TestAdminPanelMounted(t *testing.T) {
	c, _ := setup(t)
	req := httptest.NewRequest("GET", "/guard-admin/login", nil)
	w := httptest.NewRecorder()
	c.e.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("admin login page: %d", w.Code)
	}
	req = httptest.NewRequest("GET", "/guard-admin/", nil)
	w = httptest.NewRecorder()
	c.e.ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther && w.Code != http.StatusFound {
		t.Fatalf("admin root without session: %d, want redirect to login", w.Code)
	}
}

func TestRoutesTable(t *testing.T) {
	c, _ := setup(t)
	found := false
	for _, r := range echoguard.Routes(c.e) {
		if r.Method == http.MethodGet && r.Path == "/api/invoices/:id" {
			found = true
		}
	}
	if !found {
		t.Fatalf("route table missing the invoice route: %v", echoguard.Routes(c.e))
	}
	var _ []httpguard.Route = echoguard.Routes(c.e)
}
