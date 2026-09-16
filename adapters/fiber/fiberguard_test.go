package fiberguard_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/gofiber/fiber/v2"
	"github.com/redis/go-redis/v9"

	"github.com/bakhod1r/guard"
	fiberguard "github.com/bakhod1r/guard/adapters/fiber"
	"github.com/bakhod1r/guard/adminui"
	"github.com/bakhod1r/guard/guardtest"
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
	t   *testing.T
	app *fiber.App
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
	res, err := c.app.Test(req, -1)
	if err != nil {
		c.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return res.StatusCode, out
}

func setup(t *testing.T) (client, *guard.Guard) {
	t.Helper()
	mr := miniredis.RunT(t)
	g := guardtest.New(redis.NewClient(&redis.Options{Addr: mr.Addr()}), guard.Config{})
	app := fiber.New()
	opts := fiberguard.Options{AuthRateLimit: ratelimit.Rule{Limit: -1}, CreateUser: hostUsers()}
	fiberguard.Mount(app, g, opts, "/api")
	fiberguard.MountAdmin(app, g, adminui.Options{InsecureCookie: true})
	app.Get("/api/invoices/:id", fiberguard.RequirePermission(g, opts, "invoice.read"), func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"id": c.Params("id"), "user": string(fiberguard.PrincipalFrom(c).User.ID)})
	})
	app.Get("/api/users/:id/profile", fiberguard.Require(g, opts, "user", "read", fiberguard.ParamResource("id")),
		func(c *fiber.Ctx) error { return c.JSON(fiber.Map{"id": c.Params("id")}) })
	return client{t: t, app: app}, g
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
	token, id := register(t, c, "fiber@example.com")

	code, body := c.do("GET", "/api/auth/me", token, nil)
	if code != http.StatusOK {
		t.Fatalf("me: %d %v", code, body)
	}
	if body["user"].(map[string]any)["id"] != id {
		t.Fatalf("me: %v", body)
	}
	if code, _ := c.do("GET", "/api/guard/users/"+id, token, nil); code != http.StatusOK {
		t.Fatalf("self read: %d", code)
	}
	if code, _ := c.do("GET", "/api/auth/me", "", nil); code != http.StatusUnauthorized {
		t.Fatalf("me without token: %d", code)
	}
}

func TestRequirePermissionOnFiberRoute(t *testing.T) {
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

func TestParamResourceUsesFiberParams(t *testing.T) {
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
	res, err := c.app.Test(httptest.NewRequest("GET", "/guard-admin/login", nil), -1)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("admin login page: %d", res.StatusCode)
	}
}

func TestRoutesTable(t *testing.T) {
	c, _ := setup(t)
	for _, r := range fiberguard.Routes(c.app) {
		if r.Method == http.MethodGet && r.Path == "/api/invoices/:id" {
			return
		}
	}
	t.Fatalf("route table missing the invoice route: %v", fiberguard.Routes(c.app))
}
