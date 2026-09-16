package irisguard_test

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
	"github.com/kataras/iris/v12"
	"github.com/redis/go-redis/v9"

	"github.com/bakhod1r/guard"
	irisguard "github.com/bakhod1r/guard/adapters/iris"
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
	app *iris.Application
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
	c.app.ServeHTTP(w, req)
	out := map[string]any{}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func setup(t *testing.T) (client, *guard.Guard) {
	t.Helper()
	mr := miniredis.RunT(t)
	g := guardtest.New(redis.NewClient(&redis.Options{Addr: mr.Addr()}), guard.Config{})
	app := iris.New()
	app.Logger().SetLevel("fatal")
	opts := irisguard.Options{AuthRateLimit: ratelimit.Rule{Limit: -1}, CreateUser: hostUsers()}
	irisguard.Mount(app, g, opts, "/api")
	irisguard.MountAdmin(app, g, adminui.Options{InsecureCookie: true})
	app.Get("/api/invoices/{id}", irisguard.RequirePermission(g, opts, "invoice.read"), func(ctx iris.Context) {
		_ = ctx.JSON(iris.Map{"id": ctx.Params().Get("id"), "user": string(irisguard.PrincipalFrom(ctx).User.ID)})
	})
	app.Get("/api/users/{id}/profile", irisguard.Require(g, opts, "user", "read", irisguard.ParamResource("id")),
		func(ctx iris.Context) { _ = ctx.JSON(iris.Map{"id": ctx.Params().Get("id")}) })
	if err := app.Build(); err != nil {
		t.Fatalf("build: %v", err)
	}
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
	token, id := register(t, c, "iris@example.com")

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

func TestRequirePermissionOnIrisRoute(t *testing.T) {
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

func TestParamResourceUsesIrisParams(t *testing.T) {
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
	w := httptest.NewRecorder()
	c.app.ServeHTTP(w, httptest.NewRequest("GET", "/guard-admin/login", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("admin login page: %d", w.Code)
	}
}

func TestRoutesTable(t *testing.T) {
	c, _ := setup(t)
	for _, r := range irisguard.Routes(c.app) {
		// Iris normalises "{id}" to ":id" in its route registry.
		if r.Method == http.MethodGet && r.Path == "/api/invoices/:id" {
			return
		}
	}
	t.Fatalf("route table missing the invoice route: %v", irisguard.Routes(c.app))
}
