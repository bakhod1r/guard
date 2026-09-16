package hertzguard_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"sync"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/app/server"
	"github.com/cloudwego/hertz/pkg/common/ut"
	"github.com/cloudwego/hertz/pkg/common/utils"
	"github.com/cloudwego/hertz/pkg/protocol/consts"
	"github.com/redis/go-redis/v9"

	"github.com/bakhod1r/guard"
	hertzguard "github.com/bakhod1r/guard/adapters/hertz"
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
	t *testing.T
	h *server.Hertz
}

func (c client) do(method, path, token string, body any) (int, map[string]any) {
	c.t.Helper()
	headers := []ut.Header{{Key: "Content-Type", Value: "application/json"}}
	if token != "" {
		headers = append(headers, ut.Header{Key: "Authorization", Value: "Bearer " + token})
	}
	var payload *ut.Body
	if body != nil {
		var buf bytes.Buffer
		_ = json.NewEncoder(&buf).Encode(body)
		payload = &ut.Body{Body: &buf, Len: buf.Len()}
	}
	w := ut.PerformRequest(c.h.Engine, method, path, payload, headers...)
	res := w.Result()
	out := map[string]any{}
	_ = json.Unmarshal(res.Body(), &out)
	return res.StatusCode(), out
}

func setup(t *testing.T) (client, *guard.Guard) {
	t.Helper()
	mr := miniredis.RunT(t)
	g := guardtest.New(redis.NewClient(&redis.Options{Addr: mr.Addr()}), guard.Config{})
	h := server.Default(server.WithDisablePrintRoute(true))
	opts := hertzguard.Options{AuthRateLimit: ratelimit.Rule{Limit: -1}, CreateUser: hostUsers()}
	hertzguard.Mount(h, g, opts, "/api")
	hertzguard.MountAdmin(h, g, adminui.Options{InsecureCookie: true})
	h.GET("/api/invoices/:id", hertzguard.RequirePermission(g, opts, "invoice.read"),
		func(c context.Context, ctx *app.RequestContext) {
			ctx.JSON(consts.StatusOK, utils.H{"id": ctx.Param("id"), "user": string(hertzguard.PrincipalFrom(ctx).User.ID)})
		})
	h.GET("/api/users/:id/profile", hertzguard.Require(g, opts, "user", "read", hertzguard.ParamResource("id")),
		func(c context.Context, ctx *app.RequestContext) {
			ctx.JSON(consts.StatusOK, utils.H{"id": ctx.Param("id")})
		})
	return client{t: t, h: h}, g
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
	token, id := register(t, c, "hertz@example.com")

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

func TestRequirePermissionOnHertzRoute(t *testing.T) {
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

func TestParamResourceUsesHertzParams(t *testing.T) {
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
	w := ut.PerformRequest(c.h.Engine, "GET", "/guard-admin/login", nil)
	if w.Result().StatusCode() != http.StatusOK {
		t.Fatalf("admin login page: %d", w.Result().StatusCode())
	}
}
