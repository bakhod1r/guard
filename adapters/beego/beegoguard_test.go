package beegoguard_test

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
	"github.com/beego/beego/v2/server/web"
	beecontext "github.com/beego/beego/v2/server/web/context"
	"github.com/redis/go-redis/v9"

	"github.com/bakhod1r/guard"
	beegoguard "github.com/bakhod1r/guard/adapters/beego"
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

// Beego keeps one global application, so every test shares this handler.
var (
	once    sync.Once
	handler http.Handler
	testG   *guard.Guard
	testMR  string
)

func setup(t *testing.T) (http.Handler, *guard.Guard) {
	t.Helper()
	once.Do(func() {
		mr, err := miniredis.Run()
		if err != nil {
			t.Fatalf("miniredis: %v", err)
		}
		testMR = mr.Addr()
		testG = guardtest.New(redis.NewClient(&redis.Options{Addr: testMR}), guard.Config{})

		opts := beegoguard.Options{AuthRateLimit: ratelimit.Rule{Limit: -1}, CreateUser: hostUsers()}
		beegoguard.Mount(testG, opts, "/api")
		beegoguard.MountAdmin(testG, adminui.Options{InsecureCookie: true})

		// A host route protected by the seeded self-service policy: only the
		// caller's own id passes, and the id comes from Beego's own parameters.
		web.InsertFilter("/api/users/:id/profile", web.BeforeExec,
			beegoguard.Require(testG, opts, "user", "read", beegoguard.ParamResource("id")), web.WithReturnOnOutput(false))
		web.Get("/api/users/:id/profile", func(ctx *beecontext.Context) {
			_ = ctx.Output.JSON(map[string]any{"id": ctx.Input.Param(":id")}, false, false)
		})
		handler = web.BeeApp.Handlers
	})
	return handler, testG
}

func call(t *testing.T, h http.Handler, method, path, token string, body any) (int, map[string]any) {
	t.Helper()
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
	h.ServeHTTP(w, req)
	out := map[string]any{}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func register(t *testing.T, h http.Handler, email string) (token, id string) {
	t.Helper()
	code, body := call(t, h, "POST", "/api/auth/register", "", map[string]any{"email": email, "password": password})
	if code != http.StatusCreated {
		t.Fatalf("register: %d %v", code, body)
	}
	id = body["id"].(string)
	code, body = call(t, h, "POST", "/api/auth/login", "", map[string]any{"email": email, "password": password})
	if code != http.StatusOK {
		t.Fatalf("login: %d %v", code, body)
	}
	return body["token"].(string), id
}

func TestMountedRoutesWork(t *testing.T) {
	h, _ := setup(t)
	token, id := register(t, h, "beego@example.com")

	code, body := call(t, h, "GET", "/api/auth/me", token, nil)
	if code != http.StatusOK {
		t.Fatalf("me: %d %v", code, body)
	}
	if body["user"].(map[string]any)["id"] != id {
		t.Fatalf("me: %v", body)
	}
	if code, _ := call(t, h, "GET", "/api/guard/users/"+id, token, nil); code != http.StatusOK {
		t.Fatalf("self read: %d", code)
	}
	if code, _ := call(t, h, "GET", "/api/auth/me", "", nil); code != http.StatusUnauthorized {
		t.Fatalf("me without token: %d", code)
	}
}

func TestFilterUsesBeegoParams(t *testing.T) {
	h, _ := setup(t)
	token, id := register(t, h, "beego-abac@example.com")
	_, otherID := register(t, h, "beego-abac2@example.com")

	if code, body := call(t, h, "GET", "/api/users/"+id+"/profile", token, nil); code != http.StatusOK {
		t.Fatalf("own profile: %d %v", code, body)
	}
	if code, _ := call(t, h, "GET", "/api/users/"+otherID+"/profile", token, nil); code != http.StatusForbidden {
		t.Fatalf("other profile: %d", code)
	}
	if code, _ := call(t, h, "GET", "/api/users/"+id+"/profile", "", nil); code != http.StatusUnauthorized {
		t.Fatalf("profile without token: %d", code)
	}
}

func TestAdminPanelMounted(t *testing.T) {
	h, _ := setup(t)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/guard-admin/login", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("admin login page: %d", w.Code)
	}
}
