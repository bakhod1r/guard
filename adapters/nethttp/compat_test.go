// Package compat_test proves that httpguard drives the net/http router family
// with no adapter at all: chi, gorilla/mux and httprouter each mount Guard's
// routes and protect one of their own, using their own path parameters.
package compat_test

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
	"github.com/go-chi/chi/v5"
	"github.com/gorilla/mux"
	"github.com/julienschmidt/httprouter"
	"github.com/redis/go-redis/v9"

	"github.com/bakhod1r/guard"
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

func newGuard(t *testing.T) *guard.Guard {
	t.Helper()
	mr := miniredis.RunT(t)
	return guardtest.New(redis.NewClient(&redis.Options{Addr: mr.Addr()}), guard.Config{})
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

func options() httpguard.Options {
	return httpguard.Options{AuthRateLimit: ratelimit.Rule{Limit: -1}, CreateUser: hostUsers()}
}

// checkRouter runs the same scenario against any router that already has Guard
// mounted under /api and a protected GET /api/users/{id}/profile route.
func checkRouter(t *testing.T, h http.Handler) {
	t.Helper()
	token, id := register(t, h, "compat@example.com")
	_, otherID := register(t, h, "compat2@example.com")

	if code, body := call(t, h, "GET", "/api/auth/me", token, nil); code != http.StatusOK {
		t.Fatalf("me: %d %v", code, body)
	}
	if code, _ := call(t, h, "GET", "/api/auth/me", "", nil); code != http.StatusUnauthorized {
		t.Fatalf("me without token: %d", code)
	}
	// The seeded self-service policy allows only the caller's own id, so the
	// path parameter must reach Guard through the router's own store.
	if code, body := call(t, h, "GET", "/api/users/"+id+"/profile", token, nil); code != http.StatusOK {
		t.Fatalf("own profile: %d %v", code, body)
	}
	if code, _ := call(t, h, "GET", "/api/users/"+otherID+"/profile", token, nil); code != http.StatusForbidden {
		t.Fatalf("other profile: %d", code)
	}
}

func TestServeMux(t *testing.T) {
	g := newGuard(t)
	o := options()
	o.AuthPath, o.AdminPath = "/api/auth", "/api/guard"
	mux := http.NewServeMux()
	httpguard.Mount(mux, g, o)
	mux.Handle("GET /api/users/{id}/profile", httpguard.Require(g, o, "user", "read", httpguard.ParamResource("id"))(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{"id": r.PathValue("id")})
		})))
	checkRouter(t, mux)
}

func TestChi(t *testing.T) {
	g := newGuard(t)
	o := options()
	o.PathValue = func(r *http.Request, name string) string { return chi.URLParam(r, name) }
	o.RoutePattern = func(r *http.Request) string { return chi.RouteContext(r.Context()).RoutePattern() }

	r := chi.NewRouter()
	r.Mount("/api/auth", http.StripPrefix("/api/auth", guardSubrouter(g, o, "/auth")))
	r.Mount("/api/guard", http.StripPrefix("/api/guard", guardSubrouter(g, o, "/guard")))
	r.With(httpguard.Require(g, o, "user", "read", httpguard.ParamResource("id"))).
		Get("/api/users/{id}/profile", func(w http.ResponseWriter, req *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{"id": chi.URLParam(req, "id")})
		})
	checkRouter(t, r)
}

// guardSubrouter serves one Guard group (/auth or /guard) at the root of its own
// mux, so it can be mounted under any prefix.
func guardSubrouter(g *guard.Guard, o httpguard.Options, group string) http.Handler {
	sub := o
	// Inside the sub-mux the path parameters come from net/http patterns again.
	sub.PathValue = nil
	sub.RoutePattern = nil
	full := httpguard.Handler(g, sub)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.Clone(r.Context())
		r.URL.Path = group + r.URL.Path
		full.ServeHTTP(w, r)
	})
}

func TestGorillaMux(t *testing.T) {
	g := newGuard(t)
	o := options()
	o.AuthPath, o.AdminPath = "/api/auth", "/api/guard"
	o.PathValue = func(r *http.Request, name string) string { return mux.Vars(r)[name] }
	o.RoutePattern = func(r *http.Request) string {
		tpl, err := mux.CurrentRoute(r).GetPathTemplate()
		if err != nil {
			return ""
		}
		return tpl
	}

	r := mux.NewRouter()
	guardHandler := httpguard.Handler(g, withStdParams(o))
	r.PathPrefix("/api/auth").Handler(guardHandler)
	r.PathPrefix("/api/guard").Handler(guardHandler)
	r.Handle("/api/users/{id}/profile", httpguard.Require(g, o, "user", "read", httpguard.ParamResource("id"))(
		http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{"id": mux.Vars(req)["id"]})
		}))).Methods("GET")
	checkRouter(t, r)
}

func TestHTTPRouter(t *testing.T) {
	g := newGuard(t)
	o := options()
	o.AuthPath, o.AdminPath = "/api/auth", "/api/guard"
	o.PathValue = func(r *http.Request, name string) string {
		return httprouter.ParamsFromContext(r.Context()).ByName(name)
	}

	guardHandler := httpguard.Handler(g, withStdParams(o))
	router := httprouter.New()
	for _, p := range []string{"/api/auth/*guardpath", "/api/guard/*guardpath"} {
		router.Handler(http.MethodGet, p, guardHandler)
		router.Handler(http.MethodPost, p, guardHandler)
		router.Handler(http.MethodPut, p, guardHandler)
		router.Handler(http.MethodDelete, p, guardHandler)
	}
	router.Handler(http.MethodGet, "/api/users/:id/profile",
		httpguard.Require(g, o, "user", "read", httpguard.ParamResource("id"))(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]any{"id": o.PathValue(r, "id")})
			})))
	checkRouter(t, router)
}

// withStdParams restores net/http pattern parameters for Guard's own routes,
// which are served by an internal ServeMux whatever the host router is.
func withStdParams(o httpguard.Options) httpguard.Options {
	o.PathValue, o.RoutePattern = nil, nil
	return o
}

func TestAdminPanelOnChi(t *testing.T) {
	g := newGuard(t)
	r := chi.NewRouter()
	r.Mount("/guard-admin", adminui.Handler(g, adminui.Options{InsecureCookie: true}))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/guard-admin/login", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("admin login page on chi: %d", w.Code)
	}
}
