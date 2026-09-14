package adminui

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"

	"github.com/bakhod1r/guard"
	"github.com/bakhod1r/guard/guardtest"
)

func routesPanel(t *testing.T) (*gin.Engine, []*http.Cookie) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	g := guardtest.New(redis.NewClient(&redis.Options{Addr: miniredis.RunT(t).Addr()}), guard.Config{})
	if _, err := g.EnsureAdmin(context.Background(), "1", "admin@example.com", "tr0ub4dor-guard-42"); err != nil {
		t.Fatal(err)
	}
	r := gin.New()
	Mount(r, g, Options{InsecureCookie: true})
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/guard-admin/login", strings.NewReader(url.Values{"email": {"admin@example.com"}, "password": {"tr0ub4dor-guard-42"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.ServeHTTP(w, req)
	return r, w.Result().Cookies()
}

func getRoutes(t *testing.T, r *gin.Engine, cookies []*http.Cookie) (int, string) {
	t.Helper()
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/guard-admin/routes", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	r.ServeHTTP(w, req)
	return w.Code, w.Body.String()
}

func TestRoutesPage(t *testing.T) {
	r, cookies := routesPanel(t)
	// Memory Guard: no registry.
	if code, body := getRoutes(t, r, cookies); code != http.StatusOK || !strings.Contains(body, "PostgreSQL") || !strings.Contains(body, `href="/guard-admin/routes"`) {
		t.Fatalf("%d %s", code, body)
	}
	orig := listRoutes
	t.Cleanup(func() { listRoutes = orig })
	listRoutes = func(context.Context, *guard.Guard) ([]guard.RouteRecord, error) {
		return []guard.RouteRecord{
			{Method: "GET", Path: "/api/invoices/:id", Permission: "invoices.read", SeenAt: time.Now()},
			{Method: "DELETE", Path: "/api/<old>", Permission: "old.delete", Stale: true},
		}, nil
	}
	code, body := getRoutes(t, r, cookies)
	if code != http.StatusOK || !strings.Contains(body, "/api/invoices/:id") || !strings.Contains(body, "invoices.read") ||
		!strings.Contains(body, "stale") || strings.Contains(body, "<old>") || !strings.Contains(body, "1 active, 1 stale") {
		t.Fatalf("%d %s", code, body)
	}
	listRoutes = func(context.Context, *guard.Guard) ([]guard.RouteRecord, error) { return nil, nil }
	if _, body := getRoutes(t, r, cookies); !strings.Contains(body, "No routes synced yet") {
		t.Fatal(body)
	}
	listRoutes = func(context.Context, *guard.Guard) ([]guard.RouteRecord, error) { return nil, errors.New("db down") }
	if code, body := getRoutes(t, r, cookies); code != http.StatusInternalServerError || strings.Contains(body, "db down") {
		t.Fatalf("%d %s", code, body)
	}
}
