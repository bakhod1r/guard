package ginguard_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/bakhod1r/guard/adminui"
	"github.com/bakhod1r/guard/ginguard"
)

func TestSyncRoutesAndProtectRoutes(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, envConfig{})
	so := ginguard.SyncOptions{
		Prefix:       "/api",
		SkipPrefixes: []string{"/auth", "/guard", "/me"},
		Overrides:    map[string]string{"GET /api/reports/:id/export": "reports.export"},
	}
	api := e.router.Group("/api", ginguard.ProtectRoutes(e.g, ginguard.Options{}, so))
	ok := func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) }
	api.GET("/invoices/:id", ok)
	api.POST("/invoices", ok)
	api.GET("/reports/:id/export", ok)
	e.router.NoRoute(ginguard.ProtectRoutes(e.g, ginguard.Options{}, so), func(c *gin.Context) {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
	})

	res, err := ginguard.SyncRoutes(ctx, e.g, e.router.Routes(), so)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range res.Skipped {
		t.Fatalf("unexpected skip %+v", s)
	}
	got := map[string]bool{}
	for _, p := range res.Permissions {
		got[p.Code()] = true
		if p.Resource == "auth" || p.Resource == "guard" {
			t.Fatalf("skipped prefix synced: %s", p.Code())
		}
	}
	if !got["invoices.read"] || !got["invoices.create"] || !got["reports.export"] {
		t.Fatalf("permissions %v", got)
	}

	user := e.account("50", "user@example.com")
	if r := e.do("GET", "/api/invoices/7", "", nil); r.code != http.StatusUnauthorized {
		t.Fatalf("anonymous: %d", r.code)
	}
	if r := e.do("GET", "/api/invoices/7", user, nil); r.code != http.StatusOK {
		t.Fatalf("user default read: %d %v", r.code, r.body)
	}
	if r := e.do("POST", "/api/invoices", user, nil); r.code != http.StatusForbidden {
		t.Fatalf("user create: %d", r.code)
	}
	if r := e.do("GET", "/api/reports/1/export", user, nil); r.code != http.StatusForbidden || r.errCode() != "forbidden" {
		t.Fatalf("override not applied: %d %v", r.code, r.body)
	}
	if r := e.do("GET", "/api/reports/1/export", e.admin, nil); r.code != http.StatusOK {
		t.Fatalf("admin: %d", r.code)
	}
	if r := e.do("GET", "/api/nope", e.admin, nil); r.code != http.StatusNotFound {
		t.Fatalf("unmatched: %d", r.code)
	}

	// An invalid override fails closed at request time too.
	bad := e.router.Group("/bad", ginguard.ProtectRoutes(e.g, ginguard.Options{}, ginguard.SyncOptions{Overrides: map[string]string{"GET /bad/x": "nope"}}))
	bad.GET("/x", ok)
	if r := e.do("GET", "/bad/x", e.admin, nil); r.code != http.StatusForbidden {
		t.Fatalf("bad override: %d", r.code)
	}
	if _, err := ginguard.SyncRoutes(ctx, e.g, gin.RoutesInfo{{Method: "GET", Path: "/bad/x"}}, ginguard.SyncOptions{Overrides: map[string]string{"GET /bad/x": "nope"}}); err == nil {
		t.Fatal("bad override synced")
	}
}

func TestSyncRoutesSkipsGuardRoutesByDefault(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, envConfig{}) // Mounts ginguard under /auth and /guard.
	adminui.Mount(e.router, e.g, adminui.Options{Path: "/panel", InsecureCookie: true})
	ok := func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) }
	e.router.GET("/invoices/:id", ok)

	codes := func(o ginguard.SyncOptions) map[string]bool {
		t.Helper()
		res, err := ginguard.SyncRoutes(ctx, e.g, e.router.Routes(), o)
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]bool{}
		for _, p := range res.Permissions {
			got[p.Code()] = true
		}
		for _, s := range res.Skipped {
			got["skipped:"+s.Path] = true
		}
		return got
	}

	got := codes(ginguard.SyncOptions{})
	if !got["invoices.read"] {
		t.Fatalf("host route missing: %v", got)
	}
	for c := range got {
		if c != "invoices.read" {
			t.Fatalf("guard route synced without SkipPrefixes: %s (%v)", c, got)
		}
	}

	all := codes(ginguard.SyncOptions{IncludeGuardRoutes: true})
	if !all["auth_login.create"] || !all["panel.read"] {
		t.Fatalf("IncludeGuardRoutes did not sync guard routes: %v", all)
	}
	// SkipPrefixes still applies with IncludeGuardRoutes.
	if some := codes(ginguard.SyncOptions{IncludeGuardRoutes: true, SkipPrefixes: []string{"/panel"}}); some["panel.read"] || !some["auth_login.create"] {
		t.Fatalf("SkipPrefixes ignored: %v", some)
	}
}

func TestProtectRoutesSkipsGuardRoutes(t *testing.T) {
	gin.SetMode(gin.TestMode)
	e := newEnv(t, envConfig{})
	user := e.account("50", "user@example.com")
	ok := func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) }

	// Guard routes registered under a ProtectRoutes group keep their own checks:
	// no route-derived permission ("me.read") is required.
	r := gin.New()
	api := r.Group("/api", ginguard.ProtectRoutes(e.g, ginguard.Options{}, ginguard.SyncOptions{Prefix: "/api"}))
	ginguard.Mount(api, e.g, ginguard.Options{InsecureCookie: true})
	api.GET("/invoices/:id", ok)
	e.router = r
	if res := e.do("GET", "/api/auth/me", user, nil); res.code != http.StatusOK {
		t.Fatalf("guard route blocked: %d %v", res.code, res.body)
	}
	if res := e.do("GET", "/api/invoices/1", user, nil); res.code != http.StatusForbidden {
		t.Fatalf("host route not protected: %d", res.code)
	}

	// Opt-out: guard routes then need their derived permission too.
	r2 := gin.New()
	api2 := r2.Group("/api", ginguard.ProtectRoutes(e.g, ginguard.Options{}, ginguard.SyncOptions{Prefix: "/api", IncludeGuardRoutes: true}))
	ginguard.Mount(api2, e.g, ginguard.Options{InsecureCookie: true})
	e.router = r2
	if res := e.do("GET", "/api/auth/me", user, nil); res.code != http.StatusForbidden {
		t.Fatalf("IncludeGuardRoutes not enforced: %d %v", res.code, res.body)
	}
}
