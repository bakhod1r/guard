package ginguard_test

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/bakhod1r/guard/ginguard"
)

// protectedEnv mounts host routes behind Protect on newEnv's router.
func protectedEnv(t *testing.T) *env {
	t.Helper()
	e := newEnv(t, envConfig{})
	api := e.router.Group("/api", ginguard.Protect(e.g, ginguard.Options{}, "/api"))
	ok := func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) }
	api.GET("/invoices/:id", ok)
	api.POST("/invoices", ok)
	api.GET("", ok) // no derivable resource
	e.router.NoRoute(ginguard.Protect(e.g, ginguard.Options{}, "/api"), func(c *gin.Context) {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
	})
	return e
}

func TestProtectEnforcesRouteDerivedPermission(t *testing.T) {
	e := protectedEnv(t)
	ctx := context.Background()
	if _, err := ginguard.Autoseed(ctx, e.g, e.router.Routes(), ginguard.AutoseedOptions{Prefix: "/api", Exclude: []string{"/auth", "/guard"}}); err != nil {
		t.Fatal(err)
	}
	user := e.account("50", "user@example.com")

	if r := e.do("GET", "/api/invoices/7", "", nil); r.code != http.StatusUnauthorized {
		t.Fatalf("anonymous: %d %v", r.code, r.body)
	}
	if r := e.do("GET", "/api/invoices/7", user, nil); r.code != http.StatusForbidden || r.errCode() != "forbidden" {
		t.Fatalf("no permission: %d %v", r.code, r.body)
	}
	if r := e.do("GET", "/api/invoices/7", e.admin, nil); r.code != http.StatusOK {
		t.Fatalf("admin: %d %v", r.code, r.body)
	}
	if r := e.do("GET", "/api/nope", e.admin, nil); r.code != http.StatusNotFound {
		t.Fatalf("unknown route: %d %v", r.code, r.body)
	}
	if r := e.do("GET", "/api", e.admin, nil); r.code != http.StatusForbidden || r.errCode() != "forbidden" {
		t.Fatalf("underivable route: %d %v", r.code, r.body)
	}

	if _, err := e.g.Access.CreateRole(ctx, "clerk", "Clerk", "", false); err != nil {
		t.Fatal(err)
	}
	if err := e.g.Access.GrantPermission(ctx, "clerk", "invoices.read", "1"); err != nil {
		t.Fatal(err)
	}
	if err := e.g.Access.AssignRole(ctx, "50", "clerk", "1", nil); err != nil {
		t.Fatal(err)
	}
	if r := e.do("GET", "/api/invoices/7", user, nil); r.code != http.StatusOK {
		t.Fatalf("granted: %d %v", r.code, r.body)
	}
	if r := e.do("POST", "/api/invoices", user, nil); r.code != http.StatusForbidden {
		t.Fatalf("other action: %d %v", r.code, r.body)
	}
}

func TestProtectAuthorizeFailureIsInternal(t *testing.T) {
	e := protectedEnv(t)
	user := e.account("50", "user@example.com")
	e.f.set("Policies.ApplicablePolicies", "invoices", errBoom)
	if r := e.do("GET", "/api/invoices/7", user, nil); r.code != http.StatusInternalServerError {
		t.Fatalf("authorize failure: %d %v", r.code, r.body)
	}
}

func TestAutoseed(t *testing.T) {
	ctx := context.Background()
	e := protectedEnv(t)
	seed, err := ginguard.Autoseed(ctx, e.g, e.router.Routes(), ginguard.AutoseedOptions{Prefix: "/api", Exclude: []string{"/auth/", "/guard", "", "/inv"}})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, p := range seed.Permissions {
		got[p.Code()] = true
	}
	if !got["invoices.read"] || !got["invoices.create"] {
		t.Fatalf("permissions: %v", got)
	}
	for c := range got {
		if len(c) > 5 && (c[:5] == "auth_" || c[:6] == "guard_") {
			t.Fatalf("excluded route seeded: %s", c)
		}
	}

	// custom non-wildcard super role receives grants
	if _, err := e.g.Access.CreateRole(ctx, "ops", "Ops", "", false); err != nil {
		t.Fatal(err)
	}
	if _, err := ginguard.Autoseed(ctx, e.g, e.router.Routes(), ginguard.AutoseedOptions{Prefix: "/api", SuperRole: "ops", Exclude: []string{"/auth", "/guard"}}); err != nil {
		t.Fatal(err)
	}
	ops, err := e.g.Access.Role(ctx, "ops")
	if err != nil {
		t.Fatal(err)
	}
	if !ops.Allows("invoices", "create") {
		t.Fatalf("ops grants: %+v", ops)
	}

	// "-" disables granting: a newly seeded permission reaches no role
	if _, err := ginguard.Autoseed(ctx, e.g, gin.RoutesInfo{{Method: "GET", Path: "/api/ledger"}}, ginguard.AutoseedOptions{Prefix: "/api", SuperRole: "-"}); err != nil {
		t.Fatal(err)
	}
	if ops, _ := e.g.Access.Role(ctx, "ops"); ops.Allows("ledger", "read") {
		t.Fatal(`"-" still granted`)
	}

	e.f.set("Roles.CreatePermission", "*", errBoom)
	if _, err := ginguard.Autoseed(ctx, e.g, gin.RoutesInfo{{Method: "GET", Path: "/api/reports"}}, ginguard.AutoseedOptions{Prefix: "/api"}); !errors.Is(err, errBoom) {
		t.Fatalf("storage failure: %v", err)
	}
}
