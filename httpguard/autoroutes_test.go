package httpguard_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/bakhod1r/guard"
	"github.com/bakhod1r/guard/guardtest"
	"github.com/bakhod1r/guard/httpguard"
	"github.com/bakhod1r/guard/ratelimit"
)

// protectedSetup mounts Guard plus two host routes behind Protect, which derives
// the permission from the matched route pattern (GET /api/reports/{id} -> reports.read).
func protectedSetup(t *testing.T) (client, *guard.Guard, []httpguard.Route) {
	t.Helper()
	mr := miniredis.RunT(t)
	g := guardtest.New(redis.NewClient(&redis.Options{Addr: mr.Addr()}), guard.Config{})
	o := httpguard.Options{AuthPath: "/api/auth", AdminPath: "/api/guard",
		AuthRateLimit: ratelimit.Rule{Limit: -1}, CreateUser: hostUsers()}

	mux := http.NewServeMux()
	httpguard.Mount(mux, g, o)

	host := http.NewServeMux()
	collector := httpguard.NewCollector(host)
	echo := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"path": r.URL.Path})
	})
	collector.Handle("GET /api/reports/{id}", echo)
	collector.Handle("POST /api/reports", echo)

	protected := httpguard.ProtectMux(g, o, "/api", host)
	mux.Handle("/api/reports", protected)
	mux.Handle("/api/reports/{id}", protected)
	return client{t: t, router: mux}, g, collector.Routes()
}

func TestProtectDerivesPermissionFromRoute(t *testing.T) {
	c, g, routes := protectedSetup(t)
	token, id := register(t, c, "protect@example.com")

	if code, body := c.do("GET", "/api/reports/9", token, nil); code != http.StatusForbidden {
		t.Fatalf("report before seeding: %d %v", code, body)
	}

	ctx := context.Background()
	seed, err := httpguard.Autoseed(ctx, g, routes, httpguard.AutoseedOptions{Prefix: "/api", SuperRole: "reporter"})
	if err != nil {
		t.Fatalf("autoseed: %v", err)
	}
	if len(seed.Permissions) == 0 {
		t.Fatalf("autoseed created no permissions: %+v", seed)
	}
	// Autoseed's own SuperRole is wildcard, hence privileged; grant the derived
	// permissions to an ordinary role instead and give that to the caller.
	if _, err := g.Access.CreateRole(ctx, "clerk", "Clerk", "", false); err != nil {
		t.Fatalf("create role: %v", err)
	}
	for _, p := range seed.Permissions {
		if err := g.Access.GrantPermission(ctx, "clerk", p.Code(), "test"); err != nil {
			t.Fatalf("grant %s: %v", p.Code(), err)
		}
	}
	if err := g.Access.AssignRole(ctx, id, "clerk", "test", nil); err != nil {
		t.Fatalf("assign: %v", err)
	}

	if code, body := c.do("GET", "/api/reports/9", token, nil); code != http.StatusOK {
		t.Fatalf("report after seeding: %d %v", code, body)
	}
	if code, body := c.do("POST", "/api/reports", token, map[string]any{}); code != http.StatusOK {
		t.Fatalf("create report after seeding: %d %v", code, body)
	}
	if code, _ := c.do("GET", "/api/reports/9", "", nil); code != http.StatusUnauthorized {
		t.Fatalf("report without token: %d", code)
	}
}

func TestCollectorRecordsPatterns(t *testing.T) {
	_, _, routes := protectedSetup(t)
	want := map[string]string{"GET": "/api/reports/{id}", "POST": "/api/reports"}
	if len(routes) != 2 {
		t.Fatalf("want 2 routes, got %v", routes)
	}
	for _, r := range routes {
		if want[r.Method] != r.Path {
			t.Fatalf("unexpected route %v", r)
		}
	}
}

func TestRoutesParsesPatterns(t *testing.T) {
	got := httpguard.Routes("GET /api/users/{id}", "/health")
	if got[0] != (httpguard.Route{Method: "GET", Path: "/api/users/{id}"}) {
		t.Fatalf("got %v", got[0])
	}
	if got[1] != (httpguard.Route{Method: http.MethodGet, Path: "/health"}) {
		t.Fatalf("bare path should default to GET: %v", got[1])
	}
}
