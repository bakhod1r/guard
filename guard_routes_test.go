package guard

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	accessapp "github.com/bakhod1r/guard/access/application"
	accessdomain "github.com/bakhod1r/guard/access/domain"
	"github.com/bakhod1r/guard/kernel/migrations"
)

func TestSyncRoutesMemory(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, Config{})
	res, err := f.g.SyncRoutes(ctx, []accessapp.Route{{Method: "GET", Path: "/api/invoices"}, {Method: "GET", Path: "/api"}}, RouteSyncOptions{Prefix: "/api"})
	if err != nil || len(res.Created) != 1 || res.Stale != nil {
		t.Fatalf("%+v %v", res, err)
	}
	ev := f.audit.Events[len(f.audit.Events)-1]
	if ev.Action != "routes.sync" || !ev.Success || ev.Metadata["created"] != 1 || ev.Metadata["skipped"] != 1 {
		t.Fatalf("audit %+v", ev)
	}
	if _, err := f.g.ListRoutes(ctx); !errors.Is(err, ErrNoRouteRegistry) {
		t.Fatal(err)
	}
	bad := RouteSyncOptions{Overrides: map[string]string{"GET /api/x": "bad"}}
	if _, err := f.g.SyncRoutes(ctx, []accessapp.Route{{Method: "GET", Path: "/api/x"}}, bad); !errors.Is(err, accessdomain.ErrInvalidPermission) {
		t.Fatal(err)
	}
	if ev := f.audit.Events[len(f.audit.Events)-1]; ev.Action != "routes.sync" || ev.Success {
		t.Fatalf("failure audit %+v", ev)
	}
}

func TestSyncRoutesPostgres(t *testing.T) {
	dsn := os.Getenv("GUARD_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("GUARD_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	name := "guard_prod_routes_" + hex.EncodeToString(b)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	cfg, _ := pgxpool.ParseConfig(dsn)
	cfg.ConnConfig.Database = name
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, _ = admin.Exec(c, "DROP DATABASE IF EXISTS "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)")
		admin.Close()
	})
	if _, err := pool.Exec(ctx, `CREATE TABLE users (id BIGSERIAL PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	ref, err := migrations.Detect(ctx, pool, "users", "id")
	if err != nil {
		t.Fatal(err)
	}
	if err := migrations.Up(ctx, pool, "", ref); err != nil {
		t.Fatal(err)
	}
	gg, err := New(Config{DB: pool, Redis: redis.NewClient(&redis.Options{Addr: miniredis.RunT(t).Addr()})})
	if err != nil {
		t.Fatal(err)
	}
	routes := []accessapp.Route{{Method: "GET", Path: "/api/invoices"}, {Method: "DELETE", Path: "/api/invoices/:id"}}
	if _, err := gg.SyncRoutes(ctx, routes, RouteSyncOptions{Prefix: "/api"}); err != nil {
		t.Fatal(err)
	}
	res, err := gg.SyncRoutes(ctx, routes[:1], RouteSyncOptions{Prefix: "/api"})
	if err != nil || len(res.Stale) != 1 || res.Stale[0].Path != "/api/invoices/:id" {
		t.Fatalf("%+v %v", res, err)
	}
	all, err := gg.ListRoutes(ctx)
	if err != nil || len(all) != 2 {
		t.Fatalf("%+v %v", all, err)
	}
	if user, _ := gg.Access.Role(ctx, "user"); !user.Allows("invoices", "read") || user.Allows("invoices", "delete") {
		t.Fatalf("user %+v", user)
	}
}
