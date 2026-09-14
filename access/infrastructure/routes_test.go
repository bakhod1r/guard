package infrastructure

import (
	"context"
	"testing"
	"time"

	"github.com/bakhod1r/guard/access/domain"
)

// exerciseRegistry checks the RouteRegistry contract shared by both implementations.
func exerciseRegistry(t *testing.T, reg domain.RouteRegistry) {
	t.Helper()
	ctx := context.Background()
	t1 := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	t2 := t1.Add(time.Hour)
	if err := reg.SaveRoutes(ctx, nil, t1); err != nil {
		t.Fatal(err)
	}
	a := domain.RouteRecord{Method: "GET", Path: "/api/a", Permission: "a.read"}
	b := domain.RouteRecord{Method: "POST", Path: "/api/b", Permission: "b.create"}
	if err := reg.SaveRoutes(ctx, []domain.RouteRecord{b, a}, t1); err != nil {
		t.Fatal(err)
	}
	if stale, err := reg.MarkStale(ctx, t1); err != nil || len(stale) != 0 {
		t.Fatalf("nothing stale yet: %v %v", stale, err)
	}
	a.Permission = "a.list"
	if err := reg.SaveRoutes(ctx, []domain.RouteRecord{a}, t2); err != nil {
		t.Fatal(err)
	}
	stale, err := reg.MarkStale(ctx, t2)
	if err != nil || len(stale) != 1 || stale[0].Key() != "POST /api/b" || !stale[0].Stale {
		t.Fatalf("stale %+v %v", stale, err)
	}
	if again, _ := reg.MarkStale(ctx, t2); len(again) != 0 {
		t.Fatalf("stale twice: %+v", again)
	}
	all, err := reg.ListRoutes(ctx)
	if err != nil || len(all) != 2 || all[0].Key() != "GET /api/a" || all[0].Permission != "a.list" || all[0].Stale || !all[0].SeenAt.Equal(t2) || !all[1].Stale {
		t.Fatalf("list %+v %v", all, err)
	}
	// Seen again: revived.
	if err := reg.SaveRoutes(ctx, []domain.RouteRecord{b}, t2.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if all, _ := reg.ListRoutes(ctx); all[1].Stale {
		t.Fatalf("not revived %+v", all)
	}
}

func TestMemoryRoutes(t *testing.T) { exerciseRegistry(t, NewMemoryRoutes()) }

func TestPostgresRoutes(t *testing.T) {
	e := newPG(t)
	reg := NewPostgresRoutes(e.pool)
	exerciseRegistry(t, reg)
	ctx := context.Background()

	e.tracer.failOn("FROM guard_route ORDER BY")
	if _, err := reg.ListRoutes(ctx); err == nil {
		t.Fatal("list: expected error")
	}
	e.tracer.failOn("INSERT INTO guard_route")
	if err := reg.SaveRoutes(ctx, []domain.RouteRecord{{Method: "GET", Path: "/x", Permission: "x.read"}}, time.Now()); err == nil {
		t.Fatal("save: expected error")
	}
	e.tracer.failOn("UPDATE guard_route")
	if _, err := reg.MarkStale(ctx, time.Now()); err == nil {
		t.Fatal("mark: expected error")
	}
	if _, err := scanRoutes(e.pool.Query(ctx, `SELECT 'GET', '/x', 'x.read', 'maybe'::text, now()`)); err == nil {
		t.Fatal("scan: expected error")
	}
}
