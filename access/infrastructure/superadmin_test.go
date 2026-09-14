package infrastructure

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/bakhod1r/guard/access/domain"
)

type holderRepo interface {
	domain.RoleRepository
	domain.RoleHolderRepository
}

// exerciseHolders runs the holder contract against users "1" and "2".
func exerciseHolders(t *testing.T, repo holderRepo) {
	t.Helper()
	ctx := context.Background()
	h, err := repo.RoleHolders(ctx, "missing_role")
	if err != nil || len(h) != 0 {
		t.Fatalf("missing role: %v %v", h, err)
	}
	if err := repo.UnassignRoleChecked(ctx, "1", "missing_role", func([]string) error { return errors.New("not called") }); err != nil {
		t.Fatal(err)
	}
	r, _ := domain.NewRole("boss", "Boss", "", true)
	must(t, repo.CreateRole(ctx, r))
	soon := time.Now().Add(300 * time.Millisecond)
	must(t, repo.AssignRole(ctx, "1", "boss", "", nil))
	must(t, repo.AssignRole(ctx, "2", "boss", "", &soon))
	time.Sleep(400 * time.Millisecond)
	if h, err := repo.RoleHolders(ctx, "boss"); err != nil || !reflect.DeepEqual(h, []string{"1"}) {
		t.Fatalf("holders %v %v", h, err)
	}
	must(t, repo.AssignRole(ctx, "2", "boss", "", nil))
	var seen []string
	must(t, repo.UnassignRoleChecked(ctx, "2", "boss", func(h []string) error { seen = h; return nil }))
	if !reflect.DeepEqual(seen, []string{"1", "2"}) {
		t.Fatalf("seen %v", seen)
	}
	stop := errors.New("stop")
	if err := repo.UnassignRoleChecked(ctx, "1", "boss", func([]string) error { return stop }); !errors.Is(err, stop) {
		t.Fatal(err)
	}
	if h, _ := repo.RoleHolders(ctx, "boss"); !reflect.DeepEqual(h, []string{"1"}) {
		t.Fatalf("after: %v", h)
	}
	must(t, repo.UnassignRoleChecked(ctx, "", "boss", func([]string) error { return nil }))

	// Concurrent checked removals of two holders keep at least one.
	must(t, repo.AssignRole(ctx, "2", "boss", "", nil))
	var wg sync.WaitGroup
	for _, u := range []string{"1", "2"} {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			_ = repo.UnassignRoleChecked(ctx, u, "boss", func(h []string) error { return domain.EnsureOtherSuperAdmin(h, u) })
		}(u)
	}
	wg.Wait()
	if h, _ := repo.RoleHolders(ctx, "boss"); len(h) != 1 {
		t.Fatalf("race left %v", h)
	}
}

func TestMemoryRoleHolders(t *testing.T) { exerciseHolders(t, NewMemory()) }

func TestPostgresRoleHolders(t *testing.T) {
	e := newPG(t)
	exerciseHolders(t, e.repo)
	ctx := context.Background()
	chk := func([]string) error { return nil }
	// non-numeric id against bigint host ids is a no-op
	must(t, e.repo.UnassignRoleChecked(ctx, "abc", "boss", chk))
	for _, marker := range []string{"SELECT id FROM guard_role WHERE name=$1 FOR UPDATE", "ORDER BY 1", "DELETE FROM guard_user_role WHERE role_id=$1 AND user_id::text"} {
		e.tracer.failOn(marker)
		wantAnyErr(t, e.repo.UnassignRoleChecked(ctx, "1", "boss", chk))
	}
	e.tracer.failOn("SELECT id FROM guard_role WHERE name=$1")
	if _, err := e.repo.RoleHolders(ctx, "boss"); err == nil {
		t.Fatal("want error")
	}
	e.tracer.failOn("ORDER BY 1")
	if _, err := e.repo.RoleHolders(ctx, "boss"); err == nil {
		t.Fatal("want error")
	}
}

type plainRoles struct{ domain.RoleRepository }

func TestCachedRoleHolders(t *testing.T) {
	o := newOrigin(t)
	c := NewCached(o, o, nil, CacheOptions{})
	ctx := context.Background()
	must(t, c.AssignRole(ctx, "u2", "admin", "", nil))
	if _, err := c.GrantsOf(ctx, "u2"); err != nil {
		t.Fatal(err)
	}
	if h, err := c.RoleHolders(ctx, "admin"); err != nil || !reflect.DeepEqual(h, []string{"u2"}) {
		t.Fatalf("%v %v", h, err)
	}
	must(t, c.UnassignRoleChecked(ctx, "u2", "admin", func([]string) error { return nil }))
	if g, _ := c.GrantsOf(ctx, "u2"); len(g) != 0 {
		t.Fatalf("stale grants %v", g)
	}
	p := NewCached(plainRoles{o}, o, nil, CacheOptions{})
	if _, err := p.RoleHolders(ctx, "admin"); !errors.Is(err, domain.ErrHoldersUnsupported) {
		t.Fatal(err)
	}
	if err := p.UnassignRoleChecked(ctx, "u2", "admin", nil); !errors.Is(err, domain.ErrHoldersUnsupported) {
		t.Fatal(err)
	}
}
