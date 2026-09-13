package infrastructure

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bakhod1r/guard/access/domain"
)

func TestMemoryRoles(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	perms := []domain.Permission{{Resource: "doc", Action: "read"}}
	must(t, m.CreateRole(ctx, &domain.Role{Name: "b", Permissions: perms}))
	must(t, m.CreateRole(ctx, &domain.Role{Name: "a"}))
	perms[0].Action = "mutated"
	if err := m.CreateRole(ctx, &domain.Role{Name: "a"}); !errors.Is(err, domain.ErrRoleExists) {
		t.Fatalf("got %v", err)
	}
	r, err := m.Role(ctx, "b")
	if err != nil || r.Permissions[0].Action != "read" {
		t.Fatalf("stored role not copied: %+v %v", r, err)
	}
	if _, err := m.Role(ctx, "zz"); !errors.Is(err, domain.ErrRoleNotFound) {
		t.Fatalf("got %v", err)
	}
	list, _ := m.ListRoles(ctx)
	if len(list) != 2 || list[0].Name != "a" {
		t.Fatalf("got %+v", list)
	}
	must(t, m.AssignRole(ctx, "u1", "a", "", nil))
	must(t, m.DeleteRole(ctx, "a"))
	if err := m.DeleteRole(ctx, "a"); !errors.Is(err, domain.ErrRoleNotFound) {
		t.Fatalf("got %v", err)
	}
	if g, _ := m.GrantsOf(ctx, "u1"); len(g) != 0 {
		t.Fatalf("grant survived role deletion: %+v", g)
	}
}

func TestMemoryPermissions(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	read := domain.Permission{Resource: "doc", Action: "read", Description: "d"}
	write := domain.Permission{Resource: "doc", Action: "write"}
	must(t, m.CreatePermission(ctx, write))
	must(t, m.CreatePermission(ctx, read))
	if l, _ := m.ListPermissions(ctx); len(l) != 2 || l[0].Code() != "doc.read" {
		t.Fatalf("got %+v", l)
	}
	if err := m.GrantPermission(ctx, "r", read, ""); !errors.Is(err, domain.ErrRoleNotFound) {
		t.Fatalf("got %v", err)
	}
	must(t, m.CreateRole(ctx, &domain.Role{Name: "r"}))
	if err := m.GrantPermission(ctx, "r", domain.Permission{Resource: "x", Action: "y"}, ""); !errors.Is(err, domain.ErrPermissionNotFound) {
		t.Fatalf("got %v", err)
	}
	must(t, m.GrantPermission(ctx, "r", read, ""))
	must(t, m.GrantPermission(ctx, "r", read, "")) // idempotent
	must(t, m.GrantPermission(ctx, "r", write, ""))
	must(t, m.RevokePermission(ctx, "r", write))
	must(t, m.RevokePermission(ctx, "missing", write))
	r, _ := m.Role(ctx, "r")
	if len(r.Permissions) != 1 || r.Permissions[0].Description != "d" {
		t.Fatalf("got %+v", r.Permissions)
	}
}

func TestMemoryGrants(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	if err := m.AssignRole(ctx, "u1", "nope", "", nil); !errors.Is(err, domain.ErrRoleNotFound) {
		t.Fatalf("got %v", err)
	}
	must(t, m.CreateRole(ctx, &domain.Role{Name: "b"}))
	must(t, m.CreateRole(ctx, &domain.Role{Name: "a"}))
	exp := time.Now().Add(time.Hour)
	must(t, m.AssignRole(ctx, "u1", "b", "", &exp))
	must(t, m.AssignRole(ctx, "u1", "a", "", nil))
	// A grant whose role vanished from the role map is skipped.
	m.grants["u1"]["ghost"] = nil
	g, err := m.GrantsOf(ctx, "u1")
	if err != nil || len(g) != 2 || g[0].Role.Name != "a" || g[1].ExpiresAt == nil {
		t.Fatalf("got %+v %v", g, err)
	}
	must(t, m.UnassignRole(ctx, "u1", "a"))
	must(t, m.UnassignRole(ctx, "nobody", "a"))
	if g, _ := m.GrantsOf(ctx, "u1"); len(g) != 1 {
		t.Fatalf("got %+v", g)
	}
}

func TestMemoryPolicies(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	p1 := &domain.Policy{ID: "1", Name: "zeta", Resource: "*", Action: "read", Priority: 10, Enabled: true}
	p2 := &domain.Policy{ID: "2", Name: "alpha", Resource: "doc", Action: "*", Priority: 10, Enabled: true}
	p3 := &domain.Policy{ID: "3", Name: "first", Resource: "doc", Action: "read", Priority: 1, Enabled: false}
	p4 := &domain.Policy{ID: "4", Name: "other", Resource: "user", Action: "read", Priority: 5, Enabled: true}
	for _, p := range []*domain.Policy{p1, p2, p3, p4} {
		must(t, m.SavePolicy(ctx, p))
	}
	must(t, m.SavePolicy(ctx, p1)) // same id, same name: update
	if err := m.SavePolicy(ctx, &domain.Policy{ID: "9", Name: "zeta"}); !errors.Is(err, domain.ErrPolicyNameTaken) {
		t.Fatalf("got %v", err)
	}
	list, _ := m.ListPolicies(ctx)
	if len(list) != 4 || list[0].Name != "first" || list[2].Name != "alpha" {
		t.Fatalf("got %+v", list)
	}
	app, _ := m.ApplicablePolicies(ctx, "doc", "read")
	if len(app) != 2 || app[0].Name != "alpha" || app[1].Name != "zeta" {
		t.Fatalf("got %+v", app)
	}
	if p, err := m.Policy(ctx, "2"); err != nil || p.Name != "alpha" {
		t.Fatalf("got %+v %v", p, err)
	}
	must(t, m.DeletePolicy(ctx, "2"))
	if _, err := m.Policy(ctx, "2"); !errors.Is(err, domain.ErrPolicyNotFound) {
		t.Fatalf("got %v", err)
	}
	if err := m.DeletePolicy(ctx, "2"); !errors.Is(err, domain.ErrPolicyNotFound) {
		t.Fatalf("got %v", err)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
