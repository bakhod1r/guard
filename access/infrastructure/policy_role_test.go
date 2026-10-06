package infrastructure

import (
	"context"
	"reflect"
	"testing"

	"github.com/google/uuid"

	"github.com/bakhod1r/guard/access/domain"
)

type accessStore interface {
	domain.RoleRepository
	domain.PolicyRepository
}

// testPolicyRoles runs the role-binding contract against any store.
func testPolicyRoles(t *testing.T, s accessStore) {
	ctx := context.Background()
	for _, n := range []string{"author", "editor"} {
		if err := s.CreateRole(ctx, &domain.Role{Name: n, Title: n}); err != nil {
			t.Fatal(err)
		}
	}
	bound := &domain.Policy{ID: uuid.Must(uuid.NewV7()).String(), Name: "bound", Resource: "rbtest", Action: "edit",
		Effect: domain.Allow, Priority: 10, Enabled: true, Roles: []string{"author", "editor"},
		Root: &domain.ConditionGroup{Operator: domain.And, Conditions: []domain.Condition{{Field: "user.id", Operator: domain.OpEq, Value: []string{"1"}}}}}
	single := &domain.Policy{ID: uuid.Must(uuid.NewV7()).String(), Name: "single", Resource: "rbtest", Action: "edit",
		Effect: domain.Allow, Priority: 20, Enabled: true, Roles: []string{"author"}}
	global := &domain.Policy{ID: uuid.Must(uuid.NewV7()).String(), Name: "global", Resource: "rbtest", Action: "edit",
		Effect: domain.Deny, Priority: 30, Enabled: true}
	for _, p := range []*domain.Policy{bound, single, global} {
		if err := s.SavePolicy(ctx, p); err != nil {
			t.Fatal(err)
		}
	}

	got, err := s.Policy(ctx, bound.ID)
	if err != nil || !reflect.DeepEqual(got.Roles, []string{"author", "editor"}) || got.Root == nil {
		t.Fatalf("Policy: %+v %v", got, err)
	}
	all, err := s.ApplicablePolicies(ctx, "rbtest", "edit")
	var list []domain.Policy
	for _, p := range all {
		if p.Resource == "rbtest" {
			list = append(list, p)
		}
	}
	if err != nil || len(list) != 3 || list[2].Roles != nil || len(list[1].Roles) != 1 {
		t.Fatalf("ApplicablePolicies: %+v %v", list, err)
	}

	// Unknown role: rejected, previous binding kept.
	bad := *bound
	bad.Roles = []string{"ghost", "editor"}
	wantErr(t, s.SavePolicy(ctx, &bad), domain.ErrRoleNotFound)
	if got, _ := s.Policy(ctx, bound.ID); !reflect.DeepEqual(got.Roles, []string{"author", "editor"}) {
		t.Fatalf("failed save changed roles: %v", got.Roles)
	}

	// Rebinding replaces the set.
	bound.Roles = []string{"editor"}
	if err := s.SavePolicy(ctx, bound); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Policy(ctx, bound.ID); !reflect.DeepEqual(got.Roles, []string{"editor"}) {
		t.Fatalf("rebind: %v", got.Roles)
	}

	// Deleting a role drops its bindings; a policy losing its last role is
	// disabled instead of widening to everyone.
	bound.Roles = []string{"author", "editor"}
	if err := s.SavePolicy(ctx, bound); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteRole(ctx, "author"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Policy(ctx, bound.ID); !reflect.DeepEqual(got.Roles, []string{"editor"}) || !got.Enabled {
		t.Fatalf("bound after delete: %+v", got)
	}
	if got, _ := s.Policy(ctx, single.ID); got.Roles != nil || got.Enabled {
		t.Fatalf("single after delete must be unbound and disabled: %+v", got)
	}
	if got, _ := s.Policy(ctx, global.ID); !got.Enabled {
		t.Fatal("global policy must stay enabled")
	}
}

func TestMemoryPolicyRoles(t *testing.T) { testPolicyRoles(t, NewMemory()) }

func TestPostgresPolicyRoles(t *testing.T) { testPolicyRoles(t, newPG(t).repo) }

func TestCachedPolicyRolesInvalidation(t *testing.T) {
	ctx := context.Background()
	mem := NewMemory()
	c := NewCached(mem, mem, nil, CacheOptions{})
	_ = c.CreateRole(ctx, &domain.Role{Name: "editor", Title: "editor"})
	p := &domain.Policy{ID: "p1", Name: "p", Resource: "post", Action: "edit", Effect: domain.Allow, Enabled: true, Roles: []string{"editor"}}
	if err := c.SavePolicy(ctx, p); err != nil {
		t.Fatal(err)
	}
	if l, _ := c.ApplicablePolicies(ctx, "post", "edit"); len(l) != 1 || len(l[0].Roles) != 1 {
		t.Fatalf("warm: %+v", l)
	}
	if err := c.DeleteRole(ctx, "editor"); err != nil {
		t.Fatal(err)
	}
	// The policy lost its only role, so it is disabled and no longer applicable.
	if l, _ := c.ApplicablePolicies(ctx, "post", "edit"); len(l) != 0 {
		t.Fatalf("stale after role delete: %+v", l)
	}
}
