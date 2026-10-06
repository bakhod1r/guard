package application

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/bakhod1r/guard/access/domain"
	"github.com/bakhod1r/guard/access/infrastructure"
)

func TestListPoliciesForRole(t *testing.T) {
	ctx := context.Background()
	mem := infrastructure.NewMemory()
	s := NewService(mem, mem)
	for _, n := range []string{"editor", "author"} {
		if _, err := s.CreateRole(ctx, n, n, "", false); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range []domain.Policy{
		{Name: "global", Resource: "*", Action: "*", Effect: domain.Allow, Priority: 50, Enabled: true},
		{Name: "editors", Resource: "post", Action: "edit", Effect: domain.Allow, Priority: 10, Enabled: true, Roles: []string{"editor"}},
		{Name: "authors", Resource: "post", Action: "edit", Effect: domain.Deny, Priority: 5, Enabled: true, Roles: []string{"author"}},
	} {
		if err := s.SavePolicy(ctx, &p); err != nil {
			t.Fatal(err)
		}
	}
	list, err := s.ListPoliciesForRole(ctx, "editor")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, p := range list {
		names = append(names, p.Name)
	}
	if !reflect.DeepEqual(names, []string{"editors", "global"}) {
		t.Fatalf("names = %v", names)
	}
	if _, err := s.ListPoliciesForRole(ctx, "ghost"); !errors.Is(err, domain.ErrRoleNotFound) {
		t.Fatalf("unknown role: %v", err)
	}
}

func TestMigrateRoleConditions(t *testing.T) {
	ctx := context.Background()
	mem := infrastructure.NewMemory()
	s := NewService(mem, mem)
	for _, n := range []string{"editor", "author"} {
		if _, err := s.CreateRole(ctx, n, n, "", false); err != nil {
			t.Fatal(err)
		}
	}
	gate := func(roles ...string) domain.ConditionGroup {
		g := domain.ConditionGroup{Operator: domain.Or}
		for _, r := range roles {
			g.Conditions = append(g.Conditions, domain.Condition{Field: "user.roles", Operator: domain.OpContains, Value: []string{r}})
		}
		return g
	}
	body := domain.ConditionGroup{Operator: domain.And, Conditions: []domain.Condition{{Field: "resource.owner_id", Operator: domain.OpEq, Value: []string{"$user.id"}}}}
	legacy := &domain.Policy{Name: "legacy", Resource: "post", Action: "edit", Effect: domain.Allow, Enabled: true,
		Root: &domain.ConditionGroup{Operator: domain.And, Groups: []domain.ConditionGroup{gate("editor", "author"), body}}}
	ghost := &domain.Policy{Name: "ghost", Resource: "post", Action: "edit", Effect: domain.Allow, Enabled: true,
		Root: &domain.ConditionGroup{Operator: domain.And, Groups: []domain.ConditionGroup{gate("removed")}}}
	plain := &domain.Policy{Name: "plain", Resource: "post", Action: "edit", Effect: domain.Allow, Enabled: true, Root: &body}
	for _, p := range []*domain.Policy{legacy, ghost, plain} {
		if err := s.SavePolicy(ctx, p); err != nil {
			t.Fatal(err)
		}
	}

	n, err := s.MigrateRoleConditions(ctx)
	if err != nil || n != 1 {
		t.Fatalf("first run: %d %v", n, err)
	}
	got, _ := s.Policy(ctx, legacy.ID)
	if !reflect.DeepEqual(got.Roles, []string{"author", "editor"}) || !reflect.DeepEqual(*got.Root, body) {
		t.Fatalf("migrated: %+v", got)
	}
	if got, _ := s.Policy(ctx, ghost.ID); got.Roles != nil || len(got.Root.Groups) != 1 {
		t.Fatalf("policy with unknown role must stay legacy: %+v", got)
	}
	if n, err := s.MigrateRoleConditions(ctx); err != nil || n != 0 {
		t.Fatalf("second run: %d %v", n, err)
	}
}
