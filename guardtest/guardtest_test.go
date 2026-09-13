package guardtest

import (
	"context"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/bakhod1r/guard"
)

func TestNewSeedsRolesPermissionsAndPolicies(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	g := New(rdb, guard.Config{})
	ctx := context.Background()

	roles, err := g.Access.ListRoles(ctx)
	if err != nil || len(roles) != 2 || roles[0].Name != "admin" || !roles[0].Wildcard || !roles[0].IsSystem ||
		roles[1].Name != "user" || roles[1].Wildcard {
		t.Fatalf("roles: %+v %v", roles, err)
	}

	perms, err := g.Access.ListPermissions(ctx)
	if err != nil || len(perms) != 14 {
		t.Fatalf("permissions: %d %v", len(perms), err)
	}
	codes := map[string]bool{}
	for _, p := range perms {
		codes[p.Code()] = true
	}
	for _, want := range []string{"user.read", "role.assign", "policy.write", "session.revoke", "audit.read", "apikey.revoke"} {
		if !codes[want] {
			t.Errorf("missing permission %s", want)
		}
	}

	policies, err := g.Access.ListPolicies(ctx)
	if err != nil || len(policies) != 3 {
		t.Fatalf("policies: %+v %v", policies, err)
	}
	byID := map[string]bool{}
	for _, p := range policies {
		byID[p.ID] = p.Enabled
	}
	for _, id := range []string{"00000000-0000-0000-0000-000000000001", "00000000-0000-0000-0000-000000000002", "00000000-0000-0000-0000-000000000003"} {
		if !byID[id] {
			t.Errorf("policy %s missing or disabled", id)
		}
	}
	if policies[0].Name != "blocked user denied" {
		t.Errorf("deny policy must sort first by priority, got %q", policies[0].Name)
	}
	if g.Limiter == nil || g.APIKeys == nil || g.Sessions == nil || g.Audit == nil {
		t.Fatal("guard not fully wired")
	}
}
