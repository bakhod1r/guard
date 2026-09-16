package application

import (
	"context"
	"errors"
	"testing"

	"github.com/bakhod1r/guard/access/domain"
	"github.com/bakhod1r/guard/access/infrastructure"
)

// TestAdminCannotMintAdminEquivalentAccess covers every path by which a plain
// admin (or any role.write / role.assign / policy.write holder) could reach
// admin-equivalent rights without a super admin.
func TestAdminCannotMintAdminEquivalentAccess(t *testing.T) {
	ctx := context.Background()
	s, m := superFixture(t)
	forbidden := func(name string, err error) {
		t.Helper()
		if !errors.Is(err, domain.ErrForbidden) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	_, err := s.CreateRoleAs(ctx, "adm", "root2", "", "", true)
	forbidden("wildcard role", err)

	if _, err := s.CreateRoleAs(ctx, "adm", "hr", "", "", false); err != nil {
		t.Fatal(err)
	}
	for _, code := range []string{"role.assign", "role.write", "policy.write"} {
		if err := m.CreatePermission(ctx, mustPerm(t, code)); err != nil {
			t.Fatal(err)
		}
		forbidden("grant "+code, s.GrantPermission(ctx, "hr", code, "adm"))
	}
	if err := s.GrantPermission(ctx, "hr", "role.assign", "root"); err != nil {
		t.Fatal(err)
	}
	forbidden("assign privileged custom role", s.AssignRole(ctx, "bob", "hr", "adm", nil))
	forbidden("unassign privileged custom role", s.UnassignRoleAs(ctx, "adm", "bob", "hr"))
	forbidden("revoke management permission", s.RevokePermissionAs(ctx, "adm", "hr", "role.assign"))
	forbidden("delete privileged role", s.DeleteRoleAs(ctx, "adm", "hr"))

	if err := s.AssignRole(ctx, "bob", "hr", "root", nil); err != nil {
		t.Fatal(err)
	}
	forbidden("account change of custom privileged holder", s.AuthorizeAccountChange(ctx, "adm", "bob"))

	all := &domain.Policy{Name: "god", Resource: "*", Action: "*", Effect: domain.Allow, Enabled: true}
	forbidden("allow-all policy", s.SavePolicyAs(ctx, "adm", all))
	if err := s.SavePolicyAs(ctx, "root", all); err != nil {
		t.Fatal(err)
	}
	narrowed := *all
	narrowed.Resource = "invoice"
	forbidden("rewrite privileged policy as ordinary", s.SavePolicyAs(ctx, "adm", &narrowed))
	forbidden("delete privileged policy", s.DeletePolicyAs(ctx, "adm", all.ID))
}

func TestPlainAdminKeepsOrdinaryManagement(t *testing.T) {
	ctx := context.Background()
	s, m := superFixture(t)
	if err := m.CreatePermission(ctx, mustPerm(t, "invoice.read")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateRoleAs(ctx, "adm", "acct", "", "", false); err != nil {
		t.Fatal(err)
	}
	if err := s.GrantPermission(ctx, "acct", "invoice.read", "adm"); err != nil {
		t.Fatal(err)
	}
	if err := s.AssignRole(ctx, "bob", "acct", "adm", nil); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokePermissionAs(ctx, "adm", "acct", "invoice.read"); err != nil {
		t.Fatal(err)
	}
	p := &domain.Policy{Name: "inv", Resource: "invoice", Action: "read", Effect: domain.Allow, Enabled: true}
	if err := s.SavePolicyAs(ctx, "adm", p); err != nil {
		t.Fatal(err)
	}
	if err := s.SavePolicyAs(ctx, "adm", p); err != nil {
		t.Fatal(err)
	}
	if err := s.DeletePolicyAs(ctx, "adm", p.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteRoleAs(ctx, "adm", "acct"); err != nil {
		t.Fatal(err)
	}
	if err := m.CreateRole(ctx, &domain.Role{Name: "sys", Title: "sys", IsSystem: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteRoleAs(ctx, "root", "sys"); !errors.Is(err, domain.ErrSystemRole) {
		t.Fatalf("system role: %v", err)
	}
	for name, err := range map[string]error{
		"delete missing role":   s.DeleteRoleAs(ctx, "adm", "nope"),
		"delete missing policy": s.DeletePolicyAs(ctx, "adm", "00000000-0000-0000-0000-00000000dead"),
	} {
		if err == nil {
			t.Fatalf("%s: want error", name)
		}
	}
	// Unknown role: not privileged, the grant fails on the role itself.
	if err := s.AssignRole(ctx, "bob", "ghost", "adm", nil); !errors.Is(err, domain.ErrRoleNotFound) {
		t.Fatalf("unknown role: %v", err)
	}
}

func mustPerm(t *testing.T, code string) domain.Permission {
	t.Helper()
	p, err := domain.ParsePermission(code)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// policyLookupFails fails Policy lookups.
type policyLookupFails struct{ *infrastructure.Memory }

func (policyLookupFails) Policy(context.Context, string) (*domain.Policy, error) { return nil, errBoom }

func TestPrivilegeChecksSurfaceStorageErrors(t *testing.T) {
	ctx := context.Background()
	f := &failing{Memory: infrastructure.NewMemory()}
	s := NewService(f, f)
	f.fail = true
	if err := s.AssignRole(ctx, "bob", "custom", "adm", nil); !errors.Is(err, errBoom) {
		t.Fatalf("role lookup: %v", err)
	}
	if _, err := s.CreateRoleAs(ctx, "adm", "w", "", "", true); !errors.Is(err, errBoom) {
		t.Fatalf("actor roles: %v", err)
	}
	f.fail = false

	pf := policyLookupFails{infrastructure.NewMemory()}
	s = NewService(pf, pf)
	p := &domain.Policy{ID: "00000000-0000-0000-0000-000000000009", Name: "x", Resource: "invoice", Action: "read", Effect: domain.Allow}
	if err := s.SavePolicyAs(ctx, "adm", p); !errors.Is(err, errBoom) {
		t.Fatalf("old policy lookup: %v", err)
	}
}

func TestSavePolicyAsCreatesWithUnknownID(t *testing.T) {
	s, _ := superFixture(t)
	p := &domain.Policy{ID: "00000000-0000-0000-0000-00000000beef", Name: "x", Resource: "invoice", Action: "read", Effect: domain.Allow}
	if err := s.SavePolicyAs(context.Background(), "adm", p); err != nil {
		t.Fatal(err)
	}
}
