package domain

import (
	"errors"
	"testing"
)

func TestRolePrivileged(t *testing.T) {
	cases := map[string]struct {
		role Role
		want bool
	}{
		"admin by name":       {Role{Name: RoleAdmin}, true},
		"super admin":         {Role{Name: RoleSuperAdmin}, true},
		"custom wildcard":     {Role{Name: "root", Wildcard: true}, true},
		"holds role.assign":   {Role{Name: "hr", Permissions: []Permission{{Resource: "role", Action: "assign"}}}, true},
		"holds role.write":    {Role{Name: "hr", Permissions: []Permission{{Resource: "role", Action: "write"}}}, true},
		"holds policy.write":  {Role{Name: "sec", Permissions: []Permission{{Resource: "policy", Action: "write"}}}, true},
		"business permission": {Role{Name: "acct", Permissions: []Permission{{Resource: "invoice", Action: "write"}}}, false},
	}
	for name, tc := range cases {
		if got := tc.role.Privileged(); got != tc.want {
			t.Errorf("%s: got %v", name, got)
		}
	}
}

func TestPolicyPrivileged(t *testing.T) {
	for res, want := range map[string]bool{"*": true, "role": true, "policy": true, "invoice": false, "user": false} {
		if got := (Policy{Resource: res}).Privileged(); got != want {
			t.Errorf("%s: got %v", res, got)
		}
	}
}

func TestAuthorizeAccountChangeProtectsCustomPrivilegedRoles(t *testing.T) {
	root := []Role{{Name: "root", Wildcard: true}}
	if err := AuthorizeAccountChange([]Role{{Name: RoleAdmin, Wildcard: true}}, root, false); !errors.Is(err, ErrForbidden) {
		t.Fatalf("admin changing custom wildcard holder: %v", err)
	}
	if err := RequireSuperAdmin([]Role{{Name: RoleAdmin}}, true); !errors.Is(err, ErrForbidden) {
		t.Fatal(err)
	}
	if RequireSuperAdmin([]Role{{Name: RoleSuperAdmin}}, true) != nil || RequireSuperAdmin(nil, false) != nil {
		t.Fatal("super admin or unprivileged change must pass")
	}
}
