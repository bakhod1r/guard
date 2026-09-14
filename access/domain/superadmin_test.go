package domain

import (
	"errors"
	"testing"
)

func TestIsPrivilegedRole(t *testing.T) {
	for name, want := range map[string]bool{RoleSuperAdmin: true, RoleAdmin: true, "user": false, "": false} {
		if got := IsPrivilegedRole(name); got != want {
			t.Errorf("IsPrivilegedRole(%q)=%v", name, got)
		}
	}
}

func TestHasSuperAdmin(t *testing.T) {
	if HasSuperAdmin(nil) || HasSuperAdmin([]Role{{Name: RoleAdmin, Wildcard: true}}) {
		t.Fatal("admin is not super admin")
	}
	if !HasSuperAdmin([]Role{{Name: "user"}, {Name: RoleSuperAdmin}}) {
		t.Fatal("want super admin")
	}
}

func TestAuthorizeRoleChange(t *testing.T) {
	admin := []Role{{Name: RoleAdmin, Wildcard: true}}
	super := []Role{{Name: RoleSuperAdmin, Wildcard: true}}
	if err := AuthorizeRoleChange(admin, "user"); err != nil {
		t.Fatal(err)
	}
	for _, r := range []string{RoleAdmin, RoleSuperAdmin} {
		if err := AuthorizeRoleChange(admin, r); !errors.Is(err, ErrForbidden) {
			t.Fatalf("%s: %v", r, err)
		}
		if err := AuthorizeRoleChange(super, r); err != nil {
			t.Fatalf("%s: %v", r, err)
		}
	}
}

func TestEnsureOtherSuperAdmin(t *testing.T) {
	cases := []struct {
		holders []string
		user    string
		want    error
	}{
		{nil, "1", nil},
		{[]string{"2"}, "1", nil},
		{[]string{"1"}, "1", ErrLastSuperAdmin},
		{[]string{"1", "2"}, "1", nil},
	}
	for _, c := range cases {
		if err := EnsureOtherSuperAdmin(c.holders, c.user); !errors.Is(err, c.want) {
			t.Errorf("%v/%s: %v", c.holders, c.user, err)
		}
	}
}
