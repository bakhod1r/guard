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

func TestActiveSuperAdmins(t *testing.T) {
	blocked := map[string]bool{"b": true}
	got := ActiveSuperAdmins([]string{"a", "b", "c", "new"}, "b", func(id string) bool {
		if id == "new" {
			return true // unknown holders are treated as blocked (fail closed)
		}
		return blocked[id]
	})
	if len(got) != 3 || got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Fatalf("got %v", got)
	}
	if err := EnsureOtherSuperAdmin(ActiveSuperAdmins([]string{"a", "b"}, "a", func(id string) bool { return id == "b" }), "a"); !errors.Is(err, ErrLastSuperAdmin) {
		t.Fatal(err)
	}
}

func TestAuthorizeAccountChange(t *testing.T) {
	sa := []Role{{Name: RoleSuperAdmin}}
	adm := []Role{{Name: RoleAdmin}}
	usr := []Role{{Name: "user"}}
	cases := []struct {
		name          string
		actor, target []Role
		self          bool
		want          error
	}{
		{"admin on super admin", adm, sa, false, ErrForbidden},
		{"admin on admin", adm, adm, false, ErrForbidden},
		{"user role on admin", usr, adm, false, ErrForbidden},
		{"admin on user", adm, usr, false, nil},
		{"super admin on super admin", sa, sa, false, nil},
		{"admin on self", adm, adm, true, nil},
	}
	for _, c := range cases {
		if err := AuthorizeAccountChange(c.actor, c.target, c.self); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v want %v", c.name, err, c.want)
		}
	}
}
