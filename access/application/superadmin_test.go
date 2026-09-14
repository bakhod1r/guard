package application

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/bakhod1r/guard/access/domain"
	"github.com/bakhod1r/guard/access/infrastructure"
)

// superFixture: "root" is super_admin, "adm" is admin, "bob" has no role.
func superFixture(t *testing.T) (*Service, *infrastructure.Memory) {
	t.Helper()
	ctx := context.Background()
	m := infrastructure.NewMemory()
	for _, n := range []string{domain.RoleSuperAdmin, domain.RoleAdmin, "user"} {
		r, _ := domain.NewRole(n, n, "", n != "user")
		if err := m.CreateRole(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	s := NewService(m, m)
	if err := s.AssignRole(ctx, "root", domain.RoleSuperAdmin, "", nil); err != nil {
		t.Fatal(err)
	}
	if err := s.AssignRole(ctx, "adm", domain.RoleAdmin, "root", nil); err != nil {
		t.Fatal(err)
	}
	return s, m
}

func TestAssignPrivilegedRoleRequiresSuperAdmin(t *testing.T) {
	s, _ := superFixture(t)
	ctx := context.Background()
	for _, role := range []string{domain.RoleAdmin, domain.RoleSuperAdmin} {
		if err := s.AssignRole(ctx, "bob", role, "adm", nil); !errors.Is(err, domain.ErrForbidden) {
			t.Fatalf("%s by admin: %v", role, err)
		}
	}
	if err := s.AssignRole(ctx, "bob", "user", "adm", nil); err != nil {
		t.Fatal(err)
	}
	if err := s.AssignRole(ctx, "bob", domain.RoleSuperAdmin, "root", nil); err != nil {
		t.Fatal(err)
	}
	exp := time.Now().Add(time.Hour)
	if err := s.AssignRole(ctx, "bob", domain.RoleSuperAdmin, "root", &exp); !errors.Is(err, domain.ErrSuperAdminExpiry) {
		t.Fatal(err)
	}
	if err := s.AssignRole(ctx, "bob", domain.RoleAdmin, "root", &exp); err != nil {
		t.Fatal(err)
	}
}

func TestAssignPrivilegedRoleActorLookupError(t *testing.T) {
	f := &failing{Memory: infrastructure.NewMemory()}
	s := NewService(f, f)
	f.fail = true
	if err := s.AssignRole(context.Background(), "bob", domain.RoleAdmin, "root", nil); !errors.Is(err, errBoom) {
		t.Fatal(err)
	}
	if err := s.UnassignRoleAs(context.Background(), "root", "bob", domain.RoleAdmin); !errors.Is(err, errBoom) {
		t.Fatal(err)
	}
	if _, err := s.IsSuperAdmin(context.Background(), "root"); !errors.Is(err, errBoom) {
		t.Fatal(err)
	}
}

func TestUnassignLastSuperAdmin(t *testing.T) {
	s, _ := superFixture(t)
	ctx := context.Background()
	if err := s.UnassignRole(ctx, "root", domain.RoleSuperAdmin); !errors.Is(err, domain.ErrLastSuperAdmin) {
		t.Fatal(err)
	}
	if err := s.UnassignRoleAs(ctx, "adm", "root", domain.RoleSuperAdmin); !errors.Is(err, domain.ErrForbidden) {
		t.Fatal(err)
	}
	if err := s.UnassignRoleAs(ctx, "adm", "bob", "user"); err != nil {
		t.Fatal(err)
	}
	if err := s.AssignRole(ctx, "bob", domain.RoleSuperAdmin, "root", nil); err != nil {
		t.Fatal(err)
	}
	if got, err := s.SuperAdmins(ctx); err != nil || !reflect.DeepEqual(got, []string{"bob", "root"}) {
		t.Fatalf("%v %v", got, err)
	}
	if err := s.UnassignRoleAs(ctx, "bob", "root", domain.RoleSuperAdmin); err != nil {
		t.Fatal(err)
	}
	if err := s.UnassignRoleAs(ctx, "bob", "bob", domain.RoleSuperAdmin); !errors.Is(err, domain.ErrLastSuperAdmin) {
		t.Fatal(err)
	}
	if err := s.UnassignRole(ctx, "adm", domain.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.IsSuperAdmin(ctx, "bob"); err != nil || !ok {
		t.Fatal(ok, err)
	}
	if ok, _ := s.IsSuperAdmin(ctx, "root"); ok {
		t.Fatal("root revoked")
	}
}

func TestSuperAdminUnsupportedRepository(t *testing.T) {
	m := infrastructure.NewMemory()
	s := NewService(struct{ domain.RoleRepository }{m}, m)
	ctx := context.Background()
	if err := s.UnassignRole(ctx, "root", domain.RoleSuperAdmin); !errors.Is(err, domain.ErrHoldersUnsupported) {
		t.Fatal(err)
	}
	if _, err := s.SuperAdmins(ctx); !errors.Is(err, domain.ErrHoldersUnsupported) {
		t.Fatal(err)
	}
	if err := s.EnsureCanBlock(ctx, "root", nil); !errors.Is(err, domain.ErrHoldersUnsupported) {
		t.Fatal(err)
	}
}

func TestEnsureCanBlock(t *testing.T) {
	s, _ := superFixture(t)
	ctx := context.Background()
	blocked := map[string]bool{}
	isBlocked := func(_ context.Context, id string) (bool, error) {
		if id == "boom" {
			return false, errBoom
		}
		return blocked[id], nil
	}
	if err := s.EnsureCanBlock(ctx, "adm", isBlocked); err != nil {
		t.Fatal(err)
	}
	if err := s.EnsureCanBlock(ctx, "root", isBlocked); !errors.Is(err, domain.ErrLastSuperAdmin) {
		t.Fatal(err)
	}
	_ = s.AssignRole(ctx, "bob", domain.RoleSuperAdmin, "root", nil)
	if err := s.EnsureCanBlock(ctx, "root", isBlocked); err != nil {
		t.Fatal(err)
	}
	blocked["bob"] = true // a blocked super admin cannot rescue the system
	if err := s.EnsureCanBlock(ctx, "root", isBlocked); !errors.Is(err, domain.ErrLastSuperAdmin) {
		t.Fatal(err)
	}
	_ = s.AssignRole(ctx, "boom", domain.RoleSuperAdmin, "root", nil)
	if err := s.EnsureCanBlock(ctx, "root", isBlocked); !errors.Is(err, errBoom) {
		t.Fatal(err)
	}
}
