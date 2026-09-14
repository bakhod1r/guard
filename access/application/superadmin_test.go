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

// lockSpy records LockSuperAdmins calls on top of the memory store.
type lockSpy struct {
	*infrastructure.Memory
	calls int
	err   error
}

func (l *lockSpy) LockSuperAdmins(ctx context.Context, fn func(context.Context) error) error {
	l.calls++
	if l.err != nil {
		return l.err
	}
	return l.Memory.LockSuperAdmins(ctx, fn)
}

func TestLockSuperAdmins(t *testing.T) {
	ctx := context.Background()
	spy := &lockSpy{Memory: infrastructure.NewMemory()}
	s := NewService(spy, spy)
	ran := false
	if err := s.LockSuperAdmins(ctx, func(context.Context) error { ran = true; return nil }); err != nil || !ran || spy.calls != 1 {
		t.Fatal(err, ran, spy.calls)
	}
	spy.err = errBoom
	if err := s.LockSuperAdmins(ctx, func(context.Context) error { t.Error("ran"); return nil }); !errors.Is(err, errBoom) {
		t.Fatal(err)
	}
	// A repository without its own lock still gets the process-wide one.
	m := infrastructure.NewMemory()
	p := NewService(struct{ domain.RoleRepository }{m}, m)
	held, release := make(chan struct{}), make(chan struct{})
	go func() {
		_ = p.LockSuperAdmins(ctx, func(context.Context) error { close(held); <-release; return nil })
	}()
	<-held
	short, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
	defer cancel()
	if err := p.LockSuperAdmins(short, func(context.Context) error { t.Error("ran"); return nil }); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	close(release)
	if err := p.LockSuperAdmins(ctx, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
}

func TestUnassignSuperAdminCountsOnlyActive(t *testing.T) {
	s, _ := superFixture(t)
	ctx := context.Background()
	_ = s.AssignRole(ctx, "bob", domain.RoleSuperAdmin, "root", nil)
	blocked := map[string]bool{"bob": true}
	s.SetSuperAdminBlocked(func(_ context.Context, id string) (bool, error) {
		if id == "boom" {
			return false, errBoom
		}
		return blocked[id], nil
	})
	// bob is banned: root is the last active super admin.
	if err := s.UnassignRoleAs(ctx, "root", "root", domain.RoleSuperAdmin); !errors.Is(err, domain.ErrLastSuperAdmin) {
		t.Fatal(err)
	}
	// Removing the banned holder does not shrink the active set.
	if err := s.UnassignRoleAs(ctx, "root", "bob", domain.RoleSuperAdmin); err != nil {
		t.Fatal(err)
	}
	_ = s.AssignRole(ctx, "boom", domain.RoleSuperAdmin, "root", nil)
	if err := s.UnassignRole(ctx, "root", domain.RoleSuperAdmin); !errors.Is(err, errBoom) {
		t.Fatal(err)
	}
	blocked["boom"] = false
	s.SetSuperAdminBlocked(nil) // nil: every holder counts
	if err := s.UnassignRole(ctx, "boom", domain.RoleSuperAdmin); err != nil {
		t.Fatal(err)
	}
}

func TestUnassignSuperAdminLockError(t *testing.T) {
	spy := &lockSpy{Memory: infrastructure.NewMemory(), err: errBoom}
	s := NewService(spy, spy)
	if err := s.UnassignRole(context.Background(), "root", domain.RoleSuperAdmin); !errors.Is(err, errBoom) {
		t.Fatal(err)
	}
	if err := s.EnsureCanBlock(context.Background(), "root", nil); err != nil {
		t.Fatal(err) // no holders: nothing to protect
	}
}

type holdersFail struct{ *infrastructure.Memory }

func (holdersFail) RoleHolders(context.Context, string) ([]string, error) { return nil, errBoom }

func TestUnassignSuperAdminHoldersError(t *testing.T) {
	h := holdersFail{infrastructure.NewMemory()}
	s := NewService(h, h)
	if err := s.UnassignRole(context.Background(), "root", domain.RoleSuperAdmin); !errors.Is(err, errBoom) {
		t.Fatal(err)
	}
}

// failFor fails GrantsOf only for one user id.
type failFor struct {
	*infrastructure.Memory
	id string
}

func (f *failFor) GrantsOf(ctx context.Context, u string) ([]domain.RoleGrant, error) {
	if u == f.id {
		return nil, errBoom
	}
	return f.Memory.GrantsOf(ctx, u)
}

func TestAuthorizeAccountChange(t *testing.T) {
	s, m := superFixture(t)
	ctx := context.Background()
	if err := s.AssignRole(ctx, "adm2", domain.RoleAdmin, "root", nil); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"root", "adm2"} {
		if err := s.AuthorizeAccountChange(ctx, "adm", target); !errors.Is(err, domain.ErrForbidden) {
			t.Fatalf("adm on %s: %v", target, err)
		}
	}
	for _, c := range [][2]string{{"adm", "bob"}, {"adm", "adm"}, {"root", "adm"}, {"bob", "bob"}} {
		if err := s.AuthorizeAccountChange(ctx, c[0], c[1]); err != nil {
			t.Fatalf("%s on %s: %v", c[0], c[1], err)
		}
	}
	for _, id := range []string{"adm", "root"} {
		f := &failFor{Memory: m, id: id}
		if err := NewService(f, f).AuthorizeAccountChange(ctx, "adm", "root"); !errors.Is(err, errBoom) {
			t.Fatalf("lookup %s: %v", id, err)
		}
	}
}
