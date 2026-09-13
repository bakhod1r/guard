package application

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/bakhod1r/guard/access/domain"
	"github.com/bakhod1r/guard/access/infrastructure"
)

var errBoom = errors.New("storage down")

// failing wraps Memory and returns errBoom from every repository call when fail is set.
type failing struct {
	*infrastructure.Memory
	fail bool
}

func (f *failing) GrantsOf(ctx context.Context, u string) ([]domain.RoleGrant, error) {
	if f.fail {
		return nil, errBoom
	}
	return f.Memory.GrantsOf(ctx, u)
}

func (f *failing) ApplicablePolicies(ctx context.Context, r, a string) ([]domain.Policy, error) {
	if f.fail {
		return nil, errBoom
	}
	return f.Memory.ApplicablePolicies(ctx, r, a)
}

func (f *failing) CreateRole(ctx context.Context, r *domain.Role) error {
	if f.fail {
		return errBoom
	}
	return f.Memory.CreateRole(ctx, r)
}

func (f *failing) Role(ctx context.Context, n string) (*domain.Role, error) {
	if f.fail {
		return nil, errBoom
	}
	return f.Memory.Role(ctx, n)
}

func newSvc() (*Service, *failing, time.Time) {
	mem := &failing{Memory: infrastructure.NewMemory()}
	s := NewService(mem, mem)
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	return s, mem, now
}

func TestActiveRolesSkipsExpiredGrants(t *testing.T) {
	ctx := context.Background()
	s, _, now := newSvc()
	for _, n := range []string{"old", "live", "forever"} {
		if _, err := s.CreateRole(ctx, n, "", "", false); err != nil {
			t.Fatal(err)
		}
	}
	past, future := now.Add(-time.Hour), now.Add(time.Hour)
	must(t, s.AssignRole(ctx, "u1", "old", "", &past))
	must(t, s.AssignRole(ctx, "u1", "live", "", &future))
	must(t, s.AssignRole(ctx, "u1", "forever", "", nil))
	roles, err := s.ActiveRoles(ctx, "u1")
	if err != nil || len(roles) != 2 || roles[0].Name != "forever" || roles[1].Name != "live" {
		t.Fatalf("got %+v %v", roles, err)
	}
	grants, err := s.Grants(ctx, "u1")
	if err != nil || len(grants) != 3 {
		t.Fatalf("got %+v %v", grants, err)
	}
	must(t, s.UnassignRole(ctx, "u1", "old"))
	if grants, _ := s.Grants(ctx, "u1"); len(grants) != 2 {
		t.Fatalf("unassign ignored: %+v", grants)
	}
}

func TestAuthorizeLoadsRolesAndInjectsNow(t *testing.T) {
	ctx := context.Background()
	s, _, now := newSvc()
	_, err := s.CreateRole(ctx, "editor", "", "", false)
	must(t, err)
	_, err = s.CreatePermission(ctx, "doc.read", "read docs")
	must(t, err)
	must(t, s.GrantPermission(ctx, "editor", "doc.read", ""))
	must(t, s.AssignRole(ctx, "u1", "editor", "", nil))

	d, err := s.Authorize(ctx, domain.Request{Subject: domain.Subject{ID: "u1"}, Action: "read", Resource: domain.Resource{Type: "doc"}})
	if err != nil || !d.Allowed || d.Reason != "granted by role editor" {
		t.Fatalf("roles not loaded: %+v %v", d, err)
	}

	// Policy denying before "now" proves env.now is injected from the clock.
	p := &domain.Policy{Name: "after-cutoff", Resource: "doc", Action: "read", Effect: domain.Deny, Enabled: true,
		Root: &domain.ConditionGroup{Conditions: []domain.Condition{{Field: "env.now", Operator: domain.OpGte, Value: []string{now.Add(-time.Minute).Format(time.RFC3339)}}}}}
	must(t, s.SavePolicy(ctx, p))
	d, err = s.Authorize(ctx, domain.Request{Subject: domain.Subject{ID: "u1"}, Action: "read", Resource: domain.Resource{Type: "doc"}})
	if err != nil || d.Allowed {
		t.Fatalf("env.now not injected: %+v %v", d, err)
	}
	// Caller-supplied now is kept; supplied roles are not reloaded.
	d, err = s.Authorize(ctx, domain.Request{Subject: domain.Subject{ID: "u1", Roles: []domain.Role{}}, Action: "read",
		Resource: domain.Resource{Type: "doc"}, Environment: map[string]any{"now": "2000-01-01T00:00:00Z"}})
	if err != nil || d.Allowed || d.Reason != "no matching permission or policy" {
		t.Fatalf("explicit env.now or roles overridden: %+v %v", d, err)
	}
}

func TestAuthorizePropagatesRepositoryErrors(t *testing.T) {
	ctx := context.Background()
	s, mem, _ := newSvc()
	mem.fail = true
	if _, err := s.Authorize(ctx, domain.Request{Subject: domain.Subject{ID: "u1"}}); !errors.Is(err, errBoom) {
		t.Fatalf("grants error lost: %v", err)
	}
	if _, err := s.Authorize(ctx, domain.Request{Subject: domain.Subject{Roles: []domain.Role{}}}); !errors.Is(err, errBoom) {
		t.Fatalf("policies error lost: %v", err)
	}
	if _, err := s.ActiveRoles(ctx, "u1"); !errors.Is(err, errBoom) {
		t.Fatalf("got %v", err)
	}
}

func TestRoleUseCases(t *testing.T) {
	ctx := context.Background()
	s, mem, _ := newSvc()
	if _, err := s.CreateRole(ctx, "X", "", "", false); !errors.Is(err, domain.ErrInvalidName) {
		t.Fatalf("got %v", err)
	}
	r, err := s.CreateRole(ctx, "viewer", "Viewer", "", false)
	if err != nil || r.Name != "viewer" {
		t.Fatalf("got %+v %v", r, err)
	}
	if got, err := s.Role(ctx, "viewer"); err != nil || got.Title != "Viewer" {
		t.Fatalf("got %+v %v", got, err)
	}
	if list, err := s.ListRoles(ctx); err != nil || len(list) != 1 {
		t.Fatalf("got %+v %v", list, err)
	}
	sys := &domain.Role{Name: "admin", IsSystem: true}
	must(t, mem.Memory.CreateRole(ctx, sys))
	if err := s.DeleteRole(ctx, "admin"); !errors.Is(err, domain.ErrSystemRole) {
		t.Fatalf("system role deleted: %v", err)
	}
	if err := s.DeleteRole(ctx, "missing"); !errors.Is(err, domain.ErrRoleNotFound) {
		t.Fatalf("got %v", err)
	}
	must(t, s.DeleteRole(ctx, "viewer"))

	mem.fail = true
	if _, err := s.CreateRole(ctx, "other", "", "", false); !errors.Is(err, errBoom) {
		t.Fatalf("got %v", err)
	}
}

func TestPermissionUseCases(t *testing.T) {
	ctx := context.Background()
	s, _, _ := newSvc()
	if _, err := s.CreatePermission(ctx, "bad", ""); !errors.Is(err, domain.ErrInvalidPermission) {
		t.Fatalf("got %v", err)
	}
	p, err := s.CreatePermission(ctx, "doc.read", "desc")
	if err != nil || p.Description != "desc" {
		t.Fatalf("got %+v %v", p, err)
	}
	if list, err := s.ListPermissions(ctx); err != nil || len(list) != 1 {
		t.Fatalf("got %+v %v", list, err)
	}
	if err := s.GrantPermission(ctx, "r", "bad", ""); !errors.Is(err, domain.ErrInvalidPermission) {
		t.Fatalf("got %v", err)
	}
	if err := s.RevokePermission(ctx, "r", "bad"); !errors.Is(err, domain.ErrInvalidPermission) {
		t.Fatalf("got %v", err)
	}
	_, err = s.CreateRole(ctx, "editor", "", "", false)
	must(t, err)
	must(t, s.GrantPermission(ctx, "editor", "doc.read", ""))
	must(t, s.RevokePermission(ctx, "editor", "doc.read"))
	if r, _ := s.Role(ctx, "editor"); len(r.Permissions) != 0 {
		t.Fatalf("revoke ignored: %+v", r)
	}
}

func TestPolicyUseCases(t *testing.T) {
	ctx := context.Background()
	s, _, _ := newSvc()
	if err := s.SavePolicy(ctx, &domain.Policy{Name: "x", Effect: "nope"}); !errors.Is(err, domain.ErrInvalidPolicy) {
		t.Fatalf("got %v", err)
	}
	p := &domain.Policy{Name: "p", Resource: "*", Action: "*", Effect: domain.Allow}
	must(t, s.SavePolicy(ctx, p))
	if _, err := uuid.Parse(p.ID); err != nil {
		t.Fatalf("id not generated: %q", p.ID)
	}
	fixed := &domain.Policy{ID: "keep-me", Name: "q", Resource: "*", Action: "*", Effect: domain.Deny}
	must(t, s.SavePolicy(ctx, fixed))
	if fixed.ID != "keep-me" {
		t.Fatalf("existing id replaced: %q", fixed.ID)
	}
	if got, err := s.Policy(ctx, p.ID); err != nil || got.Name != "p" {
		t.Fatalf("got %+v %v", got, err)
	}
	if list, err := s.ListPolicies(ctx); err != nil || len(list) != 2 {
		t.Fatalf("got %+v %v", list, err)
	}
	must(t, s.DeletePolicy(ctx, p.ID))
	if _, err := s.Policy(ctx, p.ID); !errors.Is(err, domain.ErrPolicyNotFound) {
		t.Fatalf("got %v", err)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
