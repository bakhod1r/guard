package application

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/bakhod1r/guard/access/domain"
	"github.com/bakhod1r/guard/access/infrastructure"
)

// seedRepo wraps Memory with per-call failure switches for SeedRoutes tests.
type seedRepo struct {
	*infrastructure.Memory
	failPerm, failRole, failCreateRole, failGrant, failListPerms bool
}

func (r *seedRepo) ListPermissions(ctx context.Context) ([]domain.Permission, error) {
	if r.failListPerms {
		return nil, errBoom
	}
	return r.Memory.ListPermissions(ctx)
}

func (r *seedRepo) CreatePermission(ctx context.Context, p domain.Permission) error {
	if r.failPerm {
		return errBoom
	}
	return r.Memory.CreatePermission(ctx, p)
}

func (r *seedRepo) Role(ctx context.Context, n string) (*domain.Role, error) {
	if r.failRole {
		return nil, errBoom
	}
	return r.Memory.Role(ctx, n)
}

func (r *seedRepo) CreateRole(ctx context.Context, role *domain.Role) error {
	if r.failCreateRole {
		return errBoom
	}
	return r.Memory.CreateRole(ctx, role)
}

func (r *seedRepo) GrantPermission(ctx context.Context, role string, p domain.Permission, by string) error {
	if r.failGrant {
		return errBoom
	}
	return r.Memory.GrantPermission(ctx, role, p, by)
}

func newSeedSvc() (*Service, *seedRepo) {
	repo := &seedRepo{Memory: infrastructure.NewMemory()}
	return NewService(repo, repo), repo
}

var seedRoutes = []Route{
	{Method: "get", Path: "/api/invoices"},
	{Method: "GET", Path: "/api/invoices/:id"},
	{Method: "POST", Path: "/api/invoices"},
	{Method: "GET", Path: "/api/:id"},
}

func codes(ps []domain.Permission) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.Code())
	}
	return out
}

func TestSeedRoutesCreatesSuperRole(t *testing.T) {
	ctx := context.Background()
	s, repo := newSeedSvc()
	if _, err := s.CreateRole(ctx, "viewer", "", "", false); err != nil {
		t.Fatal(err)
	}
	res, err := s.SeedRoutes(ctx, seedRoutes, "/api", "super")
	if err != nil {
		t.Fatal(err)
	}
	if got := codes(res.Permissions); !reflect.DeepEqual(got, []string{"invoices.read", "invoices.create"}) {
		t.Fatalf("permissions %v", got)
	}
	if res.Permissions[0].Description != "GET /api/invoices" || res.Permissions[1].Description != "POST /api/invoices" {
		t.Fatalf("descriptions %+v", res.Permissions)
	}
	if !reflect.DeepEqual(res.Skipped, []Route{{Method: "GET", Path: "/api/:id"}}) {
		t.Fatalf("skipped %v", res.Skipped)
	}
	stored, _ := repo.ListPermissions(ctx)
	if len(stored) != 2 {
		t.Fatalf("stored %v", stored)
	}
	super, err := s.Role(ctx, "super")
	if err != nil || !super.Wildcard || super.Title != "Super administrator" || super.Description != "Full access to every route (autoseed)" {
		t.Fatalf("super %+v %v", super, err)
	}
	viewer, _ := s.Role(ctx, "viewer")
	if len(viewer.Permissions) != 0 {
		t.Fatalf("viewer touched: %v", viewer.Permissions)
	}
	// Idempotent re-run.
	if _, err := s.SeedRoutes(ctx, seedRoutes, "/api", "super"); err != nil {
		t.Fatal(err)
	}
}

func TestSeedRoutesGrantsExistingRole(t *testing.T) {
	ctx := context.Background()
	s, _ := newSeedSvc()
	if _, err := s.CreateRole(ctx, "admin", "", "", false); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := s.SeedRoutes(ctx, seedRoutes, "/api", "admin"); err != nil {
			t.Fatal(err)
		}
	}
	admin, _ := s.Role(ctx, "admin")
	if admin.Wildcard || !reflect.DeepEqual(codes(admin.Permissions), []string{"invoices.read", "invoices.create"}) {
		t.Fatalf("admin %+v", admin)
	}
}

func TestSeedRoutesWildcardAndNoRole(t *testing.T) {
	ctx := context.Background()
	s, repo := newSeedSvc()
	if _, err := s.CreateRole(ctx, "root", "", "", true); err != nil {
		t.Fatal(err)
	}
	repo.failGrant = true // must not be called for a wildcard role
	if _, err := s.SeedRoutes(ctx, seedRoutes, "/api", "root"); err != nil {
		t.Fatal(err)
	}
	repo.failRole = true // must not be called when superRole is empty
	res, err := s.SeedRoutes(ctx, nil, "/api", "")
	if err != nil || res.Permissions != nil || res.Skipped != nil {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestSeedRoutesErrors(t *testing.T) {
	ctx := context.Background()
	cases := map[string]func(*seedRepo){
		"permission":  func(r *seedRepo) { r.failPerm = true },
		"role lookup": func(r *seedRepo) { r.failRole = true },
		"create role": func(r *seedRepo) { r.failCreateRole = true },
		"grant":       func(r *seedRepo) { r.failGrant = true },
	}
	for name, arm := range cases {
		t.Run(name, func(t *testing.T) {
			s, repo := newSeedSvc()
			if name == "grant" {
				if _, err := s.CreateRole(ctx, "super", "", "", false); err != nil {
					t.Fatal(err)
				}
			}
			arm(repo)
			if _, err := s.SeedRoutes(ctx, seedRoutes, "/api", "super"); !errors.Is(err, errBoom) {
				t.Fatalf("got %v", err)
			}
		})
	}
}
