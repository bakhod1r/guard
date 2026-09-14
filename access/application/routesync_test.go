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

type failRegistry struct {
	*infrastructure.MemoryRoutes
	failList, failSave, failMark bool
}

func (f *failRegistry) ListRoutes(ctx context.Context) ([]domain.RouteRecord, error) {
	if f.failList {
		return nil, errBoom
	}
	return f.MemoryRoutes.ListRoutes(ctx)
}

func (f *failRegistry) SaveRoutes(ctx context.Context, rs []domain.RouteRecord, at time.Time) error {
	if f.failSave {
		return errBoom
	}
	return f.MemoryRoutes.SaveRoutes(ctx, rs, at)
}

func (f *failRegistry) MarkStale(ctx context.Context, at time.Time) ([]domain.RouteRecord, error) {
	if f.failMark {
		return nil, errBoom
	}
	return f.MemoryRoutes.MarkStale(ctx, at)
}

func syncSvc(t *testing.T) (*Service, *seedRepo) {
	t.Helper()
	s, repo := newSeedSvc()
	ctx := context.Background()
	for _, r := range []struct {
		name     string
		wildcard bool
	}{{"admin", false}, {"user", false}, {"root", true}} {
		if _, err := s.CreateRole(ctx, r.name, r.name, "", r.wildcard); err != nil {
			t.Fatal(err)
		}
	}
	return s, repo
}

var syncRoutes = []Route{
	{Method: "GET", Path: "/api/invoices"},
	{Method: "GET", Path: "/api/invoices/:id"},
	{Method: "POST", Path: "/api/invoices"},
	{Method: "DELETE", Path: "/api/invoices/:id"},
	{Method: "GET", Path: "/api/reports/:id/export"},
	{Method: "GET", Path: "/api/:id"},
}

func TestSyncRoutesDefaults(t *testing.T) {
	ctx := context.Background()
	s, _ := syncSvc(t)
	// Manually created permission with its own description must stay untouched.
	if _, err := s.CreatePermission(ctx, "invoices.delete", "hand made"); err != nil {
		t.Fatal(err)
	}
	reg := &failRegistry{MemoryRoutes: infrastructure.NewMemoryRoutes()}
	opts := RouteSyncOptions{Prefix: "/api", Overrides: map[string]string{"GET /api/reports/:id/export": "reports.export"}}
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	res, err := s.SyncRoutes(ctx, reg, syncRoutes, opts, now)
	if err != nil {
		t.Fatal(err)
	}
	if got := codes(res.Permissions); !reflect.DeepEqual(got, []string{"invoices.read", "invoices.create", "invoices.delete", "reports.export"}) {
		t.Fatalf("permissions %v", got)
	}
	if got := codes(res.Created); !reflect.DeepEqual(got, []string{"invoices.read", "invoices.create", "reports.export"}) {
		t.Fatalf("created %v", got)
	}
	if !reflect.DeepEqual(res.Skipped, []Route{{Method: "GET", Path: "/api/:id"}}) {
		t.Fatalf("skipped %v", res.Skipped)
	}
	if !reflect.DeepEqual(res.GrantedRoles, []string{"admin"}) || !reflect.DeepEqual(res.MissingRoles, []string{"super_admin"}) {
		t.Fatalf("roles %v %v", res.GrantedRoles, res.MissingRoles)
	}
	perms, _ := s.ListPermissions(ctx)
	for _, p := range perms {
		if p.Code() == "invoices.delete" && p.Description != "hand made" {
			t.Fatalf("manual permission changed: %+v", p)
		}
	}
	admin, _ := s.Role(ctx, "admin")
	if len(admin.Permissions) != 4 {
		t.Fatalf("admin %v", codes(admin.Permissions))
	}
	root, _ := s.Role(ctx, "root")
	if len(root.Permissions) != 0 {
		t.Fatal("wildcard role granted")
	}
	user, _ := s.Role(ctx, "user")
	if got := codes(user.Permissions); !reflect.DeepEqual(got, []string{"invoices.read"}) {
		t.Fatalf("user %v", got)
	}

	// Admin revokes user's read; a later sync must not re-grant it, and a
	// removed route turns stale while its permission survives.
	if err := s.RevokePermission(ctx, "user", "invoices.read"); err != nil {
		t.Fatal(err)
	}
	res, err = s.SyncRoutes(ctx, reg, syncRoutes[:3], opts, now.Add(time.Hour))
	if err != nil || len(res.Created) != 0 {
		t.Fatalf("%+v %v", res, err)
	}
	if user, _ := s.Role(ctx, "user"); len(user.Permissions) != 0 {
		t.Fatalf("re-granted %v", codes(user.Permissions))
	}
	var stale []string
	for _, r := range res.Stale {
		stale = append(stale, r.Key())
	}
	if !reflect.DeepEqual(stale, []string{"DELETE /api/invoices/:id", "GET /api/reports/:id/export"}) {
		t.Fatalf("stale %v", stale)
	}
	if perms2, _ := s.ListPermissions(ctx); len(perms2) != len(perms) {
		t.Fatal("permission deleted")
	}
	// A route new to the registry grants user actions even if its permission exists.
	res, err = s.SyncRoutes(ctx, reg, []Route{{Method: "GET", Path: "/api/invoices/:id/pdf"}}, RouteSyncOptions{Prefix: "/api", UserActions: []string{"read"}, UserRole: "user"}, now.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if user, _ := s.Role(ctx, "user"); !reflect.DeepEqual(codes(user.Permissions), []string{"invoices_pdf.read"}) {
		t.Fatalf("user %v", codes(user.Permissions))
	}
}

func TestSyncRoutesCustomOptionsAndNoRegistry(t *testing.T) {
	ctx := context.Background()
	s, _ := syncSvc(t)
	opts := RouteSyncOptions{Prefix: "/api", FullRoles: []string{"-"}, UserRole: "-", UserActions: []string{"read", "create"}}
	res, err := s.SyncRoutes(ctx, nil, syncRoutes, opts, time.Now())
	if err != nil || res.Stale != nil || res.GrantedRoles != nil {
		t.Fatalf("%+v %v", res, err)
	}
	if a, _ := s.Role(ctx, "admin"); len(a.Permissions) != 0 {
		t.Fatal("disabled full roles granted")
	}
	// Without a registry only newly created permissions reach the user role.
	s2, _ := syncSvc(t)
	res, err = s2.SyncRoutes(ctx, nil, syncRoutes, RouteSyncOptions{Prefix: "/api", FullRoles: []string{"root", "admin"}, UserActions: []string{"read", "create"}}, time.Now())
	if err != nil || !reflect.DeepEqual(res.GrantedRoles, []string{"root", "admin"}) {
		t.Fatalf("%+v %v", res, err)
	}
	if u, _ := s2.Role(ctx, "user"); !reflect.DeepEqual(codes(u.Permissions), []string{"invoices.read", "invoices.create", "reports_export.read"}) {
		t.Fatalf("user %v", codes(u.Permissions))
	}
	// Missing user role is tolerated.
	if _, err := s2.SyncRoutes(ctx, nil, []Route{{Method: "GET", Path: "/api/zzz"}}, RouteSyncOptions{Prefix: "/api", UserRole: "ghost"}, time.Now()); err != nil {
		t.Fatal(err)
	}
}

func TestSyncRoutesRejectsBadOverride(t *testing.T) {
	s, _ := syncSvc(t)
	_, err := s.SyncRoutes(context.Background(), nil, syncRoutes, RouteSyncOptions{Prefix: "/api", Overrides: map[string]string{"GET /api/invoices": "bad"}}, time.Now())
	if !errors.Is(err, domain.ErrInvalidPermission) {
		t.Fatal(err)
	}
}

func TestSyncRoutesErrors(t *testing.T) {
	ctx := context.Background()
	cases := map[string]func(*seedRepo, *failRegistry){
		"list perms":  func(r *seedRepo, _ *failRegistry) { r.failListPerms = true },
		"list routes": func(_ *seedRepo, f *failRegistry) { f.failList = true },
		"create":      func(r *seedRepo, _ *failRegistry) { r.failPerm = true },
		"role":        func(r *seedRepo, _ *failRegistry) { r.failRole = true },
		"grant":       func(r *seedRepo, _ *failRegistry) { r.failGrant = true },
		"save":        func(_ *seedRepo, f *failRegistry) { f.failSave = true },
		"mark":        func(_ *seedRepo, f *failRegistry) { f.failMark = true },
	}
	for name, arm := range cases {
		t.Run(name, func(t *testing.T) {
			s, repo := syncSvc(t)
			reg := &failRegistry{MemoryRoutes: infrastructure.NewMemoryRoutes()}
			arm(repo, reg)
			if _, err := s.SyncRoutes(ctx, reg, syncRoutes, RouteSyncOptions{Prefix: "/api"}, time.Now()); !errors.Is(err, errBoom) {
				t.Fatalf("got %v", err)
			}
		})
	}
	// Grant failure on the user role path.
	s, repo := syncSvc(t)
	repo.failGrant = true
	if _, err := s.SyncRoutes(ctx, nil, syncRoutes[:1], RouteSyncOptions{Prefix: "/api", FullRoles: []string{"-"}}, time.Now()); !errors.Is(err, errBoom) {
		t.Fatalf("user grant: %v", err)
	}
}
