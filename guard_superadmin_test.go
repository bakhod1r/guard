package guard

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"time"

	accessdomain "github.com/bakhod1r/guard/access/domain"
	accessinfra "github.com/bakhod1r/guard/access/infrastructure"
	apikeyinfra "github.com/bakhod1r/guard/apikey/infrastructure"
	"github.com/bakhod1r/guard/audit"
	identitydomain "github.com/bakhod1r/guard/identity/domain"
	identityinfra "github.com/bakhod1r/guard/identity/infrastructure"
)

const saPW = "orbit-lantern-quartz-91"

var errSABoom = errors.New("superadmin boom")

type saUsers struct {
	identitydomain.UserRepository
	byIDErr error
}

func (u *saUsers) ByID(ctx context.Context, id identitydomain.UserID) (*identitydomain.User, error) {
	if u.byIDErr != nil {
		return nil, u.byIDErr
	}
	return u.UserRepository.ByID(ctx, id)
}

// saRoles hides the holder methods of the wrapped store (a custom repository).
type saRoles struct {
	accessdomain.RoleRepository
	assignErr error
}

func (r *saRoles) AssignRole(ctx context.Context, userID, role, by string, exp *time.Time) error {
	if r.assignErr != nil {
		return r.assignErr
	}
	return r.RoleRepository.AssignRole(ctx, userID, role, by, exp)
}

type superEnv struct {
	g     *Guard
	users *saUsers
	roles *saRoles
	audit *audit.Memory
	logs  *bytes.Buffer
}

func newSuperEnv(t *testing.T, plain bool) *superEnv {
	t.Helper()
	store := accessinfra.NewMemory()
	for _, n := range []string{accessdomain.RoleSuperAdmin, accessdomain.RoleAdmin, "user"} {
		if err := store.CreateRole(context.Background(), &accessdomain.Role{Name: n, Title: n, IsSystem: true, Wildcard: n != "user"}); err != nil {
			t.Fatal(err)
		}
	}
	e := &superEnv{users: &saUsers{UserRepository: identityinfra.NewMemoryUsers()}, roles: &saRoles{RoleRepository: store},
		audit: &audit.Memory{}, logs: &bytes.Buffer{}}
	var roleRepo accessdomain.RoleRepository = store
	if plain {
		roleRepo = e.roles
	}
	e.g = Build(Repositories{
		Users: e.users, Hasher: &identityinfra.Argon2Hasher{Memory: 1024, Time: 1, Threads: 1, KeyLen: 32, SaltLen: 16},
		Roles: roleRepo, Policies: store, Audit: e.audit, APIKeys: apikeyinfra.NewMemory(),
	}, Config{Logger: slog.New(slog.NewTextHandler(e.logs, nil))})
	return e
}

func (e *superEnv) account(t *testing.T, id string) {
	t.Helper()
	if _, err := e.g.CreateAccount(context.Background(), id, id+"@example.com", saPW, nil, RequestMeta{}); err != nil {
		t.Fatal(err)
	}
}

func (e *superEnv) last() audit.Event { return e.audit.Events[len(e.audit.Events)-1] }

func TestEnsureSuperAdminIdempotent(t *testing.T) {
	e := newSuperEnv(t, false)
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		u, err := e.g.EnsureSuperAdmin(ctx, "1", "root@example.com", saPW)
		if err != nil || u.ID != "1" {
			t.Fatalf("run %d: %v %v", i, u, err)
		}
		if ev := e.last(); ev.Action != "superadmin.ensure" || ev.Target != "1" || !ev.Success {
			t.Fatalf("audit %+v", ev)
		}
	}
	if ok, err := e.g.IsSuperAdmin(ctx, "1"); err != nil || !ok {
		t.Fatal(ok, err)
	}
	if ids, err := e.g.SuperAdmins(ctx); err != nil || !reflect.DeepEqual(ids, []string{"1"}) {
		t.Fatal(ids, err)
	}
	for _, s := range []string{saPW, "root@example.com"} {
		if strings.Contains(e.logs.String(), s) {
			t.Fatal("secret or email logged")
		}
	}
}

func TestEnsureSuperAdminErrors(t *testing.T) {
	ctx := context.Background()
	e := newSuperEnv(t, true)
	if _, err := e.g.EnsureSuperAdmin(ctx, "1", "not-an-email", saPW); err == nil {
		t.Fatal("want create error")
	}
	e.account(t, "1")
	e.users.byIDErr = errSABoom
	if _, err := e.g.EnsureSuperAdmin(ctx, "1", "1@example.com", saPW); !errors.Is(err, errSABoom) {
		t.Fatal(err)
	}
	e.users.byIDErr = nil
	e.roles.assignErr = errSABoom
	if _, err := e.g.EnsureSuperAdmin(ctx, "1", "1@example.com", saPW); !errors.Is(err, errSABoom) {
		t.Fatal(err)
	}
	if ev := e.last(); ev.Action != "superadmin.ensure" || ev.Success {
		t.Fatalf("audit %+v", ev)
	}
}

func TestGuardAssignAndUnassignRole(t *testing.T) {
	e := newSuperEnv(t, false)
	ctx := context.Background()
	for _, id := range []string{"root", "adm", "bob"} {
		e.account(t, id)
	}
	if _, err := e.g.EnsureSuperAdmin(ctx, "root", "root@example.com", saPW); err != nil {
		t.Fatal(err)
	}
	if err := e.g.AssignRole(ctx, "root", "adm", accessdomain.RoleAdmin, nil); err != nil {
		t.Fatal(err)
	}
	if ev := e.last(); ev.Action != "role.assign" || ev.ActorID != "root" || ev.Metadata["role"] != "admin" {
		t.Fatalf("audit %+v", ev)
	}
	if err := e.g.AssignRole(ctx, "adm", "bob", accessdomain.RoleSuperAdmin, nil); !errors.Is(err, accessdomain.ErrForbidden) {
		t.Fatal(err)
	}
	if ev := e.last(); ev.Action != "superadmin.denied" || ev.Success || ev.Metadata["op"] != "assign" {
		t.Fatalf("audit %+v", ev)
	}
	if err := e.g.AssignRole(ctx, "root", "bob", accessdomain.RoleSuperAdmin, nil); err != nil {
		t.Fatal(err)
	}
	if ev := e.last(); ev.Action != "superadmin.grant" || ev.Target != "bob" {
		t.Fatalf("audit %+v", ev)
	}
	if err := e.g.AssignRole(ctx, "root", "ghost", "nope", nil); err == nil {
		t.Fatal("want role not found")
	}
	if ev := e.last(); ev.Action != "role.assign" || ev.Success {
		t.Fatalf("audit %+v", ev)
	}

	if err := e.g.UnassignRole(ctx, "root", "bob", accessdomain.RoleSuperAdmin); err != nil {
		t.Fatal(err)
	}
	if ev := e.last(); ev.Action != "superadmin.revoke" || ev.Target != "bob" {
		t.Fatalf("audit %+v", ev)
	}
	if err := e.g.UnassignRole(ctx, "root", "root", accessdomain.RoleSuperAdmin); !errors.Is(err, accessdomain.ErrLastSuperAdmin) {
		t.Fatal(err)
	}
	if ev := e.last(); ev.Action != "superadmin.denied" || ev.Metadata["op"] != "unassign" || ev.Metadata["reason"] != accessdomain.ErrLastSuperAdmin.Error() {
		t.Fatalf("audit %+v", ev)
	}
	if err := e.g.UnassignRole(ctx, "root", "adm", accessdomain.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	if ev := e.last(); ev.Action != "role.unassign" || !ev.Success {
		t.Fatalf("audit %+v", ev)
	}
	p := newSuperEnv(t, true)
	if _, err := p.g.EnsureSuperAdmin(ctx, "root", "root@example.com", saPW); err != nil {
		t.Fatal(err)
	}
	if err := p.g.UnassignRole(ctx, "root", "x", accessdomain.RoleSuperAdmin); !errors.Is(err, accessdomain.ErrHoldersUnsupported) {
		t.Fatal(err)
	}
	if ev := p.last(); ev.Action != "role.unassign" || ev.Success {
		t.Fatalf("audit %+v", ev)
	}
}

func TestCheckSuperAdminStatus(t *testing.T) {
	e := newSuperEnv(t, false)
	ctx := context.Background()
	for _, id := range []string{"root", "bob"} {
		e.account(t, id)
	}
	if _, err := e.g.EnsureSuperAdmin(ctx, "root", "root@example.com", saPW); err != nil {
		t.Fatal(err)
	}
	for _, st := range []Status{identitydomain.StatusBanned, identitydomain.StatusSuspended} {
		if err := e.g.checkSuperAdminStatus(ctx, "root", st); !errors.Is(err, accessdomain.ErrLastSuperAdmin) {
			t.Fatalf("%s: %v", st, err)
		}
	}
	if ev := e.last(); ev.Action != "superadmin.denied" || ev.Metadata["op"] != "status" {
		t.Fatalf("audit %+v", ev)
	}
	if err := e.g.SetUserStatus(ctx, "root", "root", identitydomain.StatusBanned); !errors.Is(err, ErrLastSuperAdmin) {
		t.Fatalf("SetUserStatus: %v", err)
	}
	if u, _ := e.g.Identity.User(ctx, "root"); u.Status != identitydomain.StatusActive {
		t.Fatalf("status changed to %s", u.Status)
	}
	if err := e.g.checkSuperAdminStatus(ctx, "root", identitydomain.StatusActive); err != nil {
		t.Fatal(err)
	}
	if err := e.g.checkSuperAdminStatus(ctx, "bob", identitydomain.StatusBanned); err != nil {
		t.Fatal(err)
	}
	// A second super admin who is banned, or whose account is missing, does not count.
	if err := e.g.AssignRole(ctx, "root", "bob", accessdomain.RoleSuperAdmin, nil); err != nil {
		t.Fatal(err)
	}
	if err := e.g.checkSuperAdminStatus(ctx, "root", identitydomain.StatusBanned); err != nil {
		t.Fatal(err)
	}
	if err := e.g.Identity.SetStatus(ctx, "bob", identitydomain.StatusBanned); err != nil {
		t.Fatal(err)
	}
	if err := e.g.checkSuperAdminStatus(ctx, "root", identitydomain.StatusSuspended); !errors.Is(err, accessdomain.ErrLastSuperAdmin) {
		t.Fatal(err)
	}
	if err := e.g.AssignRole(ctx, "root", "ghost", accessdomain.RoleSuperAdmin, nil); err != nil {
		t.Fatal(err)
	}
	if err := e.g.checkSuperAdminStatus(ctx, "root", identitydomain.StatusBanned); !errors.Is(err, accessdomain.ErrLastSuperAdmin) {
		t.Fatal(err)
	}
	e.users.byIDErr = errSABoom
	if err := e.g.checkSuperAdminStatus(ctx, "root", identitydomain.StatusBanned); !errors.Is(err, errSABoom) {
		t.Fatal(err)
	}

	// Custom repository without holder support: skip with a warning, never block bans.
	p := newSuperEnv(t, true)
	if err := p.g.checkSuperAdminStatus(ctx, "root", identitydomain.StatusBanned); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(p.logs.String(), "last-super-admin check skipped") {
		t.Fatalf("logs %q", p.logs.String())
	}
	if _, err := p.g.SuperAdmins(ctx); !errors.Is(err, accessdomain.ErrHoldersUnsupported) {
		t.Fatal(err)
	}
}

func TestGuardAccountChangesOnPrivilegedTarget(t *testing.T) {
	e := newSuperEnv(t, false)
	ctx := context.Background()
	for _, id := range []string{"root", "root2", "adm", "adm2", "bob"} {
		e.account(t, id)
	}
	for _, id := range []string{"root", "root2"} {
		if _, err := e.g.EnsureSuperAdmin(ctx, id, id+"@example.com", saPW); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []string{"adm", "adm2"} {
		if err := e.g.AssignRole(ctx, "root", id, accessdomain.RoleAdmin, nil); err != nil {
			t.Fatal(err)
		}
	}
	const newPW = "copper-meadow-violet-42"
	for _, target := range []string{"root", "adm2"} {
		if err := e.g.ResetPassword(ctx, "adm", target, newPW); !errors.Is(err, ErrForbidden) {
			t.Fatalf("reset %s: %v", target, err)
		}
		if err := e.g.SetUserStatus(ctx, "adm", target, identitydomain.StatusBanned); !errors.Is(err, ErrForbidden) {
			t.Fatalf("ban %s: %v", target, err)
		}
		if err := e.g.SetAttributes(ctx, "adm", target, map[string]any{"dept": "x"}); !errors.Is(err, ErrForbidden) {
			t.Fatalf("attributes %s: %v", target, err)
		}
		if _, err := e.g.Identity.Authenticate(ctx, target+"@example.com", saPW); err != nil {
			t.Fatalf("%s password changed: %v", target, err)
		}
	}
	if ev := e.last(); ev.Action != "superadmin.denied" || ev.ActorID != "adm" {
		t.Fatalf("audit %+v", ev)
	}
	if err := e.g.SetAttributes(ctx, "adm", "bob", map[string]any{"dept": "x"}); err != nil {
		t.Fatal(err)
	}
	for _, c := range [][2]string{{"adm", "bob"}, {"adm", "adm"}, {"root", "adm2"}, {"root", "root2"}} {
		if err := e.g.Access.AuthorizeAccountChange(ctx, c[0], c[1]); err != nil {
			t.Fatalf("%s on %s: %v", c[0], c[1], err)
		}
	}
}
