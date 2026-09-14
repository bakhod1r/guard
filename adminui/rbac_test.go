package adminui_test

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"

	"github.com/bakhod1r/guard"
	accessdomain "github.com/bakhod1r/guard/access/domain"
	accessinfra "github.com/bakhod1r/guard/access/infrastructure"
	"github.com/bakhod1r/guard/adminui"
	apikeyinfra "github.com/bakhod1r/guard/apikey/infrastructure"
	"github.com/bakhod1r/guard/audit"
	"github.com/bakhod1r/guard/guardtest"
	identityinfra "github.com/bakhod1r/guard/identity/infrastructure"
	"github.com/bakhod1r/guard/ratelimit"
	sessioninfra "github.com/bakhod1r/guard/session/infrastructure"
)

func rbacAdmin(t *testing.T) *panel {
	t.Helper()
	p := newPanel(t)
	p.account("1", "admin@example.com", true)
	p.login("admin@example.com")
	return p
}

func rbacExpect(t *testing.T, code int, h http.Header, want string) {
	t.Helper()
	if code != http.StatusSeeOther || !strings.HasPrefix(location(h), want) {
		t.Fatalf("want redirect %q, got %d %q", want, code, location(h))
	}
}

func rbacAudited(t *testing.T, g *guard.Guard, action string) {
	t.Helper()
	ev, err := g.Audit.(*audit.Memory).List(context.Background(), "", 1000)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ev {
		if e.Action == action {
			return
		}
	}
	t.Fatalf("no audit event %s", action)
}

func TestRBACAdminFlow(t *testing.T) {
	p := rbacAdmin(t)

	code, body := p.get("/guard-admin/roles")
	if code != http.StatusOK || !strings.Contains(body, "admin") || !strings.Contains(body, "wildcard") ||
		!strings.Contains(body, "system") || !strings.Contains(body, "New role") {
		t.Fatalf("roles list: %d %s", code, body)
	}

	code, _, h := p.post("/guard-admin/roles", url.Values{"name": {"editor"}, "title": {"Editor"}, "description": {"Edits <things>"}})
	rbacExpect(t, code, h, "/guard-admin/roles/editor?flash=")
	rbacAudited(t, p.g, "role.create")

	code, body = p.get("/guard-admin/roles/editor")
	if code != http.StatusOK || !strings.Contains(body, "Edits &lt;things&gt;") || !strings.Contains(body, "No permissions granted") ||
		!strings.Contains(body, `<option value="user.read">`) {
		t.Fatalf("detail: %d %s", code, body)
	}

	code, _, h = p.post("/guard-admin/roles/editor/permissions", url.Values{"code": {"user.read"}})
	rbacExpect(t, code, h, "/guard-admin/roles/editor?flash=")
	rbacAudited(t, p.g, "role.grant")
	_, body = p.get("/guard-admin/roles/editor")
	if strings.Contains(body, `<option value="user.read">`) || !strings.Contains(body, "/roles/editor/permissions/revoke") {
		t.Fatalf("grant not shown: %s", body)
	}
	if _, body = p.get("/guard-admin/permissions"); !strings.Contains(body, "editor") {
		t.Fatalf("permissions page lacks role: %s", body)
	}

	code, _, h = p.post("/guard-admin/roles/editor/permissions", url.Values{"code": {"bad"}})
	rbacExpect(t, code, h, "/guard-admin/roles/editor?error=")
	code, _, h = p.post("/guard-admin/roles/editor/permissions", url.Values{"code": {"nope.none"}})
	rbacExpect(t, code, h, "/guard-admin/roles/editor?error=")

	code, _, h = p.post("/guard-admin/roles/editor/permissions/revoke", url.Values{"code": {"user.read"}})
	rbacExpect(t, code, h, "/guard-admin/roles/editor?flash=")
	rbacAudited(t, p.g, "role.revoke")
	code, _, h = p.post("/guard-admin/roles/editor/permissions/revoke", url.Values{"code": {"bad"}})
	rbacExpect(t, code, h, "/guard-admin/roles/editor?error=")

	code, _, h = p.post("/guard-admin/roles/editor/delete", nil)
	rbacExpect(t, code, h, "/guard-admin/roles?flash=")
	rbacAudited(t, p.g, "role.delete")
	if code, _ := p.get("/guard-admin/roles/editor"); code != http.StatusNotFound {
		t.Fatalf("deleted role still there: %d", code)
	}
	code, _, h = p.post("/guard-admin/roles/editor/delete", nil)
	rbacExpect(t, code, h, "/guard-admin/roles?error=")
}

func TestRBACCreateRoleErrors(t *testing.T) {
	p := rbacAdmin(t)
	code, _, h := p.post("/guard-admin/roles", url.Values{"name": {"admin"}})
	rbacExpect(t, code, h, "/guard-admin/roles?error=access%3A+role+already+exists")
	for _, n := range []string{"", "A", "bad name", "x"} {
		code, _, h = p.post("/guard-admin/roles", url.Values{"name": {n}})
		rbacExpect(t, code, h, "/guard-admin/roles?error=")
	}
}

func TestRBACWildcardAndSystem(t *testing.T) {
	p := rbacAdmin(t)
	code, body := p.get("/guard-admin/roles/admin")
	if code != http.StatusOK || !strings.Contains(body, "wildcard role passes every check") || strings.Contains(body, `name="code"`) {
		t.Fatalf("wildcard detail: %d %s", code, body)
	}
	code, _, h := p.post("/guard-admin/roles/admin/delete", nil)
	rbacExpect(t, code, h, "/guard-admin/roles/admin?error=")
	code, _, h = p.post("/guard-admin/roles", url.Values{"name": {"super"}, "wildcard": {"on"}})
	rbacExpect(t, code, h, "/guard-admin/roles/super")
	if _, body = p.get("/guard-admin/roles/super"); !strings.Contains(body, "wildcard role passes every check") {
		t.Fatal("created wildcard role not wildcard")
	}
	if code, body := p.get("/guard-admin/roles/missing"); code != http.StatusNotFound || !strings.Contains(body, "not found") {
		t.Fatalf("unknown role: %d", code)
	}
}

func TestRBACPermissions(t *testing.T) {
	p := rbacAdmin(t)
	code, _, h := p.post("/guard-admin/permissions", url.Values{"code": {"report.export"}, "description": {"Export reports"}})
	rbacExpect(t, code, h, "/guard-admin/permissions?flash=")
	rbacAudited(t, p.g, "permission.create")
	code, body := p.get("/guard-admin/permissions")
	if code != http.StatusOK || !strings.Contains(body, "report.export") || !strings.Contains(body, "Export reports") ||
		!strings.Contains(body, "No role") || !strings.Contains(body, "New permission") {
		t.Fatalf("permissions: %d %s", code, body)
	}
	for _, c := range []string{"", "nodot", "a.b.c", "Bad.Code"} {
		code, _, h = p.post("/guard-admin/permissions", url.Values{"code": {c}})
		rbacExpect(t, code, h, "/guard-admin/permissions?error=")
	}
}

func TestRBACNonAdminForbidden(t *testing.T) {
	p := newPanel(t)
	p.account("2", "user@example.com", false)
	p.login("user@example.com")
	for _, path := range []string{"/guard-admin/roles", "/guard-admin/roles/user", "/guard-admin/permissions"} {
		if code, _ := p.get(path); code != http.StatusForbidden {
			t.Fatalf("GET %s: %d", path, code)
		}
	}
	for _, path := range []string{"/guard-admin/roles", "/guard-admin/roles/user/delete", "/guard-admin/roles/user/permissions",
		"/guard-admin/roles/user/permissions/revoke", "/guard-admin/permissions"} {
		if code, _, _ := p.post(path, url.Values{"name": {"x1"}, "code": {"user.read"}}); code != http.StatusForbidden {
			t.Fatalf("POST %s: %d", path, code)
		}
	}
	if r, _ := p.g.Access.Role(context.Background(), "user"); len(r.Permissions) != 0 {
		t.Fatal("forbidden grant applied")
	}
}

// readOnly holds role.read + permission.read but not the write permissions.
func TestRBACReadOnlyHidesForms(t *testing.T) {
	p := newPanel(t)
	ctx := context.Background()
	p.account("3", "viewer@example.com", false)
	_, _ = p.g.Access.CreateRole(ctx, "viewer", "", "", false)
	_ = p.g.Access.GrantPermission(ctx, "viewer", "role.read", "")
	_ = p.g.Access.GrantPermission(ctx, "viewer", "permission.read", "")
	_ = p.g.Access.AssignRole(ctx, "3", "viewer", "", nil)
	p.login("viewer@example.com")
	for _, path := range []string{"/guard-admin/roles", "/guard-admin/roles/viewer", "/guard-admin/permissions"} {
		code, body := p.get(path)
		if code != http.StatusOK || strings.Contains(body, "New role") || strings.Contains(body, "New permission") ||
			strings.Contains(body, "/delete") || strings.Contains(body, "/revoke") || strings.Contains(body, "Grant permission") {
			t.Fatalf("GET %s: %d %s", path, code, body)
		}
	}
}

// ---------- storage failures ----------

var errRBACStore = errors.New("db down")

type rbacFailing struct {
	*accessinfra.Memory
	fail map[string]bool
}

func (f *rbacFailing) err(op string) error {
	if f.fail[op] {
		return errRBACStore
	}
	return nil
}
func (f *rbacFailing) ListRoles(ctx context.Context) ([]accessdomain.Role, error) {
	if err := f.err("ListRoles"); err != nil {
		return nil, err
	}
	return f.Memory.ListRoles(ctx)
}
func (f *rbacFailing) ListPermissions(ctx context.Context) ([]accessdomain.Permission, error) {
	if err := f.err("ListPermissions"); err != nil {
		return nil, err
	}
	return f.Memory.ListPermissions(ctx)
}
func (f *rbacFailing) Role(ctx context.Context, n string) (*accessdomain.Role, error) {
	if err := f.err("Role"); err != nil {
		return nil, err
	}
	return f.Memory.Role(ctx, n)
}
func (f *rbacFailing) CreatePermission(ctx context.Context, pm accessdomain.Permission) error {
	if err := f.err("CreatePermission"); err != nil {
		return err
	}
	return f.Memory.CreatePermission(ctx, pm)
}

func rbacFailingPanel(t *testing.T) (*panel, *rbacFailing) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mem := accessinfra.NewMemory()
	guardtest.Seed(context.Background(), mem)
	store := &rbacFailing{Memory: mem, fail: map[string]bool{}}
	g := guard.Build(guard.Repositories{
		Users:    identityinfra.NewMemoryUsers(),
		Hasher:   &identityinfra.Argon2Hasher{Memory: 1024, Time: 1, Threads: 1, KeyLen: 32, SaltLen: 16},
		Sessions: sessioninfra.NewRedisSessions(rdb, "t:"),
		Roles:    store, Policies: mem, Audit: &audit.Memory{},
		APIKeys: apikeyinfra.NewMemory(), Limiter: ratelimit.NewRedis(rdb, "t:"),
	}, guard.Config{})
	r := gin.New()
	adminui.Mount(r, g, adminui.Options{InsecureCookie: true})
	p := &panel{t: t, g: g, r: r}
	p.account("1", "admin@example.com", true)
	p.login("admin@example.com")
	return p, store
}

func TestRBACStorageErrors(t *testing.T) {
	p, s := rbacFailingPanel(t)

	s.fail["ListRoles"] = true
	for _, path := range []string{"/guard-admin/roles", "/guard-admin/permissions"} {
		if code, body := p.get(path); code != http.StatusInternalServerError || strings.Contains(body, "db down") {
			t.Fatalf("GET %s: %d", path, code)
		}
	}
	s.fail = map[string]bool{"ListPermissions": true}
	for _, path := range []string{"/guard-admin/permissions", "/guard-admin/roles/user"} {
		if code, _ := p.get(path); code != http.StatusInternalServerError {
			t.Fatalf("GET %s: %d", path, code)
		}
	}
	s.fail = map[string]bool{"Role": true}
	if code, _ := p.get("/guard-admin/roles/user"); code != http.StatusInternalServerError {
		t.Fatalf("role err: %d", code)
	}
	s.fail = map[string]bool{"CreatePermission": true}
	code, _, h := p.post("/guard-admin/permissions", url.Values{"code": {"a.b"}})
	rbacExpect(t, code, h, "/guard-admin/permissions?error=internal")

}

func TestRBACEmptyStates(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mem := accessinfra.NewMemory()
	guardtest.Seed(context.Background(), mem)
	g := guard.Build(guard.Repositories{
		Users:    identityinfra.NewMemoryUsers(),
		Hasher:   &identityinfra.Argon2Hasher{Memory: 1024, Time: 1, Threads: 1, KeyLen: 32, SaltLen: 16},
		Sessions: sessioninfra.NewRedisSessions(rdb, "t:"),
		Roles:    &rbacEmpty{mem}, Policies: mem, Audit: &audit.Memory{},
		APIKeys: apikeyinfra.NewMemory(), Limiter: ratelimit.NewRedis(rdb, "t:"),
	}, guard.Config{})
	r := gin.New()
	adminui.Mount(r, g, adminui.Options{InsecureCookie: true})
	p := &panel{t: t, g: g, r: r}
	p.account("1", "admin@example.com", true)
	p.login("admin@example.com")
	if _, body := p.get("/guard-admin/roles"); !strings.Contains(body, "No roles yet") {
		t.Fatalf("roles empty: %s", body)
	}
	if _, body := p.get("/guard-admin/permissions"); !strings.Contains(body, "No permissions yet") {
		t.Fatalf("permissions empty: %s", body)
	}
	if _, err := g.Access.CreateRole(context.Background(), "plain", "", "", false); err != nil {
		t.Fatal(err)
	}
	if _, body := p.get("/guard-admin/roles/plain"); !strings.Contains(body, "No permissions exist") {
		t.Fatalf("no grantable: %s", body)
	}
}

// rbacEmpty lists nothing while authorization (GrantsOf) still works.
type rbacEmpty struct{ *accessinfra.Memory }

func (rbacEmpty) ListRoles(context.Context) ([]accessdomain.Role, error)             { return nil, nil }
func (rbacEmpty) ListPermissions(context.Context) ([]accessdomain.Permission, error) { return nil, nil }
