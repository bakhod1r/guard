package adminui_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"

	"github.com/bakhod1r/guard"
	accessdomain "github.com/bakhod1r/guard/access/domain"
	accessinfra "github.com/bakhod1r/guard/access/infrastructure"
	"github.com/bakhod1r/guard/adminui"
	apikeydomain "github.com/bakhod1r/guard/apikey/domain"
	apikeyinfra "github.com/bakhod1r/guard/apikey/infrastructure"
	"github.com/bakhod1r/guard/audit"
	"github.com/bakhod1r/guard/guardtest"
	identitydomain "github.com/bakhod1r/guard/identity/domain"
	identityinfra "github.com/bakhod1r/guard/identity/infrastructure"
	"github.com/bakhod1r/guard/ratelimit"
	sessiondomain "github.com/bakhod1r/guard/session/domain"
	sessioninfra "github.com/bakhod1r/guard/session/infrastructure"
)

// Fault injection: user id "boom" breaks ByID; "boom-x" breaks every
// per-user listing/revocation; search "boom" breaks List.
var errUsersBoom = errors.New("storage down")

type usersFaultUsers struct{ identitydomain.UserRepository }

func (u usersFaultUsers) ByID(ctx context.Context, id identitydomain.UserID) (*identitydomain.User, error) {
	if id == "boom" {
		return nil, errUsersBoom
	}
	return u.UserRepository.ByID(ctx, id)
}

func (u usersFaultUsers) List(ctx context.Context, q identitydomain.ListQuery) ([]identitydomain.User, int, error) {
	if q.Search == "boom" {
		return nil, 0, errUsersBoom
	}
	return u.UserRepository.List(ctx, q)
}

type usersFaultRoles struct{ *accessinfra.Memory }

func (r usersFaultRoles) GrantsOf(ctx context.Context, id string) ([]accessdomain.RoleGrant, error) {
	if id == "boom-x" {
		return nil, errUsersBoom
	}
	return r.Memory.GrantsOf(ctx, id)
}

func (r usersFaultRoles) UnassignRole(ctx context.Context, id, role string) error {
	if id == "boom-x" {
		return errUsersBoom
	}
	return r.Memory.UnassignRole(ctx, id, role)
}

type usersFaultSessions struct{ sessiondomain.Repository }

func (s usersFaultSessions) DeleteByUser(ctx context.Context, id string) error {
	if id == "boom-x" {
		return errUsersBoom
	}
	return s.Repository.DeleteByUser(ctx, id)
}

type usersFaultKeys struct{ apikeydomain.Repository }

func (k usersFaultKeys) RevokeAllByUser(ctx context.Context, id string, at time.Time) error {
	if id == "boom-x" {
		return errUsersBoom
	}
	return k.Repository.RevokeAllByUser(ctx, id, at)
}

func usersPanel(t *testing.T) *panel {
	t.Helper()
	gin.SetMode(gin.TestMode)
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	store := accessinfra.NewMemory()
	g := guard.Build(guard.Repositories{
		Users:    usersFaultUsers{identityinfra.NewMemoryUsers()},
		Hasher:   &identityinfra.Argon2Hasher{Memory: 1024, Time: 1, Threads: 1, KeyLen: 32, SaltLen: 16},
		Sessions: usersFaultSessions{sessioninfra.NewRedisSessions(rdb, "t:")},
		Roles:    usersFaultRoles{store},
		Policies: store,
		Audit:    &audit.Memory{},
		APIKeys:  usersFaultKeys{apikeyinfra.NewMemory()},
		Limiter:  ratelimit.NewRedis(rdb, "t:"),
	}, guard.Config{})
	guardtest.Seed(context.Background(), store)
	r := gin.New()
	adminui.Mount(r, g, adminui.Options{InsecureCookie: true})
	p := &panel{t: t, g: g, r: r}
	p.account("1", "admin@example.com", true)
	// super admin: role changes to admin/super_admin require it
	if _, err := g.EnsureSuperAdmin(context.Background(), "1", "admin@example.com", "tr0ub4dor-guard-42"); err != nil {
		t.Fatal(err)
	}
	p.account("2", "user@example.com", false)
	return p
}

func usersLogin(p *panel, email string) {
	p.t.Helper()
	p.login(email)
	p.get("/guard-admin/users/2") // CSRF token (every user may view self or is admin)
	if p.csrf == "" {
		p.t.Fatal("no csrf")
	}
}

func usersExpect(t *testing.T, name string, code int, h http.Header, wantPath, wantQuery string) {
	t.Helper()
	loc := location(h)
	if code != http.StatusSeeOther || !strings.HasPrefix(loc, "/guard-admin"+wantPath) || !strings.Contains(loc, wantQuery) {
		t.Fatalf("%s: %d %q (want %s ... %s)", name, code, loc, wantPath, wantQuery)
	}
}

func TestUsersListSearchFilterPagination(t *testing.T) {
	p := usersPanel(t)
	for i := 0; i < 30; i++ {
		p.account(fmt.Sprintf("u%02d", i), fmt.Sprintf("bulk%02d@example.com", i), false)
	}
	usersLogin(p, "admin@example.com")

	code, body := p.get("/guard-admin/users")
	if code != 200 || !strings.Contains(body, "32 accounts") || !strings.Contains(body, "page=2") || strings.Contains(body, "Previous") {
		t.Fatalf("page 1: %d %s", code, body)
	}
	if strings.Count(body, `class="user-row"`) != 25 || !strings.Contains(body, "Link host user") {
		t.Fatalf("page 1 rows / create form missing")
	}
	code, body = p.get("/guard-admin/users?page=2")
	if code != 200 || strings.Count(body, `class="user-row"`) != 7 || !strings.Contains(body, "Previous") || strings.Contains(body, "Next") {
		t.Fatalf("page 2: %d", code)
	}
	if _, body = p.get("/guard-admin/users?page=abc"); strings.Count(body, `class="user-row"`) != 25 {
		t.Fatal("bad page not defaulted")
	}
	code, body = p.get("/guard-admin/users?q=BULK07&status=active")
	if code != 200 || !strings.Contains(body, "bulk07@example.com") || strings.Count(body, `class="user-row"`) != 1 {
		t.Fatalf("search: %d", code)
	}
	if _, body = p.get("/guard-admin/users?status=banned"); !strings.Contains(body, "No accounts match") {
		t.Fatal("empty state")
	}
	if code, _ = p.get("/guard-admin/users?status=nope"); code != http.StatusBadRequest {
		t.Fatalf("invalid status: %d", code)
	}
	if code, body = p.get("/guard-admin/users?q=boom"); code != http.StatusInternalServerError || strings.Contains(body, "storage down") {
		t.Fatalf("list failure: %d", code)
	}
	if _, body = p.get("/guard-admin/users?q=%3Cscript%3E"); strings.Contains(body, "<script>") {
		t.Fatal("search not escaped")
	}
}

func TestUsersDetailAccess(t *testing.T) {
	p := usersPanel(t)
	usersLogin(p, "user@example.com")
	if code, body := p.get("/guard-admin/users/2"); code != 200 || !strings.Contains(body, "user@example.com") || strings.Contains(body, "Reset password") || strings.Contains(body, "Assign role") {
		t.Fatalf("self view: %d", code)
	}
	if code, _ := p.get("/guard-admin/users/1"); code != http.StatusForbidden {
		t.Fatalf("other user: %d", code)
	}
	if code, _ := p.get("/guard-admin/users"); code != http.StatusForbidden {
		t.Fatalf("list as user: %d", code)
	}
	posts := map[string]url.Values{
		"/guard-admin/users/new":                   {"user_id": {"9"}, "email": {"x@example.com"}, "password": {"tr0ub4dor-guard-42"}},
		"/guard-admin/users/1/status":              {"status": {"banned"}},
		"/guard-admin/users/1/attributes":          {"attributes": {"{}"}},
		"/guard-admin/users/1/password":            {"password": {"password999"}},
		"/guard-admin/users/1/roles":               {"role": {"admin"}},
		"/guard-admin/users/1/roles/admin/remove":  nil,
		"/guard-admin/users/1/sessions/revoke-all": nil,
		"/guard-admin/users/1/api-keys/revoke-all": nil,
		"/guard-admin/users/2/roles":               {"role": {"admin"}},
		"/guard-admin/users/2/attributes":          {"attributes": {`{"a":1}`}},
	}
	for path, form := range posts {
		if code, _, _ := p.post(path, form); code != http.StatusForbidden {
			t.Fatalf("POST %s as user: %d", path, code)
		}
	}
	if grants, _ := p.g.Access.Grants(context.Background(), "2"); len(grants) != 1 || grants[0].Role.Name != "user" {
		t.Fatalf("user escalated: %+v", grants)
	}
}

func TestUsersDetailAdmin(t *testing.T) {
	p := usersPanel(t)
	ctx := context.Background()
	exp := time.Now().Add(48 * time.Hour)
	_ = p.g.Access.AssignRole(ctx, "2", "admin", "1", &exp)
	_ = p.g.Identity.SetAttributes(ctx, "2", map[string]any{"dept": "<b>ops</b>", "branch": 7})
	if _, _, err := p.g.APIKeys.Issue(ctx, "2", "ci-key", []string{"user.read"}, nil); err != nil {
		t.Fatal(err)
	}
	usersLogin(p, "admin@example.com")
	code, body := p.get("/guard-admin/users/2")
	for _, want := range []string{"user@example.com", "dept", "&lt;b&gt;ops&lt;/b&gt;", "ci-key", "Reset password", "Assign role", "Revoke all sessions", "Revoke all API keys", "Administrator", exp.Local().Format("2006-01-02 15:04")} {
		if code != 200 || !strings.Contains(body, want) {
			t.Fatalf("detail missing %q: %d", want, code)
		}
	}
	if strings.Contains(body, "<b>ops</b>") {
		t.Fatal("attributes not escaped")
	}
	if code, _ := p.get("/guard-admin/users/nobody"); code != http.StatusNotFound {
		t.Fatalf("unknown: %d", code)
	}
	if code, body := p.get("/guard-admin/users/boom"); code != http.StatusInternalServerError || strings.Contains(body, "storage down") {
		t.Fatalf("lookup failure: %d", code)
	}
	p.account("boom-x", "boom@example.com", false)
	if code, _ := p.get("/guard-admin/users/boom-x"); code != http.StatusInternalServerError {
		t.Fatalf("related data failure: %d", code)
	}
}

func TestUsersCreate(t *testing.T) {
	p := usersPanel(t)
	usersLogin(p, "admin@example.com")
	code, _, h := p.post("/guard-admin/users/new", url.Values{"user_id": {"77"}, "email": {"new@example.com"}, "password": {"tr0ub4dor-guard-42"}})
	usersExpect(t, "create", code, h, "/users/77", "flash=")
	if _, err := p.g.Identity.User(context.Background(), "77"); err != nil {
		t.Fatal(err)
	}
	code, _, h = p.post("/guard-admin/users/new", url.Values{"user_id": {"78"}, "email": {"bad"}, "password": {"tr0ub4dor-guard-42"}})
	usersExpect(t, "create invalid", code, h, "/users", "error=identity")
}

func TestUsersStatusAttributesPassword(t *testing.T) {
	p := usersPanel(t)
	ctx := context.Background()
	usersLogin(p, "admin@example.com")

	code, _, h := p.post("/guard-admin/users/2/status", url.Values{"status": {"suspended"}})
	usersExpect(t, "status", code, h, "/users/2", "flash=")
	if u, _ := p.g.Identity.User(ctx, "2"); u.Status != identitydomain.StatusSuspended {
		t.Fatalf("status %s", u.Status)
	}
	code, _, h = p.post("/guard-admin/users/2/status", url.Values{"status": {"weird"}})
	usersExpect(t, "invalid status", code, h, "/users/2", "error=identity")
	code, _, h = p.post("/guard-admin/users/nobody/status", url.Values{"status": {"active"}})
	usersExpect(t, "status unknown", code, h, "/users/nobody", "error=identity")

	code, _, h = p.post("/guard-admin/users/2/attributes", url.Values{"attributes": {`{"dept":"ops","level":3}`}})
	usersExpect(t, "attrs", code, h, "/users/2", "flash=")
	if u, _ := p.g.Identity.User(ctx, "2"); u.Attributes["dept"] != "ops" {
		t.Fatalf("attrs %v", u.Attributes)
	}
	for _, bad := range []string{"not json", "[1,2]", `"str"`} {
		code, _, h = p.post("/guard-admin/users/2/attributes", url.Values{"attributes": {bad}})
		usersExpect(t, "attrs invalid "+bad, code, h, "/users/2", "error=invalid+input")
	}
	code, _, h = p.post("/guard-admin/users/nobody/attributes", url.Values{"attributes": {"{}"}})
	usersExpect(t, "attrs unknown", code, h, "/users/nobody", "error=identity")

	code, _, h = p.post("/guard-admin/users/2/password", url.Values{"password": {"brand-new-pass"}})
	usersExpect(t, "password", code, h, "/users/2", "flash=")
	if ok, _ := p.g.Identity.Authenticate(ctx, "user@example.com", "brand-new-pass"); ok == nil {
		// suspended users fail CanLogin after verifying; reactivate and retry
		_ = p.g.SetUserStatus(ctx, "1", "2", identitydomain.StatusActive)
		if _, err := p.g.Identity.Authenticate(ctx, "user@example.com", "brand-new-pass"); err != nil {
			t.Fatalf("password not reset: %v", err)
		}
	}
	code, _, h = p.post("/guard-admin/users/2/password", url.Values{"password": {"short"}})
	usersExpect(t, "weak password", code, h, "/users/2", "error=identity")
}

func TestUsersRoles(t *testing.T) {
	p := usersPanel(t)
	ctx := context.Background()
	usersLogin(p, "admin@example.com")
	future := time.Now().Add(72 * time.Hour).Format("2006-01-02T15:04")

	code, _, h := p.post("/guard-admin/users/2/roles", url.Values{"role": {"admin"}, "expires_at": {future}})
	usersExpect(t, "assign", code, h, "/users/2", "flash=")
	grants, _ := p.g.Access.Grants(ctx, "2")
	if len(grants) != 2 || grants[0].Role.Name != "admin" || grants[0].ExpiresAt == nil {
		t.Fatalf("grants %+v", grants)
	}
	code, _, h = p.post("/guard-admin/users/2/roles", url.Values{"role": {"user"}})
	usersExpect(t, "assign no expiry", code, h, "/users/2", "flash=")

	past := time.Now().Add(-time.Hour).Format("2006-01-02T15:04")
	for name, form := range map[string]url.Values{
		"past expiry": {"role": {"admin"}, "expires_at": {past}},
		"bad expiry":  {"role": {"admin"}, "expires_at": {"tomorrow"}},
	} {
		code, _, h = p.post("/guard-admin/users/2/roles", form)
		usersExpect(t, name, code, h, "/users/2", "error=invalid+input")
	}
	code, _, h = p.post("/guard-admin/users/2/roles", url.Values{"role": {"ghost"}})
	usersExpect(t, "unknown role", code, h, "/users/2", "error=access")
	code, _, h = p.post("/guard-admin/users/nobody/roles", url.Values{"role": {"admin"}})
	usersExpect(t, "unknown user", code, h, "/users/nobody", "error=identity")

	code, _, h = p.post("/guard-admin/users/2/roles/admin/remove", nil)
	usersExpect(t, "remove", code, h, "/users/2", "flash=")
	if grants, _ = p.g.Access.Grants(ctx, "2"); len(grants) != 1 {
		t.Fatalf("after remove %+v", grants)
	}
	code, _, h = p.post("/guard-admin/users/boom-x/roles/admin/remove", nil)
	usersExpect(t, "remove failure", code, h, "/users/boom-x", "error=internal")

	events, _ := p.g.Audit.List(ctx, "1", 100)
	var assigns, removes int
	for _, e := range events {
		switch e.Action {
		case "role.assign":
			assigns++
		case "role.unassign":
			removes++
		}
	}
	if assigns != 2 || removes != 1 {
		t.Fatalf("audit assigns=%d removes=%d", assigns, removes)
	}
}

func TestUsersRevokeAll(t *testing.T) {
	p := usersPanel(t)
	ctx := context.Background()
	if _, _, err := p.g.APIKeys.Issue(ctx, "2", "k", []string{"user.read"}, nil); err != nil {
		t.Fatal(err)
	}
	usersLogin(p, "user@example.com") // creates a session for user 2
	usersLogin(p, "admin@example.com")

	code, _, h := p.post("/guard-admin/users/2/sessions/revoke-all", nil)
	usersExpect(t, "sessions", code, h, "/users/2", "flash=")
	if s, _ := p.g.Sessions.List(ctx, "2"); len(s) != 0 {
		t.Fatalf("sessions left: %d", len(s))
	}
	code, _, h = p.post("/guard-admin/users/2/api-keys/revoke-all", nil)
	usersExpect(t, "keys", code, h, "/users/2", "flash=")
	if keys, _ := p.g.APIKeys.List(ctx, "2"); len(keys) != 1 || keys[0].RevokedAt == nil {
		t.Fatalf("keys %+v", keys)
	}
	code, _, h = p.post("/guard-admin/users/boom-x/sessions/revoke-all", nil)
	usersExpect(t, "sessions failure", code, h, "/users/boom-x", "error=internal")
	code, _, h = p.post("/guard-admin/users/boom-x/api-keys/revoke-all", nil)
	usersExpect(t, "keys failure", code, h, "/users/boom-x", "error=internal")
}

func TestUsersSuperAdminBadgeAndProtection(t *testing.T) {
	p := usersPanel(t)
	ctx := context.Background()
	p.account("3", "second@example.com", true) // admin, not super admin
	usersLogin(p, "admin@example.com")
	if code, body := p.get("/guard-admin/users/1"); code != 200 || !strings.Contains(body, `data-badge="super-admin"`) {
		t.Fatalf("super admin badge missing: %d", code)
	}
	if _, body := p.get("/guard-admin/users/3"); strings.Contains(body, `data-badge="super-admin"`) {
		t.Fatal("badge on plain admin")
	}

	usersLogin(p, "second@example.com")
	code, _, h := p.post("/guard-admin/users/2/roles", url.Values{"role": {"admin"}})
	usersExpect(t, "admin grants admin", code, h, "/users/2", "error=access")
	code, _, h = p.post("/guard-admin/users/1/roles/super_admin/remove", nil)
	usersExpect(t, "admin revokes super admin", code, h, "/users/1", "error=access")
	if ok, _ := p.g.IsSuperAdmin(ctx, "1"); !ok {
		t.Fatal("super admin revoked by admin")
	}
	code, _, h = p.post("/guard-admin/users/2/roles", url.Values{"role": {"user"}})
	usersExpect(t, "admin grants user", code, h, "/users/2", "flash=")
}
