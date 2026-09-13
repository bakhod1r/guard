package adminui_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

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
	identityinfra "github.com/bakhod1r/guard/identity/infrastructure"
	"github.com/bakhod1r/guard/ratelimit"
	sessiondomain "github.com/bakhod1r/guard/session/domain"
	sessioninfra "github.com/bakhod1r/guard/session/infrastructure"
)

var errDashBoom = errors.New("storage down")

type dashFailRoles struct{ *accessinfra.Memory }

func (dashFailRoles) ListRoles(context.Context) ([]accessdomain.Role, error) { return nil, errDashBoom }
func (dashFailRoles) ListPermissions(context.Context) ([]accessdomain.Permission, error) {
	return nil, errDashBoom
}
func (dashFailRoles) ListPolicies(context.Context) ([]accessdomain.Policy, error) {
	return nil, errDashBoom
}

type dashFailSessions struct{ sessiondomain.Repository }

func (dashFailSessions) ListByUser(context.Context, string) ([]*sessiondomain.Session, error) {
	return nil, errDashBoom
}

type dashFailKeys struct{ apikeydomain.Repository }

func (dashFailKeys) ListByUser(context.Context, string) ([]apikeydomain.Key, error) {
	return nil, errDashBoom
}

type dashFailAudit struct{ audit.Memory }

func (*dashFailAudit) List(context.Context, string, int) ([]audit.Event, error) {
	return nil, errDashBoom
}

// dashPanel builds a panel on a Guard whose storage can fail; auditLog may be nil.
func dashPanel(t *testing.T, failing bool, auditLog audit.Log) *panel {
	t.Helper()
	gin.SetMode(gin.TestMode)
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	store := accessinfra.NewMemory()
	guardtest.Seed(context.Background(), store)
	repos := guard.Repositories{
		Users:    identityinfra.NewMemoryUsers(),
		Hasher:   &identityinfra.Argon2Hasher{Memory: 1024, Time: 1, Threads: 1, KeyLen: 32, SaltLen: 16},
		Sessions: sessioninfra.NewRedisSessions(rdb, "dash:"),
		Roles:    store,
		Policies: store,
		Audit:    auditLog,
		APIKeys:  apikeyinfra.NewMemory(),
		Limiter:  ratelimit.NewRedis(rdb, "dash:"),
	}
	if failing {
		f := dashFailRoles{store}
		repos.Roles, repos.Policies = f, f
		repos.Sessions = dashFailSessions{repos.Sessions}
		repos.APIKeys = dashFailKeys{repos.APIKeys}
	}
	g := guard.Build(repos, guard.Config{})
	r := gin.New()
	adminui.Mount(r, g, adminui.Options{InsecureCookie: true})
	return &panel{t: t, g: g, r: r}
}

func dashContainsAll(t *testing.T, body string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(body, w) {
			t.Fatalf("body missing %q", w)
		}
	}
}

func TestDashboardAdminSeesStats(t *testing.T) {
	p := newPanel(t)
	p.account("1", "admin@example.com", true)
	p.login("admin@example.com")
	code, body := p.get("/guard-admin")
	if code != http.StatusOK {
		t.Fatalf("code %d", code)
	}
	dashContainsAll(t, body, "admin@example.com", `data-stat="roles"`, `data-stat="permissions"`,
		`data-stat="policies"`, `data-stat="sessions"`, `data-stat="apikeys"`, "<b>2</b>", "<b>14</b>", "<b>3</b>", "<b>1</b>", "<b>0</b>",
		`href="/guard-admin/roles"`, `href="/guard-admin/audit"`)
}

func TestDashboardUserSeesOwnStatsOnly(t *testing.T) {
	p := newPanel(t)
	p.account("2", "user@example.com", false)
	p.login("user@example.com")
	code, body := p.get("/guard-admin")
	if code != http.StatusOK {
		t.Fatalf("code %d", code)
	}
	dashContainsAll(t, body, "user@example.com", `data-stat="sessions"`, `data-stat="apikeys"`)
	for _, s := range []string{`data-stat="roles"`, `data-stat="policies"`, `data-stat="permissions"`} {
		if strings.Contains(body, s) {
			t.Fatalf("user sees %s", s)
		}
	}
}

func TestDashboardStorageErrors(t *testing.T) {
	p := dashPanel(t, true, &audit.Memory{})
	p.account("1", "admin@example.com", true)
	p.login("admin@example.com")
	code, body := p.get("/guard-admin")
	if code != http.StatusOK {
		t.Fatalf("code %d", code)
	}
	if n := strings.Count(body, "could not load"); n != 5 {
		t.Fatalf("want 5 stat errors, got %d", n)
	}
}

func TestAuditShowsEventsAndFilters(t *testing.T) {
	p := newPanel(t)
	p.account("1", "admin@example.com", true)
	p.account("2", "user@example.com", false)
	p.login("user@example.com")
	p.login("admin@example.com")
	_ = p.g.Audit.Record(context.Background(), guard.AuditEvent{ActorID: "1", Action: "x.test", Success: false,
		Metadata: map[string]any{"k": "<script>"}})

	code, body := p.get("/guard-admin/audit")
	if code != http.StatusOK {
		t.Fatalf("code %d", code)
	}
	dashContainsAll(t, body, "auth.login", "x.test", "k=&lt;script&gt;", `badge bad`, `badge ok`)
	if strings.Contains(body, "<script>") {
		t.Fatal("metadata not escaped")
	}

	_, body = p.get("/guard-admin/audit?actor_id=2")
	if strings.Contains(body, "x.test") || !strings.Contains(body, "auth.login") {
		t.Fatal("actor filter not applied")
	}
	_, body = p.get("/guard-admin/audit?actor_id=nobody")
	dashContainsAll(t, body, "No audit events")

	_, body = p.get("/guard-admin/audit?limit=1")
	if strings.Count(body, "<tr data-event") != 1 {
		t.Fatal("limit not applied")
	}
	_, body = p.get("/guard-admin/audit")
	all := strings.Count(body, "<tr data-event")
	if all < 3 {
		t.Fatalf("want at least 3 events, got %d", all)
	}
	for _, l := range []string{"abc", "-5", "0", "100000"} {
		code, body := p.get("/guard-admin/audit?limit=" + l)
		if code != http.StatusOK || strings.Count(body, "<tr data-event") != all {
			t.Fatalf("limit %s: %d", l, code)
		}
	}
	_, body = p.get("/guard-admin/audit?limit=100000")
	dashContainsAll(t, body, `value="500"`)
	_, body = p.get("/guard-admin/audit?limit=abc")
	dashContainsAll(t, body, `value="100"`)
}

func TestAuditForbiddenForUser(t *testing.T) {
	p := newPanel(t)
	p.account("2", "user@example.com", false)
	p.login("user@example.com")
	if code, _ := p.get("/guard-admin/audit"); code != http.StatusForbidden {
		t.Fatalf("user opened audit: %d", code)
	}
}

func TestAuditNotConfigured(t *testing.T) {
	p := dashPanel(t, false, nil)
	p.account("1", "admin@example.com", true)
	p.login("admin@example.com")
	code, body := p.get("/guard-admin/audit")
	if code != http.StatusOK || !strings.Contains(body, "audit log not configured") {
		t.Fatalf("code %d", code)
	}
}

func TestAuditListError(t *testing.T) {
	p := dashPanel(t, false, &dashFailAudit{})
	p.account("1", "admin@example.com", true)
	p.login("admin@example.com")
	code, body := p.get("/guard-admin/audit")
	if code != http.StatusOK || !strings.Contains(body, "could not load audit events") {
		t.Fatalf("code %d", code)
	}
}
