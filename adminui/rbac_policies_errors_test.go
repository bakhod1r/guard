package adminui_test

import (
	"context"
	"net/http"
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

// policiesFailing fails ListPolicies once armed.
type policiesFailing struct {
	*accessinfra.Memory
	fail bool
}

func (p *policiesFailing) ListPolicies(ctx context.Context) ([]accessdomain.Policy, error) {
	if p.fail {
		return nil, errRBACStore
	}
	return p.Memory.ListPolicies(ctx)
}

func TestRolePoliciesAndPolicyFormStorageErrors(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mem := accessinfra.NewMemory()
	guardtest.Seed(context.Background(), mem)
	roles := &rbacFailing{Memory: mem, fail: map[string]bool{}}
	pols := &policiesFailing{Memory: mem}
	g := guard.Build(guard.Repositories{
		Users:    identityinfra.NewMemoryUsers(),
		Hasher:   &identityinfra.Argon2Hasher{Memory: 1024, Time: 1, Threads: 1, KeyLen: 32, SaltLen: 16},
		Sessions: sessioninfra.NewRedisSessions(rdb, "t:"),
		Roles:    roles, Policies: pols, Audit: &audit.Memory{},
		APIKeys: apikeyinfra.NewMemory(), Limiter: ratelimit.NewRedis(rdb, "t:"),
	}, guard.Config{})
	r := gin.New()
	adminui.Mount(r, g, adminui.Options{InsecureCookie: true})
	p := &panel{t: t, g: g, r: r}
	p.account("1", "admin@example.com", true)
	p.login("admin@example.com")

	pols.fail = true
	if code, _ := p.get("/guard-admin/roles/user"); code != http.StatusInternalServerError {
		t.Fatalf("role policies err: %d", code)
	}
	pols.fail = false

	roles.fail["ListRoles"] = true
	if code, _ := p.get("/guard-admin/policies/new"); code != http.StatusInternalServerError {
		t.Fatalf("policy form roles err: %d", code)
	}
}
