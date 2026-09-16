package ginguard_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"

	"github.com/bakhod1r/guard"
	accessdomain "github.com/bakhod1r/guard/access/domain"
	accessinfra "github.com/bakhod1r/guard/access/infrastructure"
	apikeydomain "github.com/bakhod1r/guard/apikey/domain"
	apikeyinfra "github.com/bakhod1r/guard/apikey/infrastructure"
	"github.com/bakhod1r/guard/audit"
	"github.com/bakhod1r/guard/ginguard"
	"github.com/bakhod1r/guard/guardtest"
	identitydomain "github.com/bakhod1r/guard/identity/domain"
	identityinfra "github.com/bakhod1r/guard/identity/infrastructure"
	"github.com/bakhod1r/guard/ratelimit"
	sessiondomain "github.com/bakhod1r/guard/session/domain"
	sessioninfra "github.com/bakhod1r/guard/session/infrastructure"
)

var errBoom = errors.New("boom: storage unavailable")

// faults injects errors into repository calls: method -> (arg or "*") -> error.
type faults struct {
	mu sync.Mutex
	m  map[string]map[string]error
}

func (f *faults) set(method, arg string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.m == nil {
		f.m = map[string]map[string]error{}
	}
	if f.m[method] == nil {
		f.m[method] = map[string]error{}
	}
	f.m[method][arg] = err
}

func (f *faults) check(method, arg string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if e, ok := f.m[method][arg]; ok {
		return e
	}
	return f.m[method]["*"]
}

type users struct {
	identitydomain.UserRepository
	f *faults
}

func (r users) ByID(ctx context.Context, id identitydomain.UserID) (*identitydomain.User, error) {
	if err := r.f.check("Users.ByID", string(id)); err != nil {
		return nil, err
	}
	u, err := r.UserRepository.ByID(ctx, id)
	if err == nil && r.f.check("Users.ByID.nilAttributes", string(id)) != nil {
		u.Attributes = nil
	}
	return u, err
}

func (r users) Update(ctx context.Context, u *identitydomain.User) error {
	if err := r.f.check("Users.Update", string(u.ID)); err != nil {
		return err
	}
	return r.UserRepository.Update(ctx, u)
}

type sessions struct {
	sessiondomain.Repository
	f *faults
}

func (r sessions) Save(ctx context.Context, s *sessiondomain.Session, ttl time.Duration) error {
	if err := r.f.check("Sessions.Save", s.UserID); err != nil {
		return err
	}
	return r.Repository.Save(ctx, s, ttl)
}

func (r sessions) Get(ctx context.Context, id sessiondomain.ID) (*sessiondomain.Session, error) {
	if err := r.f.check("Sessions.Get", "*"); err != nil {
		return nil, err
	}
	return r.Repository.Get(ctx, id)
}

func (r sessions) Delete(ctx context.Context, id sessiondomain.ID) error {
	if err := r.f.check("Sessions.Delete", "*"); err != nil {
		return err
	}
	return r.Repository.Delete(ctx, id)
}

func (r sessions) ListByUser(ctx context.Context, userID string) ([]*sessiondomain.Session, error) {
	if err := r.f.check("Sessions.ListByUser", userID); err != nil {
		return nil, err
	}
	return r.Repository.ListByUser(ctx, userID)
}

func (r sessions) DeleteByUser(ctx context.Context, userID string) error {
	if err := r.f.check("Sessions.DeleteByUser", userID); err != nil {
		return err
	}
	return r.Repository.DeleteByUser(ctx, userID)
}

type roles struct {
	accessdomain.RoleRepository
	f *faults
}

func (r roles) ListRoles(ctx context.Context) ([]accessdomain.Role, error) {
	if err := r.f.check("Roles.ListRoles", "*"); err != nil {
		return nil, err
	}
	return r.RoleRepository.ListRoles(ctx)
}

func (r roles) ListPermissions(ctx context.Context) ([]accessdomain.Permission, error) {
	if err := r.f.check("Roles.ListPermissions", "*"); err != nil {
		return nil, err
	}
	return r.RoleRepository.ListPermissions(ctx)
}

func (r roles) CreatePermission(ctx context.Context, p accessdomain.Permission) error {
	if err := r.f.check("Roles.CreatePermission", "*"); err != nil {
		return err
	}
	return r.RoleRepository.CreatePermission(ctx, p)
}

func (r roles) RevokePermission(ctx context.Context, role string, p accessdomain.Permission) error {
	if err := r.f.check("Roles.RevokePermission", role); err != nil {
		return err
	}
	return r.RoleRepository.RevokePermission(ctx, role, p)
}

func (r roles) AssignRole(ctx context.Context, userID, role, by string, exp *time.Time) error {
	if err := r.f.check("Roles.AssignRole", userID); err != nil {
		return err
	}
	return r.RoleRepository.AssignRole(ctx, userID, role, by, exp)
}

func (r roles) UnassignRole(ctx context.Context, userID, role string) error {
	if err := r.f.check("Roles.UnassignRole", userID); err != nil {
		return err
	}
	return r.RoleRepository.UnassignRole(ctx, userID, role)
}

func (r roles) GrantsOf(ctx context.Context, userID string) ([]accessdomain.RoleGrant, error) {
	if err := r.f.check("Roles.GrantsOf", userID); err != nil {
		return nil, err
	}
	return r.RoleRepository.GrantsOf(ctx, userID)
}

type policies struct {
	accessdomain.PolicyRepository
	f *faults
}

func (r policies) SavePolicy(ctx context.Context, p *accessdomain.Policy) error {
	if err := r.f.check("Policies.SavePolicy", "*"); err != nil {
		return err
	}
	return r.PolicyRepository.SavePolicy(ctx, p)
}

func (r policies) ListPolicies(ctx context.Context) ([]accessdomain.Policy, error) {
	if err := r.f.check("Policies.ListPolicies", "*"); err != nil {
		return nil, err
	}
	return r.PolicyRepository.ListPolicies(ctx)
}

func (r policies) ApplicablePolicies(ctx context.Context, resource, action string) ([]accessdomain.Policy, error) {
	if err := r.f.check("Policies.ApplicablePolicies", resource); err != nil {
		return nil, err
	}
	return r.PolicyRepository.ApplicablePolicies(ctx, resource, action)
}

type apiKeys struct {
	apikeydomain.Repository
	f *faults
}

func (r apiKeys) Create(ctx context.Context, k *apikeydomain.Key) error {
	if err := r.f.check("APIKeys.Create", k.UserID); err != nil {
		return err
	}
	return r.Repository.Create(ctx, k)
}

func (r apiKeys) ListByUser(ctx context.Context, userID string) ([]apikeydomain.Key, error) {
	if err := r.f.check("APIKeys.ListByUser", userID); err != nil {
		return nil, err
	}
	return r.Repository.ListByUser(ctx, userID)
}

func (r apiKeys) RevokeAllByUser(ctx context.Context, userID string, at time.Time) error {
	if err := r.f.check("APIKeys.RevokeAllByUser", userID); err != nil {
		return err
	}
	return r.Repository.RevokeAllByUser(ctx, userID, at)
}

type auditLog struct {
	audit.Log
	f *faults
}

func (r auditLog) List(ctx context.Context, actorID string, limit int) ([]audit.Event, error) {
	if err := r.f.check("Audit.List", "*"); err != nil {
		return nil, err
	}
	return r.Log.List(ctx, actorID, limit)
}

type limiterFunc func(ctx context.Context, key string, rule ratelimit.Rule) (ratelimit.Result, error)

func (l limiterFunc) Allow(ctx context.Context, key string, rule ratelimit.Rule) (ratelimit.Result, error) {
	return l(ctx, key, rule)
}

type envConfig struct {
	noAudit    bool
	limiter    ratelimit.Limiter
	createUser func(context.Context, string) (string, error)
	rule       ratelimit.Rule
}

type env struct {
	t      *testing.T
	router *gin.Engine
	g      *guard.Guard
	f      *faults
	admin  string
}

type resp struct {
	code int
	body map[string]any
	w    *httptest.ResponseRecorder
}

func (r resp) errCode() string {
	if e, ok := r.body["error"].(map[string]any); ok {
		s, _ := e["code"].(string)
		return s
	}
	return ""
}

// raw sends body verbatim; headers are applied as given.
func (e *env) raw(method, path, body string, headers map[string]string) resp {
	e.t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	e.router.ServeHTTP(w, req)
	out := map[string]any{}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return resp{code: w.Code, body: out, w: w}
}

func (e *env) do(method, path, token string, body any) resp {
	e.t.Helper()
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	h := map[string]string{}
	if token != "" {
		h["Authorization"] = "Bearer " + token
	}
	return e.raw(method, path, buf.String(), h)
}

func (e *env) login(email, password string) string {
	e.t.Helper()
	r := e.do("POST", "/auth/login", "", map[string]any{"email": email, "password": password})
	if r.code != http.StatusOK {
		e.t.Fatalf("login %s: %d %v", email, r.code, r.body)
	}
	return r.body["token"].(string)
}

// newEnv builds a Guard with guard.Build over fault-injecting in-memory repositories.
func newEnv(t *testing.T, cfg envConfig) *env {
	t.Helper()
	gin.SetMode(gin.TestMode)
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	f := &faults{}
	store := accessinfra.NewMemory()
	guardtest.Seed(context.Background(), store)
	repos := guard.Repositories{
		Users:    users{identityinfra.NewMemoryUsers(), f},
		Hasher:   &identityinfra.Argon2Hasher{Memory: 1024, Time: 1, Threads: 1, KeyLen: 32, SaltLen: 16},
		Sessions: sessions{sessioninfra.NewRedisSessions(rdb, "cov:"), f},
		Roles:    roles{store, f},
		Policies: policies{store, f},
		APIKeys:  apiKeys{apikeyinfra.NewMemory(), f},
		Limiter:  cfg.limiter,
	}
	if !cfg.noAudit {
		repos.Audit = auditLog{&audit.Memory{}, f}
	}
	g := guard.Build(repos, guard.Config{})
	if cfg.rule == (ratelimit.Rule{}) {
		cfg.rule = ratelimit.Rule{Limit: -1}
	}
	r := gin.New()
	ginguard.Mount(r, g, ginguard.Options{AuthRateLimit: cfg.rule, CreateUser: cfg.createUser, InsecureCookie: true})
	e := &env{t: t, router: r, g: g, f: f}
	if _, err := g.EnsureAdmin(context.Background(), "1", "admin@example.com", "admin-password"); err != nil {
		t.Fatal(err)
	}
	e.admin = e.login("admin@example.com", "admin-password")
	return e
}

func (e *env) account(id, email string) string {
	e.t.Helper()
	if _, err := e.g.CreateAccount(context.Background(), id, email, "tr0ub4dor-guard-42", nil, guard.RequestMeta{}); err != nil {
		e.t.Fatal(err)
	}
	return e.login(email, "tr0ub4dor-guard-42")
}

func TestHandlersRejectMalformedJSONWithInvalidBody(t *testing.T) {
	e := newEnv(t, envConfig{createUser: func(context.Context, string) (string, error) { return "9", nil }})
	routes := []struct{ method, path string }{
		{"POST", "/auth/register"},
		{"POST", "/auth/login"},
		{"POST", "/auth/authorize"},
		{"PUT", "/auth/password"},
		{"POST", "/auth/api-keys"},
		{"POST", "/guard/users/2/account"},
		{"PUT", "/guard/users/1/password"},
		{"PUT", "/guard/users/1/status"},
		{"PUT", "/guard/users/1/attributes"},
		{"POST", "/guard/users/1/roles"},
		{"POST", "/guard/roles"},
		{"POST", "/guard/roles/admin/permissions"},
		{"POST", "/guard/permissions"},
		{"POST", "/guard/policies"},
		{"PUT", "/guard/policies/00000000-0000-0000-0000-000000000001"},
	}
	for _, rt := range routes {
		t.Run(rt.method+" "+rt.path, func(t *testing.T) {
			r := e.raw(rt.method, rt.path, "{not json", map[string]string{"Authorization": "Bearer " + e.admin})
			if r.code != http.StatusBadRequest || r.errCode() != "invalid_body" {
				t.Fatalf("want 400 invalid_body, got %d %v", r.code, r.body)
			}
		})
	}
}

func TestDomainErrorsMapToDocumentedStatusAndCode(t *testing.T) {
	e := newEnv(t, envConfig{createUser: func(_ context.Context, email string) (string, error) {
		if email == "host-fails@example.com" {
			return "", identitydomain.ErrEmailTaken
		}
		return "77", nil
	}})
	userTok := e.account("2", "user@example.com")
	past := time.Now().Add(-time.Hour)
	cases := []struct {
		name, method, path, token string
		body                      any
		status                    int
		code                      string
	}{
		{"register invalid email", "POST", "/auth/register", "", map[string]any{"email": "nope", "password": "tr0ub4dor-guard-42"}, 400, "invalid_email"},
		{"register weak password", "POST", "/auth/register", "", map[string]any{"email": "w@example.com", "password": "x"}, 400, "weak_password"},
		{"register host CreateUser error", "POST", "/auth/register", "", map[string]any{"email": "host-fails@example.com", "password": "tr0ub4dor-guard-42"}, 409, "email_taken"},
		{"login invalid credentials", "POST", "/auth/login", "", map[string]any{"email": "admin@example.com", "password": "wrong-password"}, 401, "invalid_credentials"},
		{"invalid status", "PUT", "/guard/users/2/status", e.admin, map[string]any{"status": "zombie"}, 400, "invalid_status"},
		{"set status unknown user", "PUT", "/guard/users/404/status", e.admin, map[string]any{"status": "active"}, 404, "user_not_found"},
		{"get unknown user", "GET", "/guard/users/404", e.admin, nil, 404, "user_not_found"},
		{"attributes unknown user", "PUT", "/guard/users/404/attributes", e.admin, map[string]any{"attributes": map[string]any{"a": 1}}, 404, "user_not_found"},
		{"reset password unknown user", "PUT", "/guard/users/404/password", e.admin, map[string]any{"password": "tr0ub4dor-guard-42"}, 404, "user_not_found"},
		{"invalid user id", "POST", "/guard/users/%20/account", e.admin, map[string]any{"email": "s@example.com", "password": "tr0ub4dor-guard-42"}, 400, "invalid_user_id"},
		{"account exists", "POST", "/guard/users/2/account", e.admin, map[string]any{"email": "o@example.com", "password": "tr0ub4dor-guard-42"}, 409, "account_exists"},
		{"revoke unknown own session", "DELETE", "/auth/sessions/does-not-exist", e.admin, nil, 404, "session_not_found"},
		{"invalid role name", "POST", "/guard/roles", e.admin, map[string]any{"name": "Bad Name!"}, 400, "invalid_name"},
		{"invalid permission code", "POST", "/guard/permissions", e.admin, map[string]any{"code": "nodot"}, 400, "invalid_permission"},
		{"grant invalid permission code", "POST", "/guard/roles/user/permissions", e.admin, map[string]any{"code": "nodot"}, 400, "invalid_permission"},
		{"invalid policy", "POST", "/guard/policies", e.admin, map[string]any{"name": "bad", "resource": "x", "action": "y", "effect": "maybe"}, 400, "invalid_policy"},
		{"role exists", "POST", "/guard/roles", e.admin, map[string]any{"name": "admin"}, 409, "role_exists"},
		{"policy name taken", "POST", "/guard/policies", e.admin, map[string]any{"name": "self-service user read", "resource": "user", "action": "read", "effect": "allow", "enabled": true}, 409, "policy_name_taken"},
		{"system role", "DELETE", "/guard/roles/admin", e.admin, nil, 409, "system_role"},
		{"get unknown role", "GET", "/guard/roles/ghost", e.admin, nil, 404, "role_not_found"},
		{"delete unknown role", "DELETE", "/guard/roles/ghost", e.admin, nil, 404, "role_not_found"},
		{"assign unknown role", "POST", "/guard/users/2/roles", e.admin, map[string]any{"role": "ghost"}, 404, "role_not_found"},
		{"grant unknown permission", "POST", "/guard/roles/user/permissions", e.admin, map[string]any{"code": "ghost.read"}, 404, "permission_not_found"},
		{"get unknown policy", "GET", "/guard/policies/ghost", e.admin, nil, 404, "policy_not_found"},
		{"update unknown policy", "PUT", "/guard/policies/ghost", e.admin, map[string]any{}, 404, "policy_not_found"},
		{"delete unknown policy", "DELETE", "/guard/policies/ghost", e.admin, nil, 404, "policy_not_found"},
		{"api key invalid name", "POST", "/auth/api-keys", e.admin, map[string]any{"name": "   ", "scopes": []string{"invoice.read"}}, 400, "invalid_name"},
		{"api key invalid scope", "POST", "/auth/api-keys", e.admin, map[string]any{"name": "ci", "scopes": []string{"Bad"}}, 400, "invalid_scope"},
		{"api key no scopes", "POST", "/auth/api-keys", e.admin, map[string]any{"name": "ci", "scopes": []string{}}, 400, "invalid_scope"},
		{"api key past expiry", "POST", "/auth/api-keys", e.admin, map[string]any{"name": "ci", "scopes": []string{"invoice.read"}, "expires_at": past}, 400, "invalid_expiry"},
		{"revoke unknown api key", "DELETE", "/auth/api-keys/ghost", e.admin, nil, 404, "api_key_not_found"},
		{"forged api key", "GET", "/auth/me", "gk_forged", nil, 401, "unauthenticated"},
		{"assign role past expiry", "POST", "/guard/users/2/roles", e.admin, map[string]any{"role": "user", "expires_at": past}, 400, "invalid_expiry"},
		{"assign role unknown user", "POST", "/guard/users/404/roles", e.admin, map[string]any{"role": "user"}, 404, "user_not_found"},
		{"non-admin forbidden", "GET", "/guard/roles", userTok, nil, 403, "forbidden"},
		{"change password wrong old", "PUT", "/auth/password", userTok, map[string]any{"old_password": "wrong-password", "new_password": "tr0ub4dor-guard-43"}, 401, "invalid_credentials"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := e.do(tc.method, tc.path, tc.token, tc.body)
			if r.code != tc.status || r.errCode() != tc.code {
				t.Fatalf("want %d %q, got %d %v", tc.status, tc.code, r.code, r.body)
			}
		})
	}
}

func TestInjectedDomainErrorsWithoutNaturalTrigger(t *testing.T) {
	e := newEnv(t, envConfig{})
	e.account("2", "user@example.com")
	e.f.set("Roles.AssignRole", "2", accessdomain.ErrSubjectNotFound)
	e.f.set("APIKeys.Create", "1", apikeydomain.ErrOwnerNotFound)
	if r := e.do("POST", "/guard/users/2/roles", e.admin, map[string]any{"role": "user"}); r.code != 404 || r.errCode() != "user_not_found" {
		t.Fatalf("subject not found: %d %v", r.code, r.body)
	}
	if r := e.do("POST", "/auth/api-keys", e.admin, map[string]any{"name": "ci", "scopes": []string{"invoice.read"}}); r.code != 404 || r.errCode() != "user_not_found" {
		t.Fatalf("owner not found: %d %v", r.code, r.body)
	}
}

func TestLockedAndBlockedAccounts(t *testing.T) {
	e := newEnv(t, envConfig{})
	e.account("2", "lock@example.com")
	for i := 0; i < 5; i++ {
		e.do("POST", "/auth/login", "", map[string]any{"email": "lock@example.com", "password": "wrong-password"})
	}
	if r := e.do("POST", "/auth/login", "", map[string]any{"email": "lock@example.com", "password": "tr0ub4dor-guard-42"}); r.code != 401 || r.errCode() != "invalid_credentials" {
		t.Fatalf("locked: %d %v", r.code, r.body)
	}
	e.account("3", "ban@example.com")
	if r := e.do("PUT", "/guard/users/3/status", e.admin, map[string]any{"status": "suspended"}); r.code != 204 {
		t.Fatalf("suspend: %d %v", r.code, r.body)
	}
	if r := e.do("POST", "/auth/login", "", map[string]any{"email": "ban@example.com", "password": "tr0ub4dor-guard-42"}); r.code != 401 || r.errCode() != "invalid_credentials" {
		t.Fatalf("blocked: %d %v", r.code, r.body)
	}
}

func TestStorageFailuresReturnInternalError(t *testing.T) {
	cases := []struct {
		name, method, path string
		body               any
		method2, arg       string
		useKey             bool
	}{
		{"authenticate session lookup", "GET", "/auth/me", nil, "Sessions.Get", "*", false},
		{"login session start", "POST", "/auth/login", map[string]any{"email": "admin@example.com", "password": "admin-password"}, "Sessions.Save", "1", false},
		{"authorize endpoint policies", "POST", "/auth/authorize", map[string]any{"action": "read", "resource": map[string]any{"type": "invoice"}}, "Policies.ApplicablePolicies", "invoice", false},
		{"require authorize policies", "GET", "/guard/roles", nil, "Policies.ApplicablePolicies", "role", false},
		{"logout revoke", "POST", "/auth/logout", nil, "Sessions.Delete", "*", false},
		{"logout-all", "POST", "/auth/logout-all", nil, "Sessions.DeleteByUser", "1", false},
		{"change password update", "PUT", "/auth/password", map[string]any{"old_password": "admin-password", "new_password": "admin-password2"}, "Users.Update", "1", false},
		{"my sessions", "GET", "/auth/sessions", nil, "Sessions.ListByUser", "1", false},
		{"revoke my session list", "DELETE", "/auth/sessions/x", nil, "Sessions.ListByUser", "1", false},
		{"my api keys", "GET", "/auth/api-keys", nil, "APIKeys.ListByUser", "1", false},
		{"user roles", "GET", "/guard/users/2/roles", nil, "Roles.GrantsOf", "2", false},
		{"user sessions", "GET", "/guard/users/2/sessions", nil, "Sessions.ListByUser", "2", false},
		{"revoke user sessions", "DELETE", "/guard/users/2/sessions", nil, "Sessions.DeleteByUser", "2", false},
		{"user api keys", "GET", "/guard/users/2/api-keys", nil, "APIKeys.ListByUser", "2", false},
		{"revoke user api keys", "DELETE", "/guard/users/2/api-keys", nil, "APIKeys.RevokeAllByUser", "2", false},
		{"unassign role", "DELETE", "/guard/users/2/roles/user", nil, "Roles.UnassignRole", "2", false},
		{"list roles", "GET", "/guard/roles", nil, "Roles.ListRoles", "*", false},
		{"revoke permission", "DELETE", "/guard/roles/user/permissions/user.read", nil, "Roles.RevokePermission", "user", false},
		{"list permissions", "GET", "/guard/permissions", nil, "Roles.ListPermissions", "*", false},
		{"create permission", "POST", "/guard/permissions", map[string]any{"code": "invoice.read"}, "Roles.CreatePermission", "*", false},
		{"list policies", "GET", "/guard/policies", nil, "Policies.ListPolicies", "*", false},
		{"update policy save", "PUT", "/guard/policies/00000000-0000-0000-0000-000000000001", map[string]any{"name": "p", "resource": "user", "action": "read", "effect": "allow"}, "Policies.SavePolicy", "*", false},
		{"revoke my session delete", "DELETE", "/auth/sessions/CURRENT", nil, "Sessions.Delete", "*", false},
		{"list audit", "GET", "/guard/audit", nil, "Audit.List", "*", false},
		{"api key principal roles", "GET", "/auth/me", nil, "Roles.GrantsOf", "1", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, envConfig{})
			e.account("2", "user@example.com")
			token := e.admin
			if tc.useKey {
				k := e.do("POST", "/auth/api-keys", e.admin, map[string]any{"name": "ci", "scopes": []string{"*"}})
				token = k.body["token"].(string)
			}
			path := tc.path
			if strings.HasSuffix(path, "CURRENT") {
				list := e.do("GET", "/auth/sessions", e.admin, nil)
				path = strings.Replace(path, "CURRENT", list.body["sessions"].([]any)[0].(map[string]any)["id"].(string), 1)
			}
			e.f.set(tc.method2, tc.arg, errBoom)
			r := e.do(tc.method, path, token, tc.body)
			if r.code != http.StatusInternalServerError || r.errCode() != "internal" {
				t.Fatalf("want 500 internal, got %d %v", r.code, r.body)
			}
		})
	}
}

func TestAdminSuccessPathsAndAuditTrail(t *testing.T) {
	e := newEnv(t, envConfig{})
	userTok := e.account("2", "user@example.com")
	if r := e.do("POST", "/auth/api-keys", userTok, map[string]any{"name": "ci", "scopes": []string{"invoice.read"}}); r.code != 201 {
		t.Fatalf("issue: %d %v", r.code, r.body)
	}
	policyID := "00000000-0000-0000-0000-000000000001"
	steps := []struct {
		method, path string
		body         any
		want         int
	}{
		{"POST", "/guard/permissions", map[string]any{"code": "invoice.read", "description": "read invoices"}, 201},
		{"GET", "/guard/permissions", nil, 200},
		{"POST", "/guard/roles", map[string]any{"name": "accountant"}, 201},
		{"GET", "/guard/roles", nil, 200},
		{"GET", "/guard/roles/accountant", nil, 200},
		{"POST", "/guard/roles/accountant/permissions", map[string]any{"code": "invoice.read"}, 204},
		{"DELETE", "/guard/roles/accountant/permissions/invoice.read", nil, 204},
		{"POST", "/guard/users/2/roles", map[string]any{"role": "accountant", "expires_at": time.Now().Add(time.Hour)}, 204},
		{"GET", "/guard/users/2/roles", nil, 200},
		{"DELETE", "/guard/users/2/roles/accountant", nil, 204},
		{"DELETE", "/guard/roles/accountant", nil, 204},
		{"GET", "/guard/users/2", nil, 200},
		{"PUT", "/guard/users/2/status", map[string]any{"status": "active"}, 204},
		{"GET", "/guard/users/2/sessions", nil, 200},
		{"GET", "/guard/users/2/api-keys", nil, 200},
		{"DELETE", "/guard/users/2/api-keys", nil, 204},
		{"DELETE", "/guard/users/2/sessions", nil, 204},
		{"GET", "/guard/policies", nil, 200},
		{"GET", "/guard/policies/" + policyID, nil, 200},
		{"PUT", "/guard/policies/" + policyID, map[string]any{"name": "renamed", "resource": "user", "action": "read", "effect": "allow", "enabled": true}, 200},
		{"PUT", "/guard/policies/" + policyID, map[string]any{"name": "renamed", "resource": "user", "action": "read", "effect": "maybe"}, 400},
		{"DELETE", "/guard/policies/" + policyID, nil, 204},
		{"GET", "/guard/audit?limit=5&actor_id=1", nil, 200},
	}
	for _, s := range steps {
		if r := e.do(s.method, s.path, e.admin, s.body); r.code != s.want {
			t.Fatalf("%s %s: want %d got %d %v", s.method, s.path, s.want, r.code, r.body)
		}
	}
	if r := e.do("GET", "/auth/me", userTok, nil); r.code != 401 {
		t.Fatalf("user session survived admin revoke-all: %d", r.code)
	}
	r := e.do("GET", "/guard/audit", e.admin, nil)
	actions := map[string]bool{}
	for _, ev := range r.body["events"].([]any) {
		actions[ev.(map[string]any)["action"].(string)] = true
	}
	for _, a := range []string{"role.create", "role.grant", "role.revoke", "role.assign", "role.unassign", "role.delete",
		"apikey.revoke_all", "session.revoke_all", "policy.update", "policy.delete"} {
		if !actions[a] {
			t.Errorf("audit missing %s: %v", a, actions)
		}
	}
}

func TestAdminSessionsFromAPIKeyHasNoCurrentSession(t *testing.T) {
	e := newEnv(t, envConfig{})
	k := e.do("POST", "/auth/api-keys", e.admin, map[string]any{"name": "ops", "scopes": []string{"session.read"}})
	r := e.do("GET", "/guard/users/1/sessions", k.body["token"].(string), nil)
	if r.code != 200 {
		t.Fatalf("%d %v", r.code, r.body)
	}
	for _, s := range r.body["sessions"].([]any) {
		if s.(map[string]any)["current"] != false {
			t.Fatalf("api key marked a session current: %v", s)
		}
	}
	if r := e.do("GET", "/auth/me", k.body["token"].(string), nil); r.code != 200 || r.body["api_key"] == nil {
		t.Fatalf("me via key: %d %v", r.code, r.body)
	}
}

func TestSelfServiceSessionsAndKeys(t *testing.T) {
	e := newEnv(t, envConfig{})
	second := e.login("admin@example.com", "admin-password")
	list := e.do("GET", "/auth/sessions", e.admin, nil)
	var otherID string
	for _, s := range list.body["sessions"].([]any) {
		if m := s.(map[string]any); m["current"] == false {
			otherID = m["id"].(string)
		}
	}
	if r := e.do("DELETE", "/auth/sessions/"+otherID, e.admin, nil); r.code != 204 {
		t.Fatalf("revoke own session: %d %v", r.code, r.body)
	}
	if r := e.do("GET", "/auth/me", second, nil); r.code != 401 {
		t.Fatalf("revoked session alive: %d", r.code)
	}
	r := e.do("POST", "/auth/logout-all", e.admin, nil)
	if r.code != 204 || !strings.Contains(r.w.Header().Get("Set-Cookie"), "guard_session=;") {
		t.Fatalf("logout-all: %d %v", r.code, r.w.Header())
	}
	if r := e.do("GET", "/auth/me", e.admin, nil); r.code != 401 {
		t.Fatalf("session alive after logout-all: %d", r.code)
	}
}

func TestChangePasswordSessionListFailureIsInternal(t *testing.T) {
	e := newEnv(t, envConfig{})
	e.f.set("Sessions.ListByUser", "1", errBoom)
	r := e.do("PUT", "/auth/password", e.admin, map[string]any{"old_password": "admin-password", "new_password": "admin-password2"})
	if r.code != 500 || r.errCode() != "internal" {
		t.Fatalf("%d %v", r.code, r.body)
	}
}

func TestUserWithoutAttributesSerializesEmptyObject(t *testing.T) {
	e := newEnv(t, envConfig{})
	e.account("2", "user@example.com")
	e.f.set("Users.ByID.nilAttributes", "2", errBoom)
	r := e.do("GET", "/guard/users/2", e.admin, nil)
	if attrs, ok := r.body["attributes"].(map[string]any); r.code != 200 || !ok || len(attrs) != 0 {
		t.Fatalf("%d %v", r.code, r.body)
	}
}

func TestAuditListWithoutAuditLog(t *testing.T) {
	e := newEnv(t, envConfig{noAudit: true})
	if r := e.do("POST", "/guard/roles", e.admin, map[string]any{"name": "ops"}); r.code != 201 {
		t.Fatalf("create role without audit: %d", r.code)
	}
	r := e.do("GET", "/guard/audit", e.admin, nil)
	if ev, ok := r.body["events"].([]any); r.code != 200 || !ok || len(ev) != 0 {
		t.Fatalf("%d %v", r.code, r.body)
	}
}

func TestCredentialSources(t *testing.T) {
	e := newEnv(t, envConfig{})
	k := e.do("POST", "/auth/api-keys", e.admin, map[string]any{"name": "ci", "scopes": []string{"*"}})
	key := k.body["token"].(string)
	cases := []struct {
		name    string
		headers map[string]string
		want    int
	}{
		{"session cookie", map[string]string{"Cookie": "guard_session=" + e.admin}, 200},
		{"X-API-Key header", map[string]string{"X-API-Key": key}, 200},
		{"lowercase bearer", map[string]string{"Authorization": "bearer " + e.admin}, 200},
		{"no credential", nil, 401},
		{"non-bearer authorization ignored", map[string]string{"Authorization": "Basic Zm9vOmJhcg=="}, 401},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if r := e.raw("GET", "/auth/me", "", tc.headers); r.code != tc.want {
				t.Fatalf("want %d got %d %v", tc.want, r.code, r.body)
			}
		})
	}
	if r := e.raw("POST", "/auth/logout", "", map[string]string{"X-API-Key": key}); r.code != 403 || r.errCode() != "session_required" {
		t.Fatalf("RequireSession accepted API key: %d %v", r.code, r.body)
	}
	if r := e.raw("POST", "/auth/logout", "", nil); r.code != 401 {
		t.Fatalf("RequireSession without credential: %d", r.code)
	}
}

func TestLoginSetsHardenedCookie(t *testing.T) {
	e := newEnv(t, envConfig{})
	r := e.do("POST", "/auth/login", "", map[string]any{"email": "admin@example.com", "password": "admin-password"})
	ck := r.w.Header().Get("Set-Cookie")
	if r.code != 200 || !strings.Contains(ck, "HttpOnly") || !strings.Contains(ck, "SameSite=Strict") {
		t.Fatalf("cookie: %d %q", r.code, ck)
	}
}

func TestRegisterCreatesAccount(t *testing.T) {
	e := newEnv(t, envConfig{createUser: func(context.Context, string) (string, error) { return "5", nil }})
	r := e.do("POST", "/auth/register", "", map[string]any{"email": "new@example.com", "password": "tr0ub4dor-guard-42"})
	if r.code != 201 || r.body["id"] != "5" {
		t.Fatalf("%d %v", r.code, r.body)
	}
}

func TestAuthenticateMiddlewareIsOptional(t *testing.T) {
	e := newEnv(t, envConfig{})
	whoami := func(c *gin.Context) {
		p := ginguard.PrincipalFrom(c)
		if p == nil {
			c.JSON(200, gin.H{"user": nil, "bucket": ginguard.ByPrincipal(c)})
			return
		}
		c.JSON(200, gin.H{"user": string(p.User.ID), "bucket": ginguard.ByPrincipal(c)})
	}
	e.router.GET("/optional", ginguard.Authenticate(e.g, ginguard.Options{}), whoami)
	// Authenticate twice, then RequireAuth: an attached principal is reused.
	e.router.GET("/double", ginguard.Authenticate(e.g, ginguard.Options{}), ginguard.Authenticate(e.g, ginguard.Options{}),
		ginguard.RequireAuth(e.g, ginguard.Options{}), whoami)
	k := e.do("POST", "/auth/api-keys", e.admin, map[string]any{"name": "ci", "scopes": []string{"*"}})
	key := k.body["token"].(string)
	keyID := k.body["api_key"].(map[string]any)["id"].(string)

	cases := []struct {
		name, path, token string
		wantUser          any
		wantBucket        string
	}{
		{"anonymous", "/optional", "", nil, "ip:192.0.2.1"},
		{"invalid token ignored", "/optional", "not-a-session", nil, "ip:192.0.2.1"},
		{"valid session", "/optional", e.admin, "1", "user:1"},
		{"valid api key", "/optional", key, "1", "key:" + keyID},
		{"principal reused", "/double", e.admin, "1", "user:1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := e.do("GET", tc.path, tc.token, nil)
			if r.code != 200 || r.body["user"] != tc.wantUser || r.body["bucket"] != tc.wantBucket {
				t.Fatalf("%d %v", r.code, r.body)
			}
		})
	}
}

func TestRequireResourceFuncAndPanics(t *testing.T) {
	e := newEnv(t, envConfig{})
	e.router.GET("/broken", ginguard.Require(e.g, ginguard.Options{}, "invoice", "read", func(*gin.Context) (guard.Resource, error) {
		return guard.Resource{}, errBoom
	}), func(c *gin.Context) { c.Status(200) })
	if r := e.do("GET", "/broken", e.admin, nil); r.code != 500 || r.errCode() != "internal" {
		t.Fatalf("resource func error: %d %v", r.code, r.body)
	}
	e.router.GET("/anon", ginguard.Require(e.g, ginguard.Options{}, "invoice", "read", nil), func(c *gin.Context) { c.Status(200) })
	if r := e.do("GET", "/anon", "", nil); r.code != 401 {
		t.Fatalf("require without credential: %d", r.code)
	}

	mustPanic := func(name string, fn func()) {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if v := recover(); v == nil || !strings.HasPrefix(v.(string), "ginguard: ") {
					t.Fatalf("want ginguard panic, got %v", v)
				}
			}()
			fn()
		})
	}
	mustPanic("RequirePermission bad code", func() { ginguard.RequirePermission(e.g, ginguard.Options{}, "nodot") })
	mustPanic("RateLimit invalid rule", func() { ginguard.RateLimit(e.g, "x", ratelimit.Rule{Limit: 0, Window: 0}, ginguard.ByIP) })
}

func TestRateLimitFailsOpen(t *testing.T) {
	ok := func(c *gin.Context) { c.Status(200) }
	rule := ratelimit.Rule{Limit: 1, Window: time.Minute}

	t.Run("nil limiter", func(t *testing.T) {
		e := newEnv(t, envConfig{})
		e.router.GET("/rl", ginguard.RateLimit(e.g, "rl", rule, ginguard.ByIP), ok)
		for i := 0; i < 3; i++ {
			if r := e.do("GET", "/rl", "", nil); r.code != 200 || r.w.Header().Get("X-RateLimit-Limit") != "" {
				t.Fatalf("attempt %d: %d %v", i, r.code, r.w.Header())
			}
		}
	})
	t.Run("limiter error", func(t *testing.T) {
		var keys []string
		e := newEnv(t, envConfig{limiter: limiterFunc(func(_ context.Context, key string, _ ratelimit.Rule) (ratelimit.Result, error) {
			keys = append(keys, key)
			return ratelimit.Result{}, errBoom
		})})
		var seen error
		e.router.GET("/rl2", ginguard.RateLimit(e.g, "rl2", rule, ginguard.ByIP), func(c *gin.Context) {
			if len(c.Errors) > 0 {
				seen = c.Errors[0].Err
			}
			ok(c)
		})
		if r := e.do("GET", "/rl2", "", nil); r.code != 200 || !errors.Is(seen, errBoom) {
			t.Fatalf("fail-open: %d err=%v", r.code, seen)
		}
		if len(keys) != 1 || keys[0] != "rl2:ip:192.0.2.1" {
			t.Fatalf("bucket key: %v", keys)
		}
	})
}
