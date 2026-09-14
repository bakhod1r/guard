package adminui_test

import (
	"context"
	"errors"
	"html"
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

const policiesTree = `{"operator":"and","conditions":[{"field":"user.department","operator":"eq","value":["finance"]}],` +
	`"groups":[{"operator":"or","negate":true,"conditions":[{"field":"resource.tags","operator":"contains","value":["secret"]},` +
	`{"field":"env.day","operator":"in","value":["sat","sun"]}]}]}`

const policiesDescribed = "(user.department eq finance AND NOT (resource.tags contains secret OR env.day in [sat, sun]))"

func policiesAdmin(t *testing.T) *panel {
	p := newPanel(t)
	p.account("1", "admin@example.com", true)
	p.login("admin@example.com")
	return p
}

func policiesForm(name, root string) url.Values {
	return url.Values{"name": {name}, "resource": {"report"}, "action": {"read"}, "effect": {"deny"},
		"priority": {"5"}, "enabled": {"on"}, "root": {root}}
}

func policiesByName(t *testing.T, g *guard.Guard, name string) *accessdomain.Policy {
	t.Helper()
	all, _ := g.Access.ListPolicies(context.Background())
	for i := range all {
		if all[i].Name == name {
			return &all[i]
		}
	}
	return nil
}

func policiesAudited(t *testing.T, g *guard.Guard, action string) bool {
	t.Helper()
	evs, _ := g.Audit.List(context.Background(), "1", 0)
	for _, e := range evs {
		if e.Action == action {
			return true
		}
	}
	return false
}

func TestPoliciesCreateListUpdateToggleDelete(t *testing.T) {
	p := policiesAdmin(t)

	code, body := p.get("/guard-admin/policies")
	if code != http.StatusOK || !strings.Contains(body, "blocked user denied") || !strings.Contains(body, "New policy") {
		t.Fatalf("list: %d", code)
	}
	if code, body := p.get("/guard-admin/policies/new"); code != http.StatusOK || !strings.Contains(body, `name="root"`) {
		t.Fatalf("new form: %d", code)
	}

	code, _, h := p.post("/guard-admin/policies", policiesForm("finance only", policiesTree))
	if code != http.StatusSeeOther || !strings.HasPrefix(location(h), "/guard-admin/policies?flash=") {
		t.Fatalf("create: %d %s", code, location(h))
	}
	pol := policiesByName(t, p.g, "finance only")
	if pol == nil || pol.Priority != 5 || !pol.Enabled || pol.Effect != accessdomain.Deny ||
		len(pol.Root.Groups) != 1 || !pol.Root.Groups[0].Negate {
		t.Fatalf("stored: %+v", pol)
	}
	if !policiesAudited(t, p.g, "policy.create") {
		t.Fatal("create not audited")
	}
	_, body = p.get("/guard-admin/policies")
	if !strings.Contains(html.UnescapeString(body), policiesDescribed) || !strings.Contains(body, "report.read") {
		t.Fatalf("describe missing in list:\n%s", body)
	}

	code, body = p.get("/guard-admin/policies/" + pol.ID)
	if code != http.StatusOK || !strings.Contains(body, "finance only") || !strings.Contains(html.UnescapeString(body), `"field": "user.department"`) {
		t.Fatalf("edit form: %d", code)
	}

	up := policiesForm("finance renamed", "")
	up.Set("effect", "allow")
	up.Del("enabled")
	code, _, _ = p.post("/guard-admin/policies/"+pol.ID, up)
	if code != http.StatusSeeOther {
		t.Fatalf("update: %d", code)
	}
	got, _ := p.g.Access.Policy(context.Background(), pol.ID)
	if got.Name != "finance renamed" || got.Enabled || got.Root != nil || got.Effect != accessdomain.Allow {
		t.Fatalf("updated: %+v", got)
	}
	if !policiesAudited(t, p.g, "policy.update") {
		t.Fatal("update not audited")
	}
	_, body = p.get("/guard-admin/policies")
	if !strings.Contains(body, "always") {
		t.Fatal("empty tree summary")
	}

	// empty group + empty priority
	eg := policiesForm("empty group", "{}")
	eg.Set("priority", "")
	if code, _, _ := p.post("/guard-admin/policies", eg); code != http.StatusSeeOther {
		t.Fatalf("empty group: %d", code)
	}
	_, body = p.get("/guard-admin/policies")
	if !strings.Contains(body, "(always)") {
		t.Fatal("empty group summary")
	}

	if code, _, _ := p.post("/guard-admin/policies/"+pol.ID+"/toggle", nil); code != http.StatusSeeOther {
		t.Fatalf("toggle: %d", code)
	}
	if got, _ := p.g.Access.Policy(context.Background(), pol.ID); !got.Enabled || !policiesAudited(t, p.g, "policy.toggle") {
		t.Fatal("toggle not applied")
	}
	if code, _, h := p.post("/guard-admin/policies/missing/toggle", nil); code != http.StatusSeeOther || !strings.Contains(location(h), "error=") {
		t.Fatalf("toggle missing: %d", code)
	}

	if code, _, _ := p.post("/guard-admin/policies/"+pol.ID+"/delete", nil); code != http.StatusSeeOther {
		t.Fatalf("delete: %d", code)
	}
	if _, err := p.g.Access.Policy(context.Background(), pol.ID); !errors.Is(err, accessdomain.ErrPolicyNotFound) || !policiesAudited(t, p.g, "policy.delete") {
		t.Fatal("delete not applied")
	}
	if code, _, h := p.post("/guard-admin/policies/"+pol.ID+"/delete", nil); code != http.StatusSeeOther || !strings.Contains(location(h), "error=") {
		t.Fatalf("delete missing: %d", code)
	}
}

func TestPoliciesInvalidInputRerenders(t *testing.T) {
	p := policiesAdmin(t)
	deep := `{"field":"user.x","operator":"eq","value":["1"]}`
	tree := `{"conditions":[` + deep + `]}`
	for i := 0; i < accessdomain.MaxConditionDepth; i++ {
		tree = `{"groups":[` + tree + `]}`
	}
	cases := map[string]struct {
		form url.Values
		want string
	}{
		"bad json":      {policiesForm("keepme-json", `{"operator":`), "invalid input"},
		"trailing":      {policiesForm("keepme-trail", `{} {}`), "invalid input"},
		"unknown field": {policiesForm("keepme-unknown", `{"bogus":1}`), "unknown field"},
		"too deep":      {policiesForm("keepme-deep", tree), "deeper than 8"},
		"bad operator":  {policiesForm("keepme-op", `{"conditions":[{"field":"user.x","operator":"like","value":["a"]}]}`), "unknown operator"},
		"bad priority":  {func() url.Values { f := policiesForm("keepme-prio", ""); f.Set("priority", "abc"); return f }(), "priority"},
		"name taken":    {policiesForm("blocked user denied", ""), "name already exists"},
	}
	for name, tc := range cases {
		code, body, _ := p.post("/guard-admin/policies", tc.form)
		text := html.UnescapeString(body)
		if code != http.StatusUnprocessableEntity || !strings.Contains(text, tc.want) ||
			!strings.Contains(text, `value="`+tc.form.Get("name")+`"`) || !strings.Contains(text, tc.form.Get("root")) ||
			!strings.Contains(text, `value="`+tc.form.Get("priority")+`"`) {
			t.Fatalf("%s: %d\n%s", name, code, body)
		}
	}
	// update path also re-renders
	seed := policiesByName(t, p.g, "blocked user denied")
	if code, body, _ := p.post("/guard-admin/policies/"+seed.ID, policiesForm("x", `nope`)); code != http.StatusUnprocessableEntity || !strings.Contains(body, "invalid input") {
		t.Fatalf("update invalid: %d", code)
	}
}

func TestPoliciesNotFound(t *testing.T) {
	p := policiesAdmin(t)
	if code, _ := p.get("/guard-admin/policies/nope"); code != http.StatusNotFound {
		t.Fatalf("get missing: %d", code)
	}
	if code, _, _ := p.post("/guard-admin/policies/nope", policiesForm("ghost", "")); code != http.StatusNotFound {
		t.Fatalf("update missing: %d", code)
	}
	if policiesByName(t, p.g, "ghost") != nil {
		t.Fatal("update of missing id created a policy")
	}
}

func TestPoliciesSimulate(t *testing.T) {
	p := policiesAdmin(t)
	ctx := context.Background()
	p.account("2", "fin@example.com", false)
	_ = p.g.Identity.SetAttributes(ctx, "2", map[string]any{"department": "finance"})
	_ = p.g.Access.SavePolicy(ctx, &accessdomain.Policy{Name: "finance reads", Resource: "report", Action: "read",
		Effect: accessdomain.Allow, Priority: 50, Enabled: true, Root: &accessdomain.ConditionGroup{
			Conditions: []accessdomain.Condition{{Field: "resource.owner", Operator: accessdomain.OpEq, Value: []string{"$user.id"}},
				{Field: "env.day", Operator: accessdomain.OpEq, Value: []string{"mon"}}}}})

	sim := func(user, attrs, env string) (int, string) {
		code, body, _ := p.post("/guard-admin/policies/simulate", url.Values{"user_id": {user}, "action": {"read"},
			"resource_type": {"report"}, "resource_id": {"r1"}, "resource_attributes": {attrs}, "env": {env}})
		return code, html.UnescapeString(body)
	}
	if code, body := sim("2", `{"owner":"2"}`, `{"day":"mon"}`); code != http.StatusOK || !strings.Contains(body, "Allowed") || !strings.Contains(body, "allowed by policy finance reads") {
		t.Fatalf("allow: %d\n%s", code, body)
	}
	if code, body := sim("2", `{"owner":"3"}`, ``); code != http.StatusOK || !strings.Contains(body, "Denied") || !strings.Contains(body, "no matching permission or policy") || !strings.Contains(body, `{"owner":"3"}`) {
		t.Fatalf("deny: %d\n%s", code, body)
	}
	if code, body := sim("404", ``, ``); code != http.StatusUnprocessableEntity || !strings.Contains(body, "user not found") {
		t.Fatalf("unknown user: %d", code)
	}
	if code, body := sim("2", `{bad`, ``); code != http.StatusUnprocessableEntity || !strings.Contains(body, "resource attributes") {
		t.Fatalf("bad attrs: %d", code)
	}
	if code, body := sim("2", ``, `[1]`); code != http.StatusUnprocessableEntity || !strings.Contains(body, "env") {
		t.Fatalf("bad env: %d", code)
	}
}

func TestPoliciesNonAdminForbidden(t *testing.T) {
	p := newPanel(t)
	p.account("1", "admin@example.com", true)
	p.account("2", "user@example.com", false)
	seed := "00000000-0000-0000-0000-000000000003"
	p.login("user@example.com")
	for _, path := range []string{"/guard-admin/policies", "/guard-admin/policies/new", "/guard-admin/policies/" + seed} {
		if code, _ := p.get(path); code != http.StatusForbidden {
			t.Fatalf("GET %s: %d", path, code)
		}
	}
	for _, path := range []string{"/guard-admin/policies", "/guard-admin/policies/" + seed, "/guard-admin/policies/" + seed + "/delete",
		"/guard-admin/policies/" + seed + "/toggle", "/guard-admin/policies/simulate"} {
		if code, _, _ := p.post(path, policiesForm("evil", "")); code != http.StatusForbidden {
			t.Fatalf("POST %s: %d", path, code)
		}
	}
	if got, _ := p.g.Access.Policy(context.Background(), seed); !got.Enabled || policiesByName(t, p.g, "evil") != nil {
		t.Fatal("non-admin mutated policies")
	}
}

func TestPoliciesReadOnlyViewer(t *testing.T) {
	p := newPanel(t)
	ctx := context.Background()
	p.account("2", "auditor@example.com", false)
	if _, err := p.g.Access.CreateRole(ctx, "policy-viewer", "", "", false); err != nil {
		t.Fatal(err)
	}
	_ = p.g.Access.GrantPermission(ctx, "policy-viewer", "policy.read", "")
	_ = p.g.Access.AssignRole(ctx, "2", "policy-viewer", "", nil)
	p.login("auditor@example.com")
	code, body := p.get("/guard-admin/policies")
	if code != http.StatusOK || strings.Contains(body, "New policy") || strings.Contains(body, "/toggle") {
		t.Fatalf("viewer list: %d", code)
	}
	code, body = p.get("/guard-admin/policies/00000000-0000-0000-0000-000000000003")
	if code != http.StatusOK || !strings.Contains(body, "<fieldset disabled") || strings.Contains(body, "Save policy") {
		t.Fatalf("viewer form: %d", code)
	}
	if code, _, _ := p.post("/guard-admin/policies/00000000-0000-0000-0000-000000000003/toggle", nil); code != http.StatusForbidden {
		t.Fatalf("viewer toggle: %d", code)
	}
}

// policiesFailingStore injects repository failures to exercise internal-error paths.
type policiesFailingStore struct {
	*accessinfra.Memory
	failList, failGet, failSave bool
}

var errPoliciesBoom = errors.New("db down")

func (s *policiesFailingStore) ListPolicies(ctx context.Context) ([]accessdomain.Policy, error) {
	if s.failList {
		return nil, errPoliciesBoom
	}
	return s.Memory.ListPolicies(ctx)
}

func (s *policiesFailingStore) Policy(ctx context.Context, id string) (*accessdomain.Policy, error) {
	if s.failGet {
		return nil, errPoliciesBoom
	}
	return s.Memory.Policy(ctx, id)
}

func (s *policiesFailingStore) SavePolicy(ctx context.Context, p *accessdomain.Policy) error {
	if s.failSave {
		return errPoliciesBoom
	}
	return s.Memory.SavePolicy(ctx, p)
}

func (s *policiesFailingStore) ApplicablePolicies(ctx context.Context, resource, action string) ([]accessdomain.Policy, error) {
	if resource == "boom" {
		return nil, errPoliciesBoom
	}
	return s.Memory.ApplicablePolicies(ctx, resource, action)
}

func TestPoliciesInternalErrorsHidden(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mem := accessinfra.NewMemory()
	store := &policiesFailingStore{Memory: mem}
	g := guard.Build(guard.Repositories{
		Users:    identityinfra.NewMemoryUsers(),
		Hasher:   &identityinfra.Argon2Hasher{Memory: 1024, Time: 1, Threads: 1, KeyLen: 32, SaltLen: 16},
		Sessions: sessioninfra.NewRedisSessions(rdb, "t:"),
		Roles:    mem, Policies: store, Audit: &audit.Memory{},
		APIKeys: apikeyinfra.NewMemory(), Limiter: ratelimit.NewRedis(rdb, "t:"),
	}, guard.Config{})
	guardtest.Seed(context.Background(), mem)
	r := gin.New()
	adminui.Mount(r, g, adminui.Options{InsecureCookie: true})
	p := &panel{t: t, g: g, r: r}
	p.account("1", "admin@example.com", true)
	p.login("admin@example.com")
	seed := "00000000-0000-0000-0000-000000000003"

	store.failList = true
	if code, body := p.get("/guard-admin/policies"); code != http.StatusInternalServerError || strings.Contains(body, "db down") {
		t.Fatalf("list: %d", code)
	}
	store.failList = false

	store.failGet = true
	if code, body := p.get("/guard-admin/policies/" + seed); code != http.StatusInternalServerError || strings.Contains(body, "db down") {
		t.Fatalf("get: %d", code)
	}
	store.failGet = false

	store.failSave = true
	if code, body, _ := p.post("/guard-admin/policies", policiesForm("x-save", "")); code != http.StatusInternalServerError || strings.Contains(body, "db down") {
		t.Fatalf("save: %d", code)
	}
	if code, _, h := p.post("/guard-admin/policies/"+seed+"/toggle", nil); code != http.StatusSeeOther || !strings.Contains(location(h), "internal+error") {
		t.Fatalf("toggle save: %d %s", code, location(h))
	}
	store.failSave = false

	code, body, _ := p.post("/guard-admin/policies/simulate", url.Values{"user_id": {"1"}, "action": {"read"}, "resource_type": {"boom"}})
	if code != http.StatusUnprocessableEntity || strings.Contains(body, "db down") || !strings.Contains(body, "internal error") {
		t.Fatalf("simulate: %d", code)
	}
}
