package infrastructure

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/bakhod1r/guard/access/domain"
	"github.com/bakhod1r/guard/kernel/migrations"
)

// failTracer cancels the context of the first statement containing a marker,
// forcing a deterministic storage error at that exact query.
type failTracer struct {
	mu     sync.Mutex
	marker string
}

func (f *failTracer) failOn(marker string) {
	f.mu.Lock()
	f.marker = marker
	f.mu.Unlock()
}

func (f *failTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.marker != "" && strings.Contains(d.SQL, f.marker) {
		f.marker = ""
		c, cancel := context.WithCancel(ctx)
		cancel()
		return c
	}
	return ctx
}

func (f *failTracer) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

type pgEnv struct {
	repo   *Postgres
	pool   *pgxpool.Pool
	tracer *failTracer
}

// newPG creates a dedicated database with a bigint host users table (ids 1, 2) and Guard migrations.
func newPG(t *testing.T) pgEnv {
	t.Helper()
	url := os.Getenv("GUARD_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("GUARD_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	name := "guard_cov_access_" + hex.EncodeToString(b)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.Database = name
	tr := &failTracer{}
	cfg.ConnConfig.Tracer = tr
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if _, err := admin.Exec(c, "DROP DATABASE IF EXISTS "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)"); err != nil {
			t.Errorf("drop database %s: %v", name, err)
		}
		admin.Close()
	})
	if _, err := pool.Exec(ctx, `CREATE TABLE users (id BIGSERIAL PRIMARY KEY); INSERT INTO users DEFAULT VALUES; INSERT INTO users DEFAULT VALUES`); err != nil {
		t.Fatal(err)
	}
	ref, err := migrations.Detect(ctx, pool, "users", "id")
	if err != nil {
		t.Fatal(err)
	}
	if err := migrations.Up(ctx, pool, "", ref); err != nil {
		t.Fatal(err)
	}
	return pgEnv{repo: NewPostgres(pool), pool: pool, tracer: tr}
}

func (e pgEnv) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if _, err := e.pool.Exec(context.Background(), sql, args...); err != nil {
		t.Fatal(err)
	}
}

func wantErr(t *testing.T, got, want error) {
	t.Helper()
	if !errors.Is(got, want) {
		t.Fatalf("want %v, got %v", want, got)
	}
}

func wantAnyErr(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected storage error")
	}
}

func TestPostgresRolesAndPermissions(t *testing.T) {
	e := newPG(t)
	r, ctx := e.repo, context.Background()

	must(t, r.CreateRole(ctx, &domain.Role{Name: "editor", Title: "Editor", Description: "edits"}))
	wantErr(t, r.CreateRole(ctx, &domain.Role{Name: "editor", Title: "Again"}), domain.ErrRoleExists)
	wantAnyErr(t, r.CreateRole(ctx, &domain.Role{Name: "BAD NAME", Title: "x"})) // check constraint

	must(t, r.CreatePermission(ctx, domain.Permission{Resource: "doc", Action: "read", Description: "read docs"}))
	must(t, r.CreatePermission(ctx, domain.Permission{Resource: "doc", Action: "read"})) // keeps description
	must(t, r.CreatePermission(ctx, domain.Permission{Resource: "doc", Action: "write"}))
	perms, err := r.ListPermissions(ctx)
	must(t, err)
	found := false
	for _, p := range perms {
		if p.Code() == "doc.read" {
			found = p.Description == "read docs"
		}
	}
	if !found {
		t.Fatalf("doc.read description lost: %+v", perms)
	}

	read := domain.Permission{Resource: "doc", Action: "read"}
	write := domain.Permission{Resource: "doc", Action: "write"}
	must(t, r.GrantPermission(ctx, "editor", read, "1"))
	must(t, r.GrantPermission(ctx, "editor", write, ""))
	must(t, r.GrantPermission(ctx, "editor", read, "1")) // already granted -> explainMissing nil
	wantErr(t, r.GrantPermission(ctx, "ghost", read, ""), domain.ErrRoleNotFound)
	wantErr(t, r.GrantPermission(ctx, "editor", domain.Permission{Resource: "nope", Action: "x"}, ""), domain.ErrPermissionNotFound)
	must(t, r.CreatePermission(ctx, domain.Permission{Resource: "doc", Action: "delete"}))
	del := domain.Permission{Resource: "doc", Action: "delete"}
	wantErr(t, r.GrantPermission(ctx, "editor", del, "abc"), domain.ErrSubjectNotFound)
	wantErr(t, r.GrantPermission(ctx, "editor", del, "999"), domain.ErrSubjectNotFound)

	role, err := r.Role(ctx, "editor")
	must(t, err)
	if role.Title != "Editor" || role.Description != "edits" || len(role.Permissions) != 2 || role.Permissions[0] != read {
		t.Fatalf("got %+v", role)
	}
	_, err = r.Role(ctx, "ghost")
	wantErr(t, err, domain.ErrRoleNotFound)

	must(t, r.RevokePermission(ctx, "editor", write))
	role, _ = r.Role(ctx, "editor")
	if len(role.Permissions) != 1 {
		t.Fatalf("revoke ignored: %+v", role)
	}

	roles, err := r.ListRoles(ctx)
	must(t, err)
	names := []string{}
	for _, x := range roles {
		names = append(names, x.Name)
	}
	if strings.Join(names, ",") != "admin,editor,super_admin,user" {
		t.Fatalf("got %v", names)
	}

	must(t, r.DeleteRole(ctx, "editor"))
	wantErr(t, r.DeleteRole(ctx, "editor"), domain.ErrRoleNotFound)
}

func TestPostgresAssignRoleAndGrants(t *testing.T) {
	e := newPG(t)
	r, ctx := e.repo, context.Background()

	wantErr(t, r.AssignRole(ctx, "", "user", "", nil), domain.ErrSubjectNotFound)
	wantErr(t, r.AssignRole(ctx, "abc", "user", "", nil), domain.ErrSubjectNotFound)
	wantErr(t, r.AssignRole(ctx, "999", "user", "", nil), domain.ErrSubjectNotFound)
	wantErr(t, r.AssignRole(ctx, "1", "ghost", "", nil), domain.ErrRoleNotFound)
	exp := time.Now().Add(time.Hour).UTC().Truncate(time.Microsecond)
	past := time.Now().Add(-time.Hour)
	wantAnyErr(t, r.AssignRole(ctx, "1", "user", "", &past)) // check constraint: other error passes through

	must(t, r.AssignRole(ctx, "1", "user", "2", &exp))
	must(t, r.AssignRole(ctx, "1", "admin", "", nil))
	must(t, r.AssignRole(ctx, "1", "admin", "2", nil)) // upsert

	grants, err := r.GrantsOf(ctx, "1")
	must(t, err)
	if len(grants) != 2 || grants[0].Role.Name != "admin" || grants[0].ExpiresAt != nil ||
		grants[1].Role.Name != "user" || grants[1].ExpiresAt == nil || !grants[1].ExpiresAt.Equal(exp) || grants[1].GrantedAt.IsZero() {
		t.Fatalf("got %+v", grants)
	}
	// Out-of-range bigint (22003) is not an "unknown user": it surfaces as a storage error.
	if _, err := r.GrantsOf(ctx, "99999999999999999999"); err == nil {
		t.Fatal("out-of-range id must error")
	}
	for _, id := range []string{"", "abc", "2"} {
		g, err := r.GrantsOf(ctx, id)
		if err != nil || g == nil || len(g) != 0 {
			t.Fatalf("%q: got %+v %v", id, g, err)
		}
	}

	must(t, r.UnassignRole(ctx, "", "user"))
	must(t, r.UnassignRole(ctx, "abc", "user"))
	must(t, r.UnassignRole(ctx, "1", "user"))
	if g, _ := r.GrantsOf(ctx, "1"); len(g) != 1 {
		t.Fatalf("unassign ignored: %+v", g)
	}
}

func deepTree(levels int) *domain.ConditionGroup {
	g := domain.ConditionGroup{Conditions: []domain.Condition{{Field: "user.id", Operator: domain.OpEq, Value: []string{"x"}}}}
	for i := 1; i < levels; i++ {
		g = domain.ConditionGroup{Operator: domain.Or, Groups: []domain.ConditionGroup{g}}
	}
	return &g
}

func TestPostgresPolicies(t *testing.T) {
	e := newPG(t)
	r, ctx := e.repo, context.Background()

	root := &domain.ConditionGroup{Operator: domain.And, Negate: true,
		Conditions: []domain.Condition{
			{Field: "user.status", Operator: domain.OpIn, Value: []string{"banned", "suspended"}},
			{Field: "resource.owner_id", Operator: domain.OpEq, Value: []string{"$user.id"}},
		},
		Groups: []domain.ConditionGroup{
			{Operator: domain.Or, Conditions: []domain.Condition{{Field: "env.ip", Operator: domain.OpContains, Value: []string{"10."}}}},
			{Groups: []domain.ConditionGroup{{Operator: domain.And, Negate: true, Conditions: []domain.Condition{{Field: "user.level", Operator: domain.OpGte, Value: []string{"3"}}}}}},
		}}
	p := &domain.Policy{ID: uuid.Must(uuid.NewV7()).String(), Name: "tree", Resource: "doc", Action: "read", Effect: domain.Deny, Priority: 5, Enabled: true, Root: root}
	must(t, r.SavePolicy(ctx, p))

	got, err := r.Policy(ctx, p.ID)
	must(t, err)
	want := *root
	want.Groups[1].Operator = domain.And // empty operator stored as and
	if got.Name != "tree" || got.Effect != domain.Deny || got.Priority != 5 || !got.Enabled || got.Root == nil {
		t.Fatalf("got %+v", got)
	}
	if !sameGroup(*got.Root, want) {
		t.Fatalf("condition tree round trip mismatch:\n got %+v\nwant %+v", *got.Root, want)
	}

	// Replace: update fields and drop the tree.
	p.Root, p.Enabled, p.Effect = nil, false, domain.Allow
	must(t, r.SavePolicy(ctx, p))
	got, err = r.Policy(ctx, p.ID)
	must(t, err)
	if got.Root != nil || got.Enabled || got.Effect != domain.Allow {
		t.Fatalf("replace failed: %+v", got)
	}

	dup := &domain.Policy{ID: uuid.Must(uuid.NewV7()).String(), Name: "tree", Resource: "*", Action: "*", Effect: domain.Allow}
	wantErr(t, r.SavePolicy(ctx, dup), domain.ErrPolicyNameTaken)

	wild := &domain.Policy{ID: uuid.Must(uuid.NewV7()).String(), Name: "wild", Resource: "*", Action: "read", Effect: domain.Allow, Priority: 1, Enabled: true}
	must(t, r.SavePolicy(ctx, wild))
	app, err := r.ApplicablePolicies(ctx, "doc", "read")
	must(t, err)
	names := map[string]bool{}
	for _, x := range app {
		names[x.Name] = true
	}
	if !names["wild"] || !names["blocked user denied"] || names["tree"] || names["self-service user read"] {
		t.Fatalf("got %v", names)
	}
	if app[0].Name != "wild" {
		t.Fatalf("priority order: %+v", app)
	}
	none, err := r.ApplicablePolicies(ctx, "nothing", "never")
	must(t, err)
	if len(none) != 1 || none[0].Name != "blocked user denied" {
		t.Fatalf("got %+v", none)
	}
	all, err := r.ListPolicies(ctx)
	must(t, err)
	if len(all) != 5 {
		t.Fatalf("got %d policies", len(all))
	}

	// Trees deeper than MaxConditionDepth are truncated on load.
	deep := &domain.Policy{ID: uuid.Must(uuid.NewV7()).String(), Name: "deep", Resource: "x", Action: "y", Effect: domain.Allow, Root: deepTree(domain.MaxConditionDepth + 2)}
	must(t, r.SavePolicy(ctx, deep))
	got, err = r.Policy(ctx, deep.ID)
	must(t, err)
	depth := 1
	for g := *got.Root; len(g.Groups) > 0; g = g.Groups[0] {
		depth++
	}
	if depth != domain.MaxConditionDepth {
		t.Fatalf("depth %d", depth)
	}

	for _, id := range []string{"not-a-uuid", uuid.Must(uuid.NewV7()).String()} {
		_, err := r.Policy(ctx, id)
		wantErr(t, err, domain.ErrPolicyNotFound)
		wantErr(t, r.DeletePolicy(ctx, id), domain.ErrPolicyNotFound)
	}
	must(t, r.DeletePolicy(ctx, p.ID))
	_, err = r.Policy(ctx, p.ID)
	wantErr(t, err, domain.ErrPolicyNotFound)
}

func sameGroup(a, b domain.ConditionGroup) bool {
	if a.Operator != b.Operator || a.Negate != b.Negate || len(a.Conditions) != len(b.Conditions) || len(a.Groups) != len(b.Groups) {
		return false
	}
	for i := range a.Conditions {
		x, y := a.Conditions[i], b.Conditions[i]
		if x.Field != y.Field || x.Operator != y.Operator || strings.Join(x.Value, "\x00") != strings.Join(y.Value, "\x00") {
			return false
		}
	}
	for i := range a.Groups {
		if !sameGroup(a.Groups[i], b.Groups[i]) {
			return false
		}
	}
	return true
}

func TestPostgresSavePolicyStorageErrors(t *testing.T) {
	e := newPG(t)
	r, ctx := e.repo, context.Background()
	newP := func(root *domain.ConditionGroup) *domain.Policy {
		return &domain.Policy{ID: uuid.Must(uuid.NewV7()).String(), Name: "p-" + uuid.NewString(), Resource: "*", Action: "*", Effect: domain.Allow, Root: root}
	}
	cases := []struct {
		name string
		p    *domain.Policy
		fail string
	}{
		{"policy insert check violation", &domain.Policy{ID: uuid.NewString(), Name: "bad-effect", Resource: "*", Action: "*", Effect: "maybe"}, ""},
		{"stale tree delete fails", newP(nil), "DELETE FROM guard_policy_condition_group"},
		{"group insert fails", newP(&domain.ConditionGroup{Operator: "xor"}), ""},
		{"condition insert fails", newP(&domain.ConditionGroup{Conditions: []domain.Condition{{Field: "user.id", Operator: "like", Value: []string{"x"}}}}), ""},
		{"child group insert fails", newP(&domain.ConditionGroup{Groups: []domain.ConditionGroup{{Operator: "nand"}}}), ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e.tracer.failOn(c.fail)
			wantAnyErr(t, r.SavePolicy(ctx, c.p))
			e.tracer.failOn("")
			_, err := r.Policy(ctx, c.p.ID)
			wantErr(t, err, domain.ErrPolicyNotFound) // transaction rolled back
		})
	}
}

func TestPostgresLoadPoliciesStorageErrors(t *testing.T) {
	e := newPG(t)
	r, ctx := e.repo, context.Background()
	for _, marker := range []string{"WITH p AS (SELECT"} {
		t.Run(marker, func(t *testing.T) {
			e.tracer.failOn(marker)
			_, err := r.ListPolicies(ctx)
			wantAnyErr(t, err)
			e.tracer.failOn("")
		})
	}
	t.Run("explainMissing query fails", func(t *testing.T) {
		e.tracer.failOn("SELECT EXISTS")
		wantAnyErr(t, r.GrantPermission(ctx, "ghost", domain.Permission{Resource: "user", Action: "read"}, ""))
		e.tracer.failOn("")
	})
}

// Row-level failures: the dedicated database is altered so real rows cannot be scanned
// or so the server raises while streaming rows.
func TestPostgresRowErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("role and permission scan", func(t *testing.T) {
		e := newPG(t)
		e.exec(t, `ALTER TABLE guard_role ALTER COLUMN title DROP NOT NULL`)
		e.exec(t, `ALTER TABLE guard_permission ALTER COLUMN resource DROP NOT NULL`)
		e.exec(t, `INSERT INTO guard_user_role (user_id, role_id) SELECT 1, id FROM guard_role WHERE name='user'`)
		e.exec(t, `UPDATE guard_role SET title=NULL WHERE name='user'`)
		e.exec(t, `UPDATE guard_permission SET resource=NULL WHERE code='user.read'`)
		_, err := e.repo.ListRoles(ctx)
		wantAnyErr(t, err)
		_, err = e.repo.Role(ctx, "user")
		wantAnyErr(t, err)
		_, err = e.repo.GrantsOf(ctx, "1")
		wantAnyErr(t, err)
		_, err = e.repo.ListPermissions(ctx)
		wantAnyErr(t, err)
	})

	t.Run("policy, group and condition scan", func(t *testing.T) {
		e := newPG(t)
		e.exec(t, `ALTER TABLE guard_policy_condition ALTER COLUMN field DROP NOT NULL`)
		e.exec(t, `UPDATE guard_policy_condition SET field=NULL WHERE value = ARRAY['banned','suspended']::varchar[]`)
		_, err := e.repo.ListPolicies(ctx)
		wantAnyErr(t, err)

		e.exec(t, `ALTER TABLE guard_policy_condition_group ALTER COLUMN negate DROP NOT NULL`)
		e.exec(t, `UPDATE guard_policy_condition_group SET negate=NULL`)
		_, err = e.repo.ListPolicies(ctx)
		wantAnyErr(t, err)

		e.exec(t, `ALTER TABLE guard_policy ALTER COLUMN name DROP NOT NULL`)
		e.exec(t, `UPDATE guard_policy SET name=NULL`)
		_, err = e.repo.ListPolicies(ctx)
		wantAnyErr(t, err)
	})

	t.Run("server error while streaming groups and conditions", func(t *testing.T) {
		e := newPG(t)
		e.exec(t, `CREATE FUNCTION guard_cov_boom(t text) RETURNS text LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'boom'; END $$`)
		e.exec(t, `ALTER TABLE guard_policy_condition RENAME TO guard_policy_condition_real`)
		e.exec(t, `CREATE VIEW guard_policy_condition AS SELECT id, group_id, guard_cov_boom(field) AS field, operator, value, position FROM guard_policy_condition_real`)
		_, err := e.repo.ListPolicies(ctx)
		wantAnyErr(t, err)

		e.exec(t, `ALTER TABLE guard_policy_condition_group RENAME TO guard_policy_condition_group_real`)
		e.exec(t, `CREATE VIEW guard_policy_condition_group AS SELECT id, policy_id, parent_group_id, guard_cov_boom(logical_operator) AS logical_operator, negate, position FROM guard_policy_condition_group_real`)
		_, err = e.repo.ListPolicies(ctx)
		wantAnyErr(t, err)

		e.exec(t, `ALTER TABLE guard_policy RENAME TO guard_policy_real`)
		e.exec(t, `CREATE VIEW guard_policy AS SELECT id, guard_cov_boom(name) AS name, resource, action, effect, priority, enabled FROM guard_policy_real`)
		_, err = e.repo.ListPolicies(ctx)
		wantAnyErr(t, err)

		e.exec(t, `INSERT INTO guard_user_role (user_id, role_id) SELECT 1, id FROM guard_role WHERE name='user'`)
		e.exec(t, `ALTER TABLE guard_role RENAME TO guard_role_real`)
		e.exec(t, `CREATE VIEW guard_role AS SELECT id, name, guard_cov_boom(title) AS title, description, is_system, wildcard FROM guard_role_real`)
		_, err = e.repo.ListRoles(ctx)
		wantAnyErr(t, err)
		_, err = e.repo.GrantsOf(ctx, "1")
		wantAnyErr(t, err)
	})

	t.Run("closed pool", func(t *testing.T) {
		e := newPG(t)
		e.pool.Close()
		r := e.repo
		wantAnyErr(t, r.CreateRole(ctx, &domain.Role{Name: "zz", Title: "z"}))
		wantAnyErr(t, r.DeleteRole(ctx, "zz"))
		_, err := r.ListRoles(ctx)
		wantAnyErr(t, err)
		_, err = r.GrantsOf(ctx, "1")
		wantAnyErr(t, err)
		wantAnyErr(t, r.CreatePermission(ctx, domain.Permission{Resource: "a", Action: "b"}))
		_, err = r.ListPermissions(ctx)
		wantAnyErr(t, err)
		wantAnyErr(t, r.GrantPermission(ctx, "user", domain.Permission{Resource: "a", Action: "b"}, ""))
		wantAnyErr(t, r.RevokePermission(ctx, "user", domain.Permission{Resource: "a", Action: "b"}))
		wantAnyErr(t, r.AssignRole(ctx, "1", "user", "", nil))
		wantAnyErr(t, r.UnassignRole(ctx, "1", "user"))
		wantAnyErr(t, r.SavePolicy(ctx, &domain.Policy{ID: uuid.NewString(), Name: "x", Resource: "*", Action: "*", Effect: domain.Allow}))
		wantAnyErr(t, r.DeletePolicy(ctx, uuid.NewString()))
		_, err = r.Policy(ctx, uuid.NewString())
		wantAnyErr(t, err)
	})
}
