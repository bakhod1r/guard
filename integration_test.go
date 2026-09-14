package guard_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/bakhod1r/guard"
	accessdomain "github.com/bakhod1r/guard/access/domain"
	"github.com/bakhod1r/guard/kernel/migrations"
	"github.com/bakhod1r/guard/ratelimit"
)

// Runs against real services:
//
//	GUARD_TEST_DATABASE_URL=postgres://postgres:postgres@localhost:55432/guard?sslmode=disable \
//	GUARD_TEST_REDIS_ADDR=localhost:56379 go test -run Integration ./...
func TestIntegrationPostgresRedis(t *testing.T) {
	dsn, addr := os.Getenv("GUARD_TEST_DATABASE_URL"), os.Getenv("GUARD_TEST_REDIS_ADDR")
	if dsn == "" || addr == "" {
		t.Skip("GUARD_TEST_DATABASE_URL / GUARD_TEST_REDIS_ADDR not set")
	}
	ctx := context.Background()
	pool := integrationDatabase(t, dsn)
	rdb := redis.NewClient(&redis.Options{Addr: addr})
	defer rdb.Close()

	// The host application owns its user table; Guard only references it.
	if _, err := pool.Exec(ctx, `CREATE TABLE app_users (id BIGSERIAL PRIMARY KEY, full_name TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	hostUser := func(name string) string {
		var id string
		if err := pool.QueryRow(ctx, `INSERT INTO app_users (full_name) VALUES ($1) RETURNING id::text`, name).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}

	g, err := guard.New(guard.Config{DB: pool, Redis: rdb, RedisPrefix: "guard-it-" + pool.Config().ConnConfig.Database + ":", UserTable: "app_users", AccessCache: &guard.AccessCacheOptions{}})
	if err != nil {
		t.Fatal(err)
	}
	ref, err := g.UserRef(ctx)
	if err != nil || ref.IDType != "bigint" {
		t.Fatalf("detect: %+v %v", ref, err)
	}
	dir := filepath.Join(t.TempDir(), "migrations", "guard")
	rendered, err := migrations.Render(ref)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := fs.Glob(rendered, "*.sql")
	if files, err := g.WriteMigrations(ctx, dir); err != nil || len(files) != len(want) || len(want) < 4 {
		t.Fatalf("write migrations: %v %v", files, err)
	}
	if err := g.Migrate(ctx, dir); err != nil {
		t.Fatal(err)
	}
	if err := g.Migrate(ctx, dir); err != nil {
		t.Fatalf("second migrate must be a no-op: %v", err)
	}

	var typ string
	if err := pool.QueryRow(ctx, `SELECT data_type FROM information_schema.columns WHERE table_name='guard_account' AND column_name='user_id'`).Scan(&typ); err != nil || typ != "bigint" {
		t.Fatalf("guard_account.user_id type: %q %v", typ, err)
	}
	var guardUsers int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.tables WHERE table_name IN ('guard_user','guard_identity')`).Scan(&guardUsers)
	if guardUsers != 0 {
		t.Fatal("guard must not create its own user tables")
	}

	rootID := hostUser("Root")
	admin, err := g.EnsureAdmin(ctx, rootID, "root@example.com", "tr0ub4dor-guard-42-root")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.EnsureAdmin(ctx, rootID, "root@example.com", "tr0ub4dor-guard-42-root"); err != nil {
		t.Fatalf("EnsureAdmin not idempotent: %v", err)
	}
	if _, err := g.CreateAccount(ctx, "999999", "ghost@example.com", "tr0ub4dor-guard-42", nil, guard.RequestMeta{}); err == nil {
		t.Fatal("account for missing host user accepted")
	}
	if _, err := g.CreateAccount(ctx, "not-a-number", "ghost@example.com", "tr0ub4dor-guard-42", nil, guard.RequestMeta{}); err == nil {
		t.Fatal("account for invalid host id accepted")
	}
	u, err := g.CreateAccount(ctx, hostUser("Ali"), "user@example.com", "tr0ub4dor-guard-42", map[string]any{"department": "sales"}, guard.RequestMeta{IP: "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}

	res, err := g.Login(ctx, "user@example.com", "tr0ub4dor-guard-42", guard.RequestMeta{IP: "127.0.0.1", UserAgent: "test"})
	if err != nil {
		t.Fatal(err)
	}
	p, err := g.Authenticate(ctx, string(res.Token))
	if err != nil || len(p.Roles) != 1 || p.Roles[0].Name != "user" || p.User.Attributes["department"] != "sales" {
		t.Fatalf("authenticate: %+v %v", p, err)
	}

	// RBAC with time-bound grant.
	if _, err := g.Access.CreatePermission(ctx, "report.read", "Read reports"); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Access.CreateRole(ctx, "analyst", "Analyst", "", false); err != nil {
		t.Fatal(err)
	}
	if err := g.Access.GrantPermission(ctx, "analyst", "report.read", string(admin.ID)); err != nil {
		t.Fatal(err)
	}
	exp := time.Now().Add(time.Hour)
	if err := g.Access.AssignRole(ctx, string(u.ID), "analyst", string(admin.ID), &exp); err != nil {
		t.Fatal(err)
	}
	p, _ = g.Authenticate(ctx, string(res.Token))
	if d, err := g.Authorize(ctx, p, "read", guard.Resource{Type: "report"}, nil); err != nil || !d.Allowed {
		t.Fatalf("rbac: %+v %v", d, err)
	}

	// ABAC tree round-trips through the three policy tables.
	pol := &accessdomain.Policy{Name: "weekend lock", Resource: "report", Action: "read", Effect: accessdomain.Deny, Priority: 20, Enabled: true,
		Root: &accessdomain.ConditionGroup{Operator: accessdomain.Or, Groups: []accessdomain.ConditionGroup{
			{Operator: accessdomain.And, Conditions: []accessdomain.Condition{{Field: "env.day", Operator: accessdomain.OpIn, Value: []string{"sat", "sun"}}}},
			{Operator: accessdomain.And, Negate: true, Conditions: []accessdomain.Condition{{Field: "user.department", Operator: accessdomain.OpEq, Value: []string{"sales"}}}},
		}}}
	if err := g.Access.SavePolicy(ctx, pol); err != nil {
		t.Fatal(err)
	}
	loaded, err := g.Access.Policy(ctx, pol.ID)
	if err != nil || loaded.Root == nil || len(loaded.Root.Groups) != 2 || !loaded.Root.Groups[1].Negate {
		t.Fatalf("policy round trip: %+v %v", loaded, err)
	}
	if d, _ := g.Authorize(ctx, p, "read", guard.Resource{Type: "report"}, map[string]any{"day": "mon"}); !d.Allowed {
		t.Fatalf("weekday sales denied: %+v", d)
	}
	if d, _ := g.Authorize(ctx, p, "read", guard.Resource{Type: "report"}, map[string]any{"day": "sun"}); d.Allowed {
		t.Fatalf("weekend allowed: %+v", d)
	}

	// Seeded self-service policy.
	if d, _ := g.Authorize(ctx, p, "read", guard.Resource{Type: "user", ID: string(u.ID)}, nil); !d.Allowed {
		t.Fatalf("self read denied: %+v", d)
	}
	if d, _ := g.Authorize(ctx, p, "read", guard.Resource{Type: "user", ID: string(admin.ID)}, nil); d.Allowed {
		t.Fatalf("foreign read allowed: %+v", d)
	}

	// API key narrows the owner's access; stored hashed in PostgreSQL.
	key, tok, err := g.IssueAPIKey(ctx, p, "etl", []string{"user.read"}, nil, guard.RequestMeta{})
	if err != nil {
		t.Fatal(err)
	}
	kp, err := g.Authenticate(ctx, string(tok))
	if err != nil || kp.APIKey == nil || kp.APIKey.ID != key.ID {
		t.Fatalf("api key auth: %+v %v", kp, err)
	}
	if d, _ := g.Authorize(ctx, kp, "read", guard.Resource{Type: "report"}, map[string]any{"day": "mon"}); d.Allowed {
		t.Fatalf("key scope ignored: %+v", d)
	}
	if d, _ := g.Authorize(ctx, kp, "read", guard.Resource{Type: "user", ID: string(u.ID)}, nil); !d.Allowed {
		t.Fatalf("key in scope denied: %+v", d)
	}
	if err := g.APIKeys.Revoke(ctx, string(u.ID), key.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Authenticate(ctx, string(tok)); err == nil {
		t.Fatal("revoked key authenticated")
	}

	// Rate limiter on real Redis.
	rule := ratelimit.Rule{Limit: 2, Window: time.Second}
	for i, want := range []bool{true, true, false} {
		if r, err := g.Limiter.Allow(ctx, "it:"+string(u.ID), rule); err != nil || r.Allowed != want {
			t.Fatalf("limiter hit %d: %+v %v", i, r, err)
		}
	}

	// Ban revokes Redis sessions.
	if err := g.SetUserStatus(ctx, string(admin.ID), string(u.ID), "banned"); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Authenticate(ctx, string(res.Token)); err == nil {
		t.Fatal("banned session still valid")
	}

	events, err := g.Audit.List(ctx, "", 50)
	if err != nil || len(events) < 3 {
		t.Fatalf("audit: %d %v", len(events), err)
	}

	if st, ok := g.AccessStats(); !ok || st.Hits+st.Misses == 0 {
		t.Fatalf("access cache unused: %+v %v", st, ok)
	}

	// Host user deletion cascades into Guard; cached grants are dropped.
	if _, err := pool.Exec(ctx, `DELETE FROM app_users WHERE id=$1`, string(u.ID)); err != nil {
		t.Fatal(err)
	}
	if err := g.InvalidateAccess(ctx); err != nil {
		t.Fatal(err)
	}
	if grants, err := g.Access.Grants(ctx, string(u.ID)); err != nil || len(grants) != 0 {
		t.Fatalf("grants after host deletion: %v %v", grants, err)
	}
	if _, err := g.Identity.User(ctx, u.ID); err == nil {
		t.Fatal("account survived host user deletion")
	}

	if err := migrations.Down(ctx, pool, dir, ref); err != nil {
		t.Fatalf("down: %v", err)
	}
	var hostRows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM app_users`).Scan(&hostRows); err != nil || hostRows != 1 {
		t.Fatalf("host table touched by down: %d %v", hostRows, err)
	}
}

// integrationDatabase creates guard_it_<random> so the test never touches
// tables in the shared database, and drops it WITH (FORCE) afterwards.
func integrationDatabase(t *testing.T, dsn string) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	name := "guard_it_" + hex.EncodeToString(b)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.Database = name
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if _, err := admin.Exec(c, "DROP DATABASE IF EXISTS "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)"); err != nil {
			t.Errorf("drop %s: %v", name, err)
		}
		admin.Close()
	})
	return pool
}
