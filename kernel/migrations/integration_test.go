package migrations

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func randSuffix(t *testing.T) string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func testURL(t *testing.T) string {
	u := os.Getenv("GUARD_TEST_DATABASE_URL")
	if u == "" {
		t.Skip("GUARD_TEST_DATABASE_URL not set")
	}
	return u
}

// freshDB creates a dedicated database and returns a pool connected to it.
func freshDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, testURL(t))
	if err != nil {
		t.Fatal(err)
	}
	name := "guard_mig_" + randSuffix(t)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	cfg, err := pgxpool.ParseConfig(testURL(t))
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
			t.Errorf("drop database %s: %v", name, err)
		}
		admin.Close()
	})
	return pool
}

func TestDetectIntegration(t *testing.T) {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, testURL(t))
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	schema := "guard_detect_" + randSuffix(t)
	q := pgx.Identifier{schema}.Sanitize()
	if _, err := pool.Exec(ctx, "CREATE SCHEMA "+q+`;
		CREATE TABLE `+q+`.users_big (id bigserial PRIMARY KEY);
		CREATE TABLE `+q+`.users_uuid (id uuid PRIMARY KEY);
		CREATE TABLE `+q+`.users_code (id serial PRIMARY KEY, code text UNIQUE);
		CREATE TABLE `+q+`.users_nounique (id int, code text);
		CREATE TABLE `+q+`.users_arr (id int[] PRIMARY KEY);`); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := pool.Exec(context.Background(), "DROP SCHEMA "+q+" CASCADE"); err != nil {
			t.Errorf("drop schema: %v", err)
		}
	}()

	ok := []struct {
		table, column string
		want          UserRef
	}{
		{schema + ".users_big", "", UserRef{schema + ".users_big", "id", "bigint"}},
		{schema + ".users_uuid", "id", UserRef{schema + ".users_uuid", "id", "uuid"}},
		{schema + ".users_code", "id", UserRef{schema + ".users_code", "id", "integer"}},
		{schema + ".users_code", "code", UserRef{schema + ".users_code", "code", "text"}},
	}
	for _, c := range ok {
		got, err := Detect(ctx, pool, c.table, c.column)
		if err != nil {
			t.Errorf("Detect(%s,%s): %v", c.table, c.column, err)
			continue
		}
		if got != c.want {
			t.Errorf("Detect(%s,%s) = %+v, want %+v", c.table, c.column, got, c.want)
		}
	}

	bad := []struct{ table, column, msg string }{
		{schema + ".missing", "id", "not found"},
		{"users_big", "id", "not found"}, // schema not on search_path
		{schema + ".users_big", "nope", `column "nope" not found`},
		{schema + ".users_nounique", "id", "UNIQUE"},
		{schema + ".users_nounique", "code", "UNIQUE"},
		{schema + ".users_arr", "id", "array"},
	}
	for _, c := range bad {
		_, err := Detect(ctx, pool, c.table, c.column)
		if err == nil || !strings.Contains(err.Error(), c.msg) {
			t.Errorf("Detect(%s,%s) err = %v, want containing %q", c.table, c.column, err, c.msg)
		}
	}
}

func TestUpDownIntegration(t *testing.T) {
	ctx := context.Background()
	pool := freshDB(t)
	if _, err := pool.Exec(ctx, `CREATE TABLE app_users (id bigserial PRIMARY KEY, name text NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	ref, err := Detect(ctx, pool, "app_users", "id")
	if err != nil {
		t.Fatal(err)
	}
	if ref != (UserRef{"app_users", "id", "bigint"}) {
		t.Fatalf("ref = %+v", ref)
	}
	if err := Up(ctx, pool, "", ref); err != nil {
		t.Fatalf("Up: %v", err)
	}
	// Idempotent re-run.
	if err := Up(ctx, pool, "", ref); err != nil {
		t.Fatalf("second Up: %v", err)
	}

	var typ string
	if err := pool.QueryRow(ctx, `SELECT data_type FROM information_schema.columns
		WHERE table_schema = current_schema() AND table_name = 'guard_account' AND column_name = 'user_id'`).Scan(&typ); err != nil {
		t.Fatal(err)
	}
	if typ != "bigint" {
		t.Fatalf("guard_account.user_id type = %s", typ)
	}
	var roles, policies int
	if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM guard_role), (SELECT count(*) FROM guard_policy)`).Scan(&roles, &policies); err != nil {
		t.Fatal(err)
	}
	if roles != 3 || policies != 3 {
		t.Fatalf("seed: roles=%d policies=%d", roles, policies)
	}

	var uid int64
	if err := pool.QueryRow(ctx, `INSERT INTO app_users (name) VALUES ('alice') RETURNING id`).Scan(&uid); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO guard_account (user_id, email, secret) VALUES ($1, 'alice@example.com', 'x')`, uid); err != nil {
		t.Fatalf("insert guard_account: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO guard_account (user_id, email, secret) VALUES ($1, 'ghost@example.com', 'x')`, uid+1000); err == nil {
		t.Fatal("FK to host table not enforced")
	}

	if err := Down(ctx, pool, "", ref); err != nil {
		t.Fatalf("Down: %v", err)
	}
	var guardTables int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.tables
		WHERE table_schema = current_schema() AND table_name LIKE 'guard\_%' AND table_name <> $1`, VersionTable).Scan(&guardTables); err != nil {
		t.Fatal(err)
	}
	if guardTables != 0 {
		t.Fatalf("%d guard tables remain after Down", guardTables)
	}
	var users int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM app_users`).Scan(&users); err != nil {
		t.Fatalf("host table: %v", err)
	}
	if users != 1 {
		t.Fatalf("host users = %d", users)
	}
}

func TestUpFromDirIntegration(t *testing.T) {
	ctx := context.Background()
	pool := freshDB(t)
	if _, err := pool.Exec(ctx, `CREATE SCHEMA auth; CREATE TABLE auth.users (id uuid PRIMARY KEY DEFAULT gen_random_uuid())`); err != nil {
		t.Fatal(err)
	}
	ref, err := Detect(ctx, pool, "auth.users", "")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if _, err := Write(dir, ref); err != nil {
		t.Fatal(err)
	}
	if err := Up(ctx, pool, dir, UserRef{}); err != nil {
		t.Fatalf("Up from dir: %v", err)
	}
	var typ string
	if err := pool.QueryRow(ctx, `SELECT data_type FROM information_schema.columns
		WHERE table_name = 'guard_api_key' AND column_name = 'user_id'`).Scan(&typ); err != nil {
		t.Fatal(err)
	}
	if typ != "uuid" {
		t.Fatalf("guard_api_key.user_id type = %s", typ)
	}
	if err := Down(ctx, pool, dir, UserRef{}); err != nil {
		t.Fatalf("Down from dir: %v", err)
	}
}

// Two replicas starting at once must not race each other through the schema:
// the session advisory lock serialises them and every migration runs once.
func TestConcurrentUpIntegration(t *testing.T) {
	ctx := context.Background()
	pool := freshDB(t)
	if _, err := pool.Exec(ctx, `CREATE TABLE users (id bigserial PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	ref, err := Detect(ctx, pool, "users", "id")
	if err != nil {
		t.Fatal(err)
	}
	const replicas = 2
	errs := make([]error, replicas)
	var wg sync.WaitGroup
	for i := range replicas {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = Up(ctx, pool, "", ref)
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("replica %d: %v", i, err)
		}
	}
	var applied, distinct int
	if err := pool.QueryRow(ctx, `SELECT count(*), count(DISTINCT version_id) FROM `+VersionTable+` WHERE version_id > 0`).Scan(&applied, &distinct); err != nil {
		t.Fatal(err)
	}
	if applied != 6 || distinct != 6 {
		t.Fatalf("applied=%d distinct=%d, want 6/6", applied, distinct)
	}
	var roles int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM guard_role`).Scan(&roles); err != nil || roles != 3 {
		t.Fatalf("seed ran more than once: roles=%d err=%v", roles, err)
	}
	var idx int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM pg_indexes WHERE schemaname = current_schema() AND indexname IN
		('guard_idx_role_permission_granted_by', 'guard_idx_user_role_granted_by', 'guard_idx_pcg_policy')`).Scan(&idx); err != nil || idx != 3 {
		t.Fatalf("fk indexes = %d, err = %v", idx, err)
	}
}
