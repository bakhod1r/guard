package config

import (
	"crypto/rand"
	"encoding/hex"
	"github.com/jackc/pgx/v5/pgxpool"
	"net/url"

	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bakhod1r/guard"
	"github.com/bakhod1r/guard/ginguard"
	"github.com/bakhod1r/guard/ratelimit"
)

const full = `
database: { url: "${T_DB}" }
redis: { addr: "${T_REDIS}", password: "${T_PW}", db: 2, prefix: "g:" }
user_table: app.users
user_id_column: id
default_role: member
session: { idle: 30m, absolute: 168h, max_per_user: 3 }
lockout: { attempts: 5, window: 15m }
audit: { async_buffer: 64, email_key: "${T_AUDIT_KEY}", redis_buffer: { enabled: true, batch_size: 200, interval: 2s } }
access_cache: { enabled: true, ttl: 10s, max_entries: 500 }
migrations: { dir: ./migrations/guard, auto_apply: true }
http:
  cookie_name: sid
  insecure_cookie: true
  cookie_domain: example.com
  auth_path: /auth
  admin_path: /guard
  trusted_origins: [app.example.com]
  max_body_bytes: 2048
  hsts: true
  auth_rate_limit: { limit: 10, window: 1m }
autoseed: { enabled: true, prefix: /api, super_role: admin, exclude: [/api/auth, /api/guard] }
`

func setEnv(t *testing.T) {
	t.Setenv("T_DB", "postgres://u:p@h/db")
	t.Setenv("T_REDIS", "localhost:6379")
	t.Setenv("T_PW", "secret")
	t.Setenv("T_AUDIT_KEY", "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=") // base64 of 32 x "A"
}

func TestParseFull(t *testing.T) {
	setEnv(t)
	f, err := Parse([]byte(full))
	if err != nil {
		t.Fatal(err)
	}
	if f.Database.URL != "postgres://u:p@h/db" || f.Redis.Addr != "localhost:6379" || f.Redis.Password != "secret" || f.Redis.DB != 2 {
		t.Fatalf("env not expanded: %+v %+v", f.Database, f.Redis)
	}
	c := f.guardConfig()
	want := guard.SessionPolicy{IdleTimeout: 30 * time.Minute, AbsoluteTimeout: 168 * time.Hour, MaxPerUser: 3}
	if c.Session != want || c.Lockout != (guard.Lockout{MaxAttempts: 5, Duration: 15 * time.Minute}) ||
		c.RedisPrefix != "g:" || c.DefaultRole != "member" || c.UserTable != "app.users" || c.UserIDColumn != "id" || c.AsyncAudit != 64 {
		t.Fatalf("guard config: %+v", c)
	}
	if !c.AuditBuffer.Enabled || c.AuditBuffer.BatchSize != 200 || c.AuditBuffer.Interval != 2*time.Second {
		t.Fatalf("audit buffer: %+v", c.AuditBuffer)
	}
	if string(c.AuditEmailKey) != strings.Repeat("A", 32) {
		t.Fatalf("audit email key: %q", c.AuditEmailKey)
	}
	if c.AccessCache == nil || c.AccessCache.TTL != 10*time.Second || c.AccessCache.MaxEntries != 500 {
		t.Fatalf("access cache: %+v", c.AccessCache)
	}
	h := f.HTTPOptions()
	if h.CookieName != "sid" || !h.InsecureCookie || h.CookieDomain != "example.com" || h.AuthPath != "/auth" ||
		h.AdminPath != "/guard" || len(h.TrustedOrigins) != 1 || h.MaxBodyBytes != 2048 || !h.HSTS ||
		h.AuthRateLimit != (ratelimit.Rule{Limit: 10, Window: time.Minute}) {
		t.Fatalf("http: %+v", h)
	}
	a, ok := f.AutoseedOptions()
	if !ok || a.Prefix != "/api" || a.SuperRole != "admin" || len(a.Exclude) != 2 {
		t.Fatalf("autoseed: %+v %v", a, ok)
	}
}

func TestParseMinimalDefaults(t *testing.T) {
	f, err := Parse([]byte("database: {url: postgres://x}\nredis: {addr: r:1}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := f.AutoseedOptions(); ok {
		t.Fatal("autoseed should be disabled")
	}
	if (f.HTTPOptions().AuthRateLimit != ratelimit.Rule{}) || f.guardConfig().Session != (guard.SessionPolicy{}) ||
		f.guardConfig().AccessCache != nil || f.guardConfig().AuditEmailKey != nil || f.guardConfig().AuditBuffer.Enabled {
		t.Fatal("zero values expected so library defaults apply")
	}
}

func TestParseErrors(t *testing.T) {
	base := "database: {url: postgres://x}\nredis: {addr: r:1}\n"
	cases := map[string]string{
		"unknown key":      base + "bogus: 1\n",
		"unknown nested":   base + "session: {idel: 1m}\n",
		"bad duration":     base + "session: {idle: soon}\n",
		"duration type":    base + "session: {idle: [1]}\n",
		"no db url":        "redis: {addr: r:1}\n",
		"no redis addr":    "database: {url: postgres://x}\n",
		"bad table":        base + "user_table: \"users; drop\"\n",
		"bad column":       base + "user_id_column: 1id\n",
		"neg idle":         base + "session: {idle: -1m}\n",
		"neg absolute":     base + "session: {absolute: -1m}\n",
		"neg max per user": base + "session: {max_per_user: -1}\n",
		"neg attempts":     base + "lockout: {attempts: -1}\n",
		"neg lock window":  base + "lockout: {window: -1s}\n",
		"neg redis db":     base + "redis: {addr: r:1, db: -1}\n",
		"neg async":        base + "audit: {async_buffer: -1}\n",
		"neg body":         base + "http: {max_body_bytes: -1}\n",
		"neg rl window":    base + "http: {auth_rate_limit: {window: -1s}}\n",
		"rl limit < -1":    base + "http: {auth_rate_limit: {limit: -2}}\n",
		"auto no dir":      base + "migrations: {auto_apply: true}\n",
		"neg batch":        base + "audit: {redis_buffer: {batch_size: -1}}\n",
		"neg interval":     base + "audit: {redis_buffer: {interval: -1s}}\n",
		"neg cache ttl":    base + "access_cache: {ttl: -1s}\n",
		"neg cache max":    base + "access_cache: {max_entries: -1}\n",
		"email key b64":    base + "audit: {email_key: \"not base64!\"}\n",
		"email key short":  base + "audit: {email_key: QUFBQQ==}\n",
		"not yaml":         "::: [",
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(in))
			if err == nil || !strings.HasPrefix(err.Error(), "config: ") {
				t.Fatalf("want config error, got %v", err)
			}
		})
	}
}

func TestParseAllowsRateLimitDisable(t *testing.T) {
	f, err := Parse([]byte("database: {url: postgres://x}\nredis: {addr: r:1}\nhttp: {auth_rate_limit: {limit: -1}}\n"))
	if err != nil || f.HTTPOptions().AuthRateLimit.Limit != -1 {
		t.Fatalf("%v", err)
	}
}

func TestLoad(t *testing.T) {
	setEnv(t)
	p := filepath.Join(t.TempDir(), "guard.yaml")
	if err := os.WriteFile(p, []byte(full), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing.yaml")); err == nil || !strings.HasPrefix(err.Error(), "config: ") {
		t.Fatalf("got %v", err)
	}
}

func valid(t *testing.T, extra string) *File {
	t.Helper()
	f, err := Parse([]byte("database: {url: \"postgres://u:p@127.0.0.1:1/db?connect_timeout=1\"}\nredis: {addr: \"127.0.0.1:1\"}\n" + extra))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestOpenInvalidURL(t *testing.T) {
	f := valid(t, "")
	f.Database.URL = "::not a url"
	if _, err := f.Open(context.Background()); err == nil || !strings.HasPrefix(err.Error(), "config: ") {
		t.Fatalf("got %v", err)
	}
}

func TestOpenGuardNewFails(t *testing.T) {
	orig := newGuard
	t.Cleanup(func() { newGuard = orig })
	newGuard = func(guard.Config) (*guard.Guard, error) { return nil, errors.New("boom") }
	if _, err := valid(t, "").Open(context.Background()); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("got %v", err)
	}
}

func TestOpenNoAutoApply(t *testing.T) {
	g, err := valid(t, "").Open(context.Background())
	if err != nil || g == nil {
		t.Fatalf("lazy connect should succeed: %v", err)
	}
}

func TestOpenWriteMigrationsFails(t *testing.T) {
	// Unreachable database: user table detection fails.
	_, err := valid(t, "migrations: {dir: "+t.TempDir()+", auto_apply: true}\n").Open(context.Background())
	if err == nil || !strings.HasPrefix(err.Error(), "config: write migrations") {
		t.Fatalf("got %v", err)
	}
}

func TestOpenMigrateFails(t *testing.T) {
	ow, om := writeMigrations, migrate
	t.Cleanup(func() { writeMigrations, migrate = ow, om })
	writeMigrations = func(context.Context, *guard.Guard, string) error { return nil }
	migrate = func(context.Context, *guard.Guard, string) error { return errors.New("boom") }
	_, err := valid(t, "migrations: {dir: x, auto_apply: true}\n").Open(context.Background())
	if err == nil || !strings.HasPrefix(err.Error(), "config: migrate") {
		t.Fatalf("got %v", err)
	}
}

// TestIntegrationOpen runs against real services:
//
//	GUARD_TEST_DATABASE_URL=postgres://postgres:postgres@localhost:18432/guard?sslmode=disable \
//	GUARD_TEST_REDIS_ADDR=localhost:18379 go test ./config/
func TestIntegrationOpen(t *testing.T) {
	dsn, addr := os.Getenv("GUARD_TEST_DATABASE_URL"), os.Getenv("GUARD_TEST_REDIS_ADDR")
	if dsn == "" || addr == "" {
		t.Skip("GUARD_TEST_DATABASE_URL / GUARD_TEST_REDIS_ADDR not set")
	}
	dsn = ownDatabase(t, dsn)
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	// Host user table Guard references; migrations detect its id type.
	if _, err := pool.Exec(context.Background(), `CREATE TABLE IF NOT EXISTS users (id BIGSERIAL PRIMARY KEY, email TEXT UNIQUE)`); err != nil {
		t.Fatal(err)
	}
	t.Setenv("T_DB", dsn)
	t.Setenv("T_REDIS", addr)
	dir := t.TempDir()
	f, err := Parse([]byte("database: {url: \"${T_DB}\"}\nredis: {addr: \"${T_REDIS}\"}\nmigrations: {dir: " + dir + ", auto_apply: true}\n"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	g, err := f.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := g.Health(ctx); err != nil {
		t.Fatal(err)
	}
	var _ ginguard.Options = f.HTTPOptions()
}

// ownDatabase creates guard_prod_config_<random> and drops it WITH (FORCE) on cleanup.
func ownDatabase(t *testing.T, dsn string) string {
	t.Helper()
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	name := "guard_prod_config_" + hex.EncodeToString(b)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(ctx, "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
		admin.Close()
	})
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	return u.String()
}
