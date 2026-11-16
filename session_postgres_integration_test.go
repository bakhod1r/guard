package guard_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/bakhod1r/guard"
	sessionapp "github.com/bakhod1r/guard/session/application"
	sessiondomain "github.com/bakhod1r/guard/session/domain"
	sessioninfra "github.com/bakhod1r/guard/session/infrastructure"
)

const iphoneUA = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1"

// Config.SessionStore = SessionPostgres: sessions live in guard_session, survive a Redis flush, rotate once, expire by
// idle window, and sessions created in Redis before the switch are carried over (LegacyRedisSessions). Same services as
// TestIntegrationPostgresRedis.
func TestIntegrationPostgresSessions(t *testing.T) {
	dsn, addr := os.Getenv("GUARD_TEST_DATABASE_URL"), os.Getenv("GUARD_TEST_REDIS_ADDR")
	if dsn == "" || addr == "" {
		t.Skip("GUARD_TEST_DATABASE_URL / GUARD_TEST_REDIS_ADDR not set")
	}
	ctx := context.Background()
	pool := integrationDatabase(t, dsn)
	rdb := redis.NewClient(&redis.Options{Addr: addr})
	defer rdb.Close()
	if _, err := pool.Exec(ctx, `CREATE TABLE app_users (id BIGSERIAL PRIMARY KEY, full_name TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	prefix := "guard-ps-" + pool.Config().ConnConfig.Database + ":"
	cfg := guard.Config{DB: pool, Redis: rdb, RedisPrefix: prefix, UserTable: "app_users", SessionStore: guard.SessionPostgres,
		LegacyRedisSessions: true, Session: guard.SessionPolicy{IdleTimeout: time.Hour, AbsoluteTimeout: 24 * time.Hour}}
	g, err := guard.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "m")
	if _, err := g.WriteMigrations(ctx, dir); err != nil {
		t.Fatal(err)
	}
	if err := g.Migrate(ctx, dir); err != nil {
		t.Fatal(err)
	}

	count := func(where string, args ...any) int {
		var n int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM guard_session `+where, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	s, tok, err := g.Sessions.Start(ctx, sessionapp.StartInput{UserID: "7", IP: "203.0.113.9", UserAgent: iphoneUA, Metadata: map[string]string{"k": "v"}})
	if err != nil {
		t.Fatal(err)
	}
	if count("WHERE id = $1 AND status = 'active'", string(s.ID)) != 1 {
		t.Fatal("session row missing")
	}
	if keys, _ := rdb.Keys(ctx, prefix+"session:*").Result(); len(keys) != 0 {
		t.Fatalf("session written to Redis: %v", keys)
	}

	// Redis loses everything: the session is still good, with all its data
	if err := rdb.FlushAll(ctx).Err(); err != nil {
		t.Fatal(err)
	}
	got, err := g.Sessions.Resolve(ctx, tok)
	if err != nil || got.IP != "203.0.113.9" || got.UserAgent != iphoneUA || got.Metadata["k"] != "v" {
		t.Fatalf("resolve after flush: %+v %v", got, err)
	}

	// the stored row carries the parsed device and client, not just the raw header
	var os, family string
	var human bool
	if err := pool.QueryRow(ctx, `SELECT device->>'OS', device->>'Raw', (client->>'Bot')::boolean IS NOT TRUE FROM guard_session WHERE id = $1`, string(s.ID)).Scan(&os, &family, &human); err != nil {
		t.Fatal(err)
	}
	if os == "" || family != iphoneUA || !human {
		t.Fatalf("device not parsed: os=%q raw=%q human=%v", os, family, human)
	}

	// rotate: one winner, the old token dies
	_, tok2, err := g.Sessions.Rotate(ctx, tok)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.Sessions.Resolve(ctx, tok); err != sessiondomain.ErrSessionNotFound {
		t.Fatalf("old token: %v", err)
	}
	if _, _, err := g.Sessions.Rotate(ctx, tok); err == nil {
		t.Fatal("rotating a spent token succeeded")
	}
	if list, err := g.Sessions.List(ctx, "7"); err != nil || len(list) != 1 {
		t.Fatalf("list: %d %v", len(list), err)
	}

	// idle expiry
	if _, err := pool.Exec(ctx, `UPDATE guard_session SET last_seen = now() - interval '2 hours' WHERE user_id = '7'`); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Sessions.Resolve(ctx, tok2); err == nil {
		t.Fatal("idle session resolved")
	}

	// revoke all
	_, tok3, _ := g.Sessions.Start(ctx, sessionapp.StartInput{UserID: "7"})
	if err := g.Sessions.RevokeAll(ctx, "7"); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Sessions.Resolve(ctx, tok3); err == nil {
		t.Fatal("revoked session resolved")
	}

	// a session written to Redis before the switch is carried over
	old := sessioninfra.NewRedisSessions(rdb, prefix)
	ls, oldTok := sessiondomain.New("8", time.Now().UTC(), sessiondomain.Policy{IdleTimeout: time.Hour, AbsoluteTimeout: 24 * time.Hour})
	if err := old.Save(ctx, ls, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Sessions.Resolve(ctx, oldTok); err != nil {
		t.Fatalf("legacy session: %v", err)
	}
	if _, err := old.Get(ctx, ls.ID); err != sessiondomain.ErrSessionNotFound {
		t.Fatalf("legacy copy kept in Redis: %v", err)
	}
	if count("WHERE id = $1", string(ls.ID)) != 1 {
		t.Fatal("legacy session not adopted")
	}

	// the same Guard without the legacy bridge does not see Redis sessions
	cfg.LegacyRedisSessions = false
	g2, err := guard.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ls2, tok4 := sessiondomain.New("9", time.Now().UTC(), sessiondomain.DefaultPolicy())
	if err := old.Save(ctx, ls2, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := g2.Sessions.Resolve(ctx, tok4); err != sessiondomain.ErrSessionNotFound {
		t.Fatalf("redis session visible without legacy bridge: %v", err)
	}

	// the default store stays Redis
	cfg.SessionStore = ""
	g3, err := guard.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g3.Sessions.Resolve(ctx, tok4); err != nil {
		t.Fatalf("default (redis) store: %v", err)
	}
	cfg.SessionStore = "memcached"
	if _, err := guard.New(cfg); err == nil {
		t.Fatal("unknown store accepted")
	}
}
