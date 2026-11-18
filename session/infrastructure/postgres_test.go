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

	"github.com/alicebob/miniredis/v2"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/bakhod1r/guard/kernel/migrations"
	"github.com/bakhod1r/guard/session/domain"
)

// hookTracer runs hook before every statement; a true result cancels that
// statement's context, forcing a storage error at that exact query.
type hookTracer struct {
	mu   sync.Mutex
	hook func(sql string) bool
}

func (h *hookTracer) set(f func(sql string) bool) {
	h.mu.Lock()
	h.hook = f
	h.mu.Unlock()
}

// failOn fails every statement matching match until reset with set(nil).
// It must keep failing: database/sql retries a statement that fails before it
// is sent on a fresh connection.
func (h *hookTracer) failOn(match func(sql string) bool) { h.set(match) }

func (h *hookTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	h.mu.Lock()
	f := h.hook
	h.mu.Unlock()
	if f != nil && f(d.SQL) {
		c, cancel := context.WithCancel(ctx)
		cancel()
		return c
	}
	return ctx
}

func (h *hookTracer) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

type pgEnv struct {
	pool   *pgxpool.Pool // traced
	plain  *pgxpool.Pool // untraced, for setup and races
	tracer *hookTracer
}

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
	name := "guard_cov_session_" + hex.EncodeToString(b)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	open := func(tr pgx.QueryTracer) *pgxpool.Pool {
		cfg, err := pgxpool.ParseConfig(url)
		if err != nil {
			t.Fatal(err)
		}
		cfg.ConnConfig.Database = name
		cfg.ConnConfig.Tracer = tr
		p, err := pgxpool.NewWithConfig(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	tr := &hookTracer{}
	pool, plain := open(tr), open(nil)
	t.Cleanup(func() {
		pool.Close()
		plain.Close()
		c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if _, err := admin.Exec(c, "DROP DATABASE IF EXISTS "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)"); err != nil {
			t.Errorf("drop database %s: %v", name, err)
		}
		admin.Close()
	})
	if _, err := plain.Exec(ctx, `CREATE TABLE users (id BIGSERIAL PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	ref, err := migrations.Detect(ctx, plain, "users", "id")
	if err != nil {
		t.Fatal(err)
	}
	if err := migrations.Up(ctx, plain, "", ref); err != nil {
		t.Fatal(err)
	}
	return pgEnv{pool: pool, plain: plain, tracer: tr}
}

var testPolicy = domain.Policy{IdleTimeout: time.Hour, AbsoluteTimeout: 24 * time.Hour}

func newSession(uid string, now time.Time) *domain.Session {
	s, _ := domain.New(uid, now, testPolicy)
	return s
}

func newLegacy(t *testing.T) *RedisSessions {
	t.Helper()
	mr := miniredis.RunT(t)
	return NewRedisSessions(redis.NewClient(&redis.Options{Addr: mr.Addr()}), "legacy:")
}

func has(sub string) func(string) bool {
	return func(s string) bool { return strings.Contains(s, sub) }
}

func prefix(p, sub string) func(string) bool {
	return func(s string) bool { return strings.HasPrefix(strings.TrimSpace(s), p) && strings.Contains(s, sub) }
}

func wantNotFound(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, domain.ErrSessionNotFound) {
		t.Fatalf("want ErrSessionNotFound, got %v", err)
	}
}

func wantErr(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("want an error")
	}
}

func TestPostgresSessionsLifecycle(t *testing.T) {
	e := newPG(t)
	r := NewPostgresSessions(e.pool, testPolicy, nil)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)

	s := newSession("1", now)
	s.IP, s.UserAgent, s.Forwarded, s.Locale, s.LocaleSource = "1.2.3.4", "Mozilla/5.0", "9.9.9.9", "uz", "header"
	s.Metadata = map[string]string{"k": "v", domain.FamilyKey: "fam"}
	s.RenewedAt = now
	if err := r.Save(ctx, s, 0); err != nil {
		t.Fatal(err)
	}
	got, err := r.Get(ctx, s.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.UserID != "1" || got.IP != "1.2.3.4" || got.UserAgent != "Mozilla/5.0" || got.Forwarded != "9.9.9.9" ||
		got.Locale != "uz" || got.Metadata["k"] != "v" || got.Family() != "fam" || !got.RenewedAt.Equal(now) {
		t.Fatalf("round trip: %+v", got)
	}

	// a non-string metadata value is dropped on read
	if _, err := e.plain.Exec(ctx, `UPDATE guard_session SET data = '{"metadata":{"n":1,"k":"v"}}' WHERE id = $1`, string(s.ID)); err != nil {
		t.Fatal(err)
	}
	if got, _ := r.Get(ctx, s.ID); len(got.Metadata) != 1 || got.Metadata["k"] != "v" {
		t.Fatalf("metadata: %+v", got.Metadata)
	}

	// Touch slides last_seen
	s.LastSeenAt = now.Add(time.Minute)
	if err := r.Touch(ctx, s, 0); err != nil {
		t.Fatal(err)
	}
	if got, _ := r.Get(ctx, s.ID); !got.LastSeenAt.Equal(s.LastSeenAt) {
		t.Fatalf("touch: %v", got.LastSeenAt)
	}

	// ListByUser: newest first, other users excluded, revoked rows skipped
	s2 := newSession("1", now)
	s2.LastSeenAt = now.Add(2 * time.Minute)
	s3 := newSession("1", now)
	other := newSession("2", now)
	for _, x := range []*domain.Session{s2, s3, other} {
		if err := r.Save(ctx, x, 0); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.plain.Exec(ctx, `UPDATE guard_session SET status = 'revoked' WHERE id = $1`, string(s3.ID)); err != nil {
		t.Fatal(err)
	}
	list, err := r.ListByUser(ctx, "1")
	if err != nil || len(list) != 2 || list[0].ID != s2.ID || list[1].ID != s.ID {
		t.Fatalf("list: %v %v", list, err)
	}

	// a revoked row is gone for Get, Touch, Take and cannot be saved over
	_, err = r.Get(ctx, s3.ID)
	wantNotFound(t, err)
	wantNotFound(t, r.Touch(ctx, s3, 0))
	_, err = r.Take(ctx, s3.ID)
	wantNotFound(t, err)
	wantNotFound(t, r.Save(ctx, s3, 0))

	// unknown ids
	_, err = r.Get(ctx, "missing")
	wantNotFound(t, err)
	_, err = r.Take(ctx, "missing")
	wantNotFound(t, err)

	// Take claims once
	taken, err := r.Take(ctx, s2.ID)
	if err != nil || taken.ID != s2.ID {
		t.Fatalf("take: %v %v", taken, err)
	}
	_, err = r.Take(ctx, s2.ID)
	wantNotFound(t, err)

	// Delete / DeleteByUser
	if err := r.Delete(ctx, s.ID); err != nil {
		t.Fatal(err)
	}
	_, err = r.Get(ctx, s.ID)
	wantNotFound(t, err)
	if err := r.DeleteByUser(ctx, "2"); err != nil {
		t.Fatal(err)
	}
	if list, _ := r.ListByUser(ctx, "2"); len(list) != 0 {
		t.Fatalf("delete by user: %v", list)
	}
}

func TestPostgresSessionsSaveLimited(t *testing.T) {
	e := newPG(t)
	r := NewPostgresSessions(e.pool, testPolicy, nil)
	ctx := context.Background()
	now := time.Now().UTC()
	var ids []domain.ID
	for i := range 3 {
		s := newSession("1", now)
		s.LastSeenAt = now.Add(time.Duration(i) * time.Minute)
		if err := r.SaveLimited(ctx, s, 0, 2); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, s.ID)
	}
	list, _ := r.ListByUser(ctx, "1")
	if len(list) != 2 || list[0].ID != ids[2] || list[1].ID != ids[1] {
		t.Fatalf("limited: %v", list)
	}
	// a failed save evicts nothing
	revoked := newSession("1", now)
	if err := r.Save(ctx, revoked, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := e.plain.Exec(ctx, `UPDATE guard_session SET status = 'expired' WHERE id = $1`, string(revoked.ID)); err != nil {
		t.Fatal(err)
	}
	wantNotFound(t, r.SaveLimited(ctx, revoked, 0, 1))
	if list, _ := r.ListByUser(ctx, "1"); len(list) != 2 {
		t.Fatalf("evicted on failed save: %v", list)
	}
}

func TestPostgresSessionsLegacyAdoption(t *testing.T) {
	e := newPG(t)
	legacy := newLegacy(t)
	r := NewPostgresSessions(e.pool, testPolicy, legacy)
	ctx := context.Background()
	now := time.Now().UTC()

	// a live legacy session moves over on first read
	old := newSession("1", now)
	if err := legacy.Save(ctx, old, time.Hour); err != nil {
		t.Fatal(err)
	}
	got, err := r.Get(ctx, old.ID)
	if err != nil || got.ID != old.ID {
		t.Fatalf("adopt: %v %v", got, err)
	}
	if _, err := legacy.Get(ctx, old.ID); !errors.Is(err, domain.ErrSessionNotFound) {
		t.Fatalf("legacy copy kept: %v", err)
	}
	if _, err := r.Get(ctx, old.ID); err != nil {
		t.Fatalf("adopted session not in postgres: %v", err)
	}

	// an idle legacy session is dropped, not adopted
	idle := newSession("1", now.Add(-2*time.Hour))
	if err := legacy.Save(ctx, idle, time.Hour); err != nil {
		t.Fatal(err)
	}
	_, err = r.Get(ctx, idle.ID)
	wantNotFound(t, err)
	if _, err := legacy.Get(ctx, idle.ID); !errors.Is(err, domain.ErrSessionNotFound) {
		t.Fatalf("idle legacy session kept: %v", err)
	}

	// missing in both stores
	_, err = r.Get(ctx, "missing")
	wantNotFound(t, err)

	// adoption fails when the postgres save fails
	broken := newSession("1", now)
	if err := legacy.Save(ctx, broken, time.Hour); err != nil {
		t.Fatal(err)
	}
	e.tracer.failOn(prefix("INSERT", "guard_session"))
	_, err = r.Get(ctx, broken.ID)
	wantErr(t, err)
	e.tracer.set(nil)
	if _, err := legacy.Get(ctx, broken.ID); err != nil {
		t.Fatalf("legacy session lost on failed adoption: %v", err)
	}

	// ListByUser merges legacy sessions without duplicates
	if err := legacy.Save(ctx, old, time.Hour); err != nil { // same id in both stores
		t.Fatal(err)
	}
	list, err := r.ListByUser(ctx, "1")
	if err != nil || len(list) != 2 {
		t.Fatalf("merged list: %v %v", list, err)
	}

	// Take falls back to the legacy store
	lt := newSession("1", now)
	if err := legacy.Save(ctx, lt, time.Hour); err != nil {
		t.Fatal(err)
	}
	if got, err := r.Take(ctx, lt.ID); err != nil || got.ID != lt.ID {
		t.Fatalf("legacy take: %v %v", got, err)
	}

	// Delete and DeleteByUser clear both stores
	if err := r.Delete(ctx, old.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.Get(ctx, old.ID); !errors.Is(err, domain.ErrSessionNotFound) {
		t.Fatalf("legacy delete: %v", err)
	}
	if err := r.DeleteByUser(ctx, "1"); err != nil {
		t.Fatal(err)
	}
	if list, _ := legacy.ListByUser(ctx, "1"); len(list) != 0 {
		t.Fatalf("legacy delete by user: %v", list)
	}
}

// legacyFail is a legacy store whose reads fail.
type legacyFail struct{ *RedisSessions }

func (legacyFail) ListByUser(context.Context, string) ([]*domain.Session, error) {
	return nil, errors.New("legacy down")
}

// noTake is a legacy store without the Taker capability.
type noTake struct{ domain.Repository }

func TestPostgresSessionsLegacyErrors(t *testing.T) {
	e := newPG(t)
	ctx := context.Background()
	r := NewPostgresSessions(e.pool, testPolicy, legacyFail{newLegacy(t)})
	_, err := r.ListByUser(ctx, "1")
	wantErr(t, err)

	r = NewPostgresSessions(e.pool, testPolicy, noTake{newLegacy(t)})
	_, err = r.Take(ctx, "missing")
	wantNotFound(t, err)
}

func TestPostgresSessionsStorageErrors(t *testing.T) {
	e := newPG(t)
	r := NewPostgresSessions(e.pool, testPolicy, nil)
	ctx := context.Background()
	now := time.Now().UTC()
	s := newSession("1", now)
	if err := r.Save(ctx, s, 0); err != nil {
		t.Fatal(err)
	}
	load := prefix("SELECT", "WHERE id =")

	cases := []struct {
		name  string
		match func(string) bool
		call  func() error
	}{
		{"save", prefix("INSERT", "guard_session"), func() error { return r.Save(ctx, newSession("1", now), 0) }},
		{"get load", load, func() error { _, err := r.Get(ctx, s.ID); return err }},
		{"take load", load, func() error { _, err := r.Take(ctx, s.ID); return err }},
		{"take claim", has("SET status = 'revoked'"), func() error { _, err := r.Take(ctx, s.ID); return err }},
		{"delete", prefix("DELETE", "WHERE id ="), func() error { return r.Delete(ctx, s.ID) }},
		{"list", prefix("SELECT", "WHERE user_id ="), func() error { _, err := r.ListByUser(ctx, "1"); return err }},
		{"delete by user", prefix("DELETE", "WHERE user_id ="), func() error { return r.DeleteByUser(ctx, "1") }},
		{"touch", has("SET last_seen"), func() error { return r.Touch(ctx, s, 0) }},
		{"save limited evict", has("OFFSET"), func() error { return r.SaveLimited(ctx, newSession("1", now), 0, 1) }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e.tracer.failOn(c.match)
			wantErr(t, c.call())
			e.tracer.set(nil)
		})
	}
}

func TestPostgresSessionsTakeLosesRace(t *testing.T) {
	e := newPG(t)
	r := NewPostgresSessions(e.pool, testPolicy, nil)
	ctx := context.Background()
	s := newSession("1", time.Now().UTC())
	if err := r.Save(ctx, s, 0); err != nil {
		t.Fatal(err)
	}
	// another caller claims the session between Load and the claiming UPDATE
	var once sync.Once
	e.tracer.set(func(sql string) bool {
		if strings.Contains(sql, "SET status = 'revoked'") {
			once.Do(func() {
				if _, err := e.plain.Exec(ctx, `UPDATE guard_session SET status = 'revoked' WHERE id = $1`, string(s.ID)); err != nil {
					t.Error(err)
				}
			})
		}
		return false
	})
	_, err := r.Take(ctx, s.ID)
	wantNotFound(t, err)
}
