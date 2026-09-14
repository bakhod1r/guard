package infrastructure

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/bakhod1r/guard/identity/domain"
	"github.com/bakhod1r/guard/kernel/migrations"
)

// freshPool creates a dedicated migrated database (host users table with
// BIGSERIAL id) and drops it on cleanup. Skips without GUARD_TEST_DATABASE_URL.
func freshPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("GUARD_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("GUARD_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	name := "guard_cov_identity_" + hex.EncodeToString(b)
	admin, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	cfg, err := pgxpool.ParseConfig(url)
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
	if _, err := pool.Exec(ctx, `CREATE TABLE users (id BIGSERIAL PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	ref, err := migrations.Detect(ctx, pool, "users", "id")
	if err != nil {
		t.Fatal(err)
	}
	if err := migrations.Up(ctx, pool, "", ref); err != nil {
		t.Fatal(err)
	}
	return pool
}

func hostUsers(t *testing.T, pool *pgxpool.Pool, n int) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `INSERT INTO users SELECT FROM generate_series(1, $1)`, n); err != nil {
		t.Fatal(err)
	}
}

func account(id, email string, created time.Time) *domain.User {
	return &domain.User{ID: domain.UserID(id), Email: domain.Email(email), Status: domain.StatusActive,
		PasswordHash: "h", Attributes: map[string]any{"dept": "it"}, CreatedAt: created, UpdatedAt: created}
}

func TestPostgresUsersCreateReadUpdate(t *testing.T) {
	ctx := context.Background()
	pool := freshPool(t)
	hostUsers(t, pool, 2)
	r := NewPostgresUsers(pool)
	now := time.Now().UTC().Truncate(time.Microsecond)
	u := account("1", "a@b.uz", now)
	if err := r.Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	if err := r.Create(ctx, account("2", "c@d.uz", now)); err != nil {
		t.Fatal(err)
	}

	got, err := r.ByID(ctx, "1")
	if err != nil || got.Email != "a@b.uz" || got.Attributes["dept"] != "it" || !got.CreatedAt.Equal(now) {
		t.Fatalf("by id: %+v %v", got, err)
	}
	if got, err := r.ByEmail(ctx, "c@d.uz"); err != nil || got.ID != "2" {
		t.Fatalf("by email: %+v %v", got, err)
	}

	u.Status, u.FailedAttempts, u.LastFailedAt = domain.StatusBanned, 2, &now
	if err := r.Update(ctx, u); err != nil {
		t.Fatal(err)
	}
	if got, _ := r.ByID(ctx, "1"); got.Status != domain.StatusBanned || got.FailedAttempts != 2 || got.LastFailedAt == nil {
		t.Fatalf("after update: %+v", got)
	}
}

func TestPostgresUsersMapsConstraintViolations(t *testing.T) {
	ctx := context.Background()
	pool := freshPool(t)
	hostUsers(t, pool, 2)
	r := NewPostgresUsers(pool)
	now := time.Now().UTC()
	if err := r.Create(ctx, account("1", "a@b.uz", now)); err != nil {
		t.Fatal(err)
	}
	if err := r.Create(ctx, account("2", "c@d.uz", now)); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		call func() error
		want error
	}{
		{"create duplicate user id", func() error { return r.Create(ctx, account("1", "new@b.uz", now)) }, domain.ErrAccountExists},
		{"create duplicate email", func() error {
			if _, err := pool.Exec(ctx, `INSERT INTO users DEFAULT VALUES`); err != nil {
				return err
			}
			return r.Create(ctx, account("3", "a@b.uz", now))
		}, domain.ErrEmailTaken},
		{"create missing host user", func() error { return r.Create(ctx, account("999", "x@b.uz", now)) }, domain.ErrUserNotFound},
		{"create non-numeric id", func() error { return r.Create(ctx, account("abc", "x@b.uz", now)) }, domain.ErrUserNotFound},
		{"update email taken", func() error { return r.Update(ctx, account("2", "a@b.uz", now)) }, domain.ErrEmailTaken},
		{"update non-numeric id", func() error { return r.Update(ctx, account("abc", "x@b.uz", now)) }, domain.ErrUserNotFound},
		{"update missing row", func() error { return r.Update(ctx, account("999", "x@b.uz", now)) }, domain.ErrUserNotFound},
		{"by id missing", func() error { _, err := r.ByID(ctx, "999"); return err }, domain.ErrUserNotFound},
		{"by id non-numeric", func() error { _, err := r.ByID(ctx, "abc"); return err }, domain.ErrUserNotFound},
		{"by email missing", func() error { _, err := r.ByEmail(ctx, "no@b.uz"); return err }, domain.ErrUserNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.call(); !errors.Is(err, tc.want) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
		})
	}
}

func TestPostgresUsersList(t *testing.T) {
	ctx := context.Background()
	pool := freshPool(t)
	hostUsers(t, pool, 4)
	r := NewPostgresUsers(pool)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	seed := []*domain.User{
		account("1", "bob@x.uz", base),
		account("2", "alice@x.uz", base),
		account("3", "50%off@y.uz", base.Add(time.Hour)),
		account("4", "a_b@y.uz", base.Add(2*time.Hour)),
	}
	seed[1].Status = domain.StatusBanned
	for _, u := range seed {
		if err := r.Create(ctx, u); err != nil {
			t.Fatal(err)
		}
	}
	ids := func(us []domain.User) string {
		s := ""
		for _, u := range us {
			s += string(u.ID)
		}
		return s
	}
	cases := []struct {
		name  string
		q     domain.ListQuery
		want  string
		total int
	}{
		{"all newest first then id", domain.ListQuery{Limit: 10}, "4312", 4},
		{"paging", domain.ListQuery{Limit: 2, Offset: 1}, "31", 4},
		{"email substring case-insensitive", domain.ListQuery{Limit: 10, Search: "BOB"}, "1", 1},
		{"exact user id", domain.ListQuery{Limit: 10, Search: "2"}, "2", 1},
		{"percent is literal", domain.ListQuery{Limit: 10, Search: "%"}, "3", 1},
		{"underscore is literal", domain.ListQuery{Limit: 10, Search: "_"}, "4", 1},
		{"status filter", domain.ListQuery{Limit: 10, Status: domain.StatusBanned}, "2", 1},
		{"no match", domain.ListQuery{Limit: 10, Search: "zzz"}, "", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, total, err := r.List(ctx, tc.q)
			if err != nil || ids(got) != tc.want || total != tc.total {
				t.Fatalf("got %q %d %v, want %q %d", ids(got), total, err, tc.want, tc.total)
			}
		})
	}

	t.Run("negative limit fails the page query", func(t *testing.T) {
		if _, _, err := r.List(ctx, domain.ListQuery{Limit: -1}); err == nil {
			t.Fatal("want error")
		}
	})
}

// cancelOnQuery cancels the query context as soon as a statement containing
// marker starts, so the statement fails before reaching the server.
type cancelOnQuery struct {
	marker string
	cancel context.CancelFunc
}

func (c *cancelOnQuery) TraceQueryStart(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	if strings.Contains(d.SQL, c.marker) {
		c.cancel()
	}
	return ctx
}

func (*cancelOnQuery) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func TestPostgresUsersListFailsWhenPageQueryCannotStart(t *testing.T) {
	pool := freshPool(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cfg := pool.Config()
	cfg.ConnConfig.Tracer = &cancelOnQuery{marker: "ORDER BY created_at", cancel: cancel}
	traced, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer traced.Close()
	if _, _, err := NewPostgresUsers(traced).List(ctx, domain.ListQuery{Limit: 10}); !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
}

func TestPostgresUsersSurfacesStorageErrors(t *testing.T) {
	ctx := context.Background()
	pool := freshPool(t)
	hostUsers(t, pool, 1)
	r := NewPostgresUsers(pool)
	now := time.Now().UTC()
	if err := r.Create(ctx, account("1", "a@b.uz", now)); err != nil {
		t.Fatal(err)
	}

	unmarshalable := account("1", "a@b.uz", now)
	unmarshalable.Attributes = map[string]any{"bad": make(chan int)}
	if err := r.Create(ctx, unmarshalable); err == nil {
		t.Fatal("create with unmarshalable attributes: want error")
	}
	if err := r.Update(ctx, unmarshalable); err == nil {
		t.Fatal("update with unmarshalable attributes: want error")
	}

	// Corrupt attributes (not a JSON object) to exercise decode failures.
	if _, err := pool.Exec(ctx, `ALTER TABLE guard_account DROP CONSTRAINT guard_account_attributes_object;
		UPDATE guard_account SET attributes = '5'::jsonb`); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ByID(ctx, "1"); err == nil || errors.Is(err, domain.ErrUserNotFound) {
		t.Fatalf("by id corrupt attrs: %v", err)
	}
	if _, _, err := r.List(ctx, domain.ListQuery{Limit: 10}); err == nil {
		t.Fatal("list corrupt attrs: want error")
	}

	pool.Close()
	if err := r.Create(ctx, account("1", "z@b.uz", now)); err == nil || errors.Is(err, domain.ErrUserNotFound) {
		t.Fatalf("create closed pool: %v", err)
	}
	if err := r.Update(ctx, account("1", "z@b.uz", now)); err == nil || errors.Is(err, domain.ErrUserNotFound) {
		t.Fatalf("update closed pool: %v", err)
	}
	if _, _, err := r.List(ctx, domain.ListQuery{Limit: 10}); err == nil {
		t.Fatal("list closed pool: want error")
	}
}
