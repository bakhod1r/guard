package audit

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/bakhod1r/guard/kernel/migrations"
)

// freshDB creates a dedicated database with a bigint host users table and Guard
// migrations applied. Skips when GUARD_TEST_DATABASE_URL is unset.
func freshDB(t *testing.T) *pgxpool.Pool {
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
	name := "guard_cov_audit_" + hex.EncodeToString(b)
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
			t.Errorf("drop database %s: %v", name, err)
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

// newUser inserts a host user and returns its id as text.
func newUser(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(context.Background(), `INSERT INTO users DEFAULT VALUES RETURNING id::text`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}
