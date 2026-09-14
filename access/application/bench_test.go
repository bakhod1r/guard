package application

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/bakhod1r/guard/access/domain"
	"github.com/bakhod1r/guard/access/infrastructure"
	"github.com/bakhod1r/guard/kernel/migrations"
)

// benchPolicies is the dataset size used by every Authorize benchmark:
// 50 resource types x 4 actions x 5 policies + 10 wildcard policies = 1010.
const benchResources, benchActions, benchPerTarget, benchWildcards = 50, 4, 5, 10

// seedAccess loads roles, a user with three grants and ~1k policies with nested conditions.
func seedAccess(tb testing.TB, roles domain.RoleRepository, policies domain.PolicyRepository) {
	tb.Helper()
	ctx := context.Background()
	svc := NewService(roles, policies)
	for i := 0; i < 3; i++ {
		name := fmt.Sprintf("bench_role_%d", i)
		if _, err := svc.CreateRole(ctx, name, name, "", false); err != nil {
			tb.Fatal(err)
		}
		for a := 0; a < benchActions; a++ {
			code := fmt.Sprintf("res%d.act%d", i, a)
			if _, err := svc.CreatePermission(ctx, code, ""); err != nil {
				tb.Fatal(err)
			}
			if err := svc.GrantPermission(ctx, name, code, ""); err != nil {
				tb.Fatal(err)
			}
		}
		if err := svc.AssignRole(ctx, "1", name, "", nil); err != nil {
			tb.Fatal(err)
		}
	}
	save := func(name, res, act string, prio int) {
		p := &domain.Policy{Name: name, Resource: res, Action: act, Effect: domain.Allow, Priority: prio, Enabled: true,
			Root: &domain.ConditionGroup{Operator: domain.And, Conditions: []domain.Condition{
				{Field: "user.department", Operator: domain.OpEq, Value: []string{"eng"}},
				{Field: "resource.owner", Operator: domain.OpEq, Value: []string{"$user.id"}},
			}, Groups: []domain.ConditionGroup{{Operator: domain.Or, Conditions: []domain.Condition{
				{Field: "env.ip", Operator: domain.OpIn, Value: []string{"10.0.0.1", "10.0.0.2"}},
			}}}}}
		if err := svc.SavePolicy(ctx, p); err != nil {
			tb.Fatal(err)
		}
	}
	for r := 0; r < benchResources; r++ {
		for a := 0; a < benchActions; a++ {
			for k := 0; k < benchPerTarget; k++ {
				save(fmt.Sprintf("p_%d_%d_%d", r, a, k), fmt.Sprintf("res%d", r), fmt.Sprintf("act%d", a), 100+k)
			}
		}
	}
	for w := 0; w < benchWildcards; w++ {
		save(fmt.Sprintf("wild_%d", w), "*", "*", 500+w)
	}
}

// benchPool creates a throwaway database (dropped on cleanup) with Guard migrations.
func benchPool(tb testing.TB) *pgxpool.Pool {
	tb.Helper()
	url := os.Getenv("GUARD_TEST_DATABASE_URL")
	if url == "" {
		tb.Skip("GUARD_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, url)
	if err != nil {
		tb.Fatal(err)
	}
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	name := "guard_prod_access_" + hex.EncodeToString(b)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		admin.Close()
		tb.Fatal(err)
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		tb.Fatal(err)
	}
	cfg.ConnConfig.Database = name
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() {
		pool.Close()
		c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, _ = admin.Exec(c, "DROP DATABASE IF EXISTS "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)")
		admin.Close()
	})
	if _, err := pool.Exec(ctx, `CREATE TABLE users (id BIGSERIAL PRIMARY KEY); INSERT INTO users DEFAULT VALUES`); err != nil {
		tb.Fatal(err)
	}
	ref, err := migrations.Detect(ctx, pool, "users", "id")
	if err != nil {
		tb.Fatal(err)
	}
	if err := migrations.Up(ctx, pool, "", ref); err != nil {
		tb.Fatal(err)
	}
	return pool
}

func benchRequest() domain.Request {
	return domain.Request{
		Subject:     domain.Subject{ID: "1", Attributes: map[string]any{"department": "eng", "id": "1"}},
		Resource:    domain.Resource{Type: "res7", Attributes: map[string]any{"owner": "1"}},
		Action:      "act2",
		Environment: map[string]any{"ip": "10.0.0.1"},
	}
}

func runAuthorize(b *testing.B, svc *Service) {
	ctx := context.Background()
	if _, err := svc.Authorize(ctx, benchRequest()); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := svc.Authorize(ctx, benchRequest()); err != nil {
				b.Error(err)
				return
			}
		}
	})
}

func BenchmarkAuthorizeMemory(b *testing.B) {
	m := infrastructure.NewMemory()
	seedAccess(b, m, m)
	runAuthorize(b, NewService(m, m))
}

func BenchmarkAuthorizePostgres(b *testing.B) {
	pg := infrastructure.NewPostgres(benchPool(b))
	seedAccess(b, pg, pg)
	runAuthorize(b, NewService(pg, pg))
}

// BenchmarkAuthorizeCachedPostgres measures the hot path through the Cached
// decorator (one Redis GET per cached read) in front of Postgres.
func BenchmarkAuthorizeCachedPostgres(b *testing.B) {
	addr := os.Getenv("GUARD_TEST_REDIS_ADDR")
	if addr == "" {
		b.Skip("GUARD_TEST_REDIS_ADDR not set")
	}
	pg := infrastructure.NewPostgres(benchPool(b))
	rdb := redis.NewClient(&redis.Options{Addr: addr})
	suffix := make([]byte, 6)
	_, _ = rand.Read(suffix)
	prefix := "guard_prod_access_bench_" + hex.EncodeToString(suffix) + ":"
	b.Cleanup(func() {
		rdb.Del(context.Background(), prefix+"access:version")
		_ = rdb.Close()
	})
	c := infrastructure.NewCached(pg, pg, rdb, infrastructure.CacheOptions{Prefix: prefix})
	seedAccess(b, c, c)
	runAuthorize(b, NewService(c, c))
	if s := c.Stats(); s.Bypasses != 0 {
		b.Fatalf("unexpected cache bypasses: %+v", s)
	}
}
