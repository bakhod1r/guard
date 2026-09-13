// Package guardtest builds a Guard on in-memory storage (plus a Redis client
// for sessions) seeded like the SQL migrations. For tests only.
package guardtest

import (
	"context"

	"github.com/redis/go-redis/v9"

	"github.com/bakhod1r/guard"
	accessdomain "github.com/bakhod1r/guard/access/domain"
	accessinfra "github.com/bakhod1r/guard/access/infrastructure"
	apikeyinfra "github.com/bakhod1r/guard/apikey/infrastructure"
	"github.com/bakhod1r/guard/audit"
	identityinfra "github.com/bakhod1r/guard/identity/infrastructure"
	"github.com/bakhod1r/guard/ratelimit"
	sessioninfra "github.com/bakhod1r/guard/session/infrastructure"
)

// New returns a seeded in-memory Guard. cfg.DB and cfg.Redis are ignored;
// any non-empty string is a valid user id (no host user table in memory).
func New(rdb redis.UniversalClient, cfg guard.Config) *guard.Guard {
	store := accessinfra.NewMemory()
	g := guard.Build(guard.Repositories{
		Users:    identityinfra.NewMemoryUsers(),
		Hasher:   &identityinfra.Argon2Hasher{Memory: 1024, Time: 1, Threads: 1, KeyLen: 32, SaltLen: 16},
		Sessions: sessioninfra.NewRedisSessions(rdb, "guardtest:"),
		Roles:    store,
		Policies: store,
		Audit:    &audit.Memory{},
		APIKeys:  apikeyinfra.NewMemory(),
		Limiter:  ratelimit.NewRedis(rdb, "guardtest:"),
	}, cfg)
	Seed(context.Background(), store)
	return g
}

// Seed mirrors kernel/migrations/sql/00002_guard_seed.sql.tmpl and 00003.
func Seed(ctx context.Context, store *accessinfra.Memory) {
	_ = store.CreateRole(ctx, &accessdomain.Role{Name: "admin", Title: "Administrator", IsSystem: true, Wildcard: true})
	_ = store.CreateRole(ctx, &accessdomain.Role{Name: "user", Title: "User", IsSystem: true})
	for _, code := range []string{"user.read", "user.write", "role.read", "role.write", "role.assign",
		"permission.read", "permission.write", "policy.read", "policy.write", "session.read", "session.revoke", "audit.read", "apikey.read", "apikey.revoke"} {
		p, _ := accessdomain.ParsePermission(code)
		_ = store.CreatePermission(ctx, p)
	}
	selfCond := func(field string) *accessdomain.ConditionGroup {
		return &accessdomain.ConditionGroup{Operator: accessdomain.And,
			Conditions: []accessdomain.Condition{{Field: field, Operator: accessdomain.OpEq, Value: []string{"$user.id"}}}}
	}
	_ = store.SavePolicy(ctx, &accessdomain.Policy{ID: "00000000-0000-0000-0000-000000000001", Name: "self-service user read",
		Resource: "user", Action: "read", Effect: accessdomain.Allow, Priority: 100, Enabled: true, Root: selfCond("resource.id")})
	_ = store.SavePolicy(ctx, &accessdomain.Policy{ID: "00000000-0000-0000-0000-000000000002", Name: "self-service role read",
		Resource: "role", Action: "read", Effect: accessdomain.Allow, Priority: 100, Enabled: true, Root: selfCond("resource.owner_id")})
	_ = store.SavePolicy(ctx, &accessdomain.Policy{ID: "00000000-0000-0000-0000-000000000003", Name: "blocked user denied",
		Resource: "*", Action: "*", Effect: accessdomain.Deny, Priority: 10, Enabled: true,
		Root: &accessdomain.ConditionGroup{Operator: accessdomain.And, Conditions: []accessdomain.Condition{
			{Field: "user.status", Operator: accessdomain.OpIn, Value: []string{"banned", "suspended"}}}}})
}
