# Quick start

## Install

```bash
go get github.com/bakhod1r/guard
```

Requirements: Go 1.26+, PostgreSQL 13+, Redis 6.2+.

## Wire it into an existing app

Guard does **not** create a users table. It detects your existing table
(`users.id` — bigint, uuid, text…) and references it.

```go
pool, _ := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
rdb := redis.NewClient(&redis.Options{Addr: os.Getenv("REDIS_ADDR")})

g, _ := guard.New(guard.Config{DB: pool, Redis: rdb, UserTable: "users", UserIDColumn: "id"})

g.WriteMigrations(ctx, "./migrations/guard") // detects users.id type, renders SQL into your repo (never overwrites)
g.Migrate(ctx, "./migrations/guard")         // goose, version table guard_schema_version

// give an existing user of yours login credentials + admin role
g.EnsureAdmin(ctx, adminUserID, "admin@example.com", os.Getenv("ADMIN_PASSWORD"))

r := gin.Default()
opts := ginguard.Options{
    // optional self-registration: insert a NEW row into your users table, return its id
    CreateUser: func(ctx context.Context, email string) (string, error) { /* INSERT ... RETURNING id::text */ },
}
ginguard.Mount(r.Group("/api"), g, opts)          // /api/auth/*, /api/guard/*
adminui.Mount(r, g, adminui.Options{})            // /guard-admin (HTML panel)

r.GET("/api/invoices/:id", ginguard.RequirePermission(g, opts, "invoice.read"), handler)
```

Link accounts for users you already have:
`g.CreateAccount(ctx, userID, email, password, attrs, guard.RequestMeta{})`.

Not using Gin? The HTTP layer is plain `net/http` (`httpguard`) — see
[Frameworks](frameworks.md).

## Run the example

```bash
# whole stack in containers (app + PostgreSQL + Redis)
docker compose -f examples/gin/docker-compose.yml up --build
# API:   http://localhost:18080/api/auth/login
# Panel: http://localhost:18080/guard-admin   (admin@example.com / change-me-now)

# or run the app from source against the compose databases
docker compose -f examples/gin/docker-compose.yml up -d --wait postgres redis
DATABASE_URL=postgres://postgres:postgres@localhost:18432/guard?sslmode=disable REDIS_ADDR=localhost:18379 \
GUARD_ADMIN_EMAIL=admin@example.com GUARD_ADMIN_PASSWORD=change-me-now GUARD_INSECURE_COOKIE=1 \
go run ./examples/gin   # http://localhost:8080
```

## Configuration file and autoseed

Load Guard from YAML (`${ENV}` expansion, unknown keys rejected, secrets from env)
and protect host routes by derived permissions:

```go
cfg, _ := config.Load("guard.yaml")
g, _ := cfg.Open(ctx)                                  // PostgreSQL + Redis, migrations if auto_apply
api.Use(ginguard.Protect(g, cfg.HTTPOptions(), "/api")) // GET /api/reports/:id -> reports.read
ao, _ := cfg.AutoseedOptions()
_, _ = ginguard.Autoseed(ctx, g, r.Routes(), ao)       // create permissions; super role gets all, others denied
```

Key reference and caveats: [Configuration](configuration.md).

## Route auto-discovery

```go
api.Use(ginguard.ProtectRoutes(g, opts, so))                  // GET /api/reports/:id -> reports.read
res, err := ginguard.SyncRoutes(ctx, g, r.Routes(), ginguard.SyncOptions{
	Prefix: "/api", SkipPrefixes: []string{"/api/auth", "/api/guard"},
	// FullRoles nil = admin + super_admin; UserActions nil = ["read"] for role "user"
	Overrides: map[string]string{"POST /api/reports/:id/approve": "reports.approve"},
})
```

Routes served by Guard's own handlers (`ginguard.Mount`, `adminui.Mount`) are skipped
automatically by both `SyncRoutes` and `ProtectRoutes` (detected from gin's handler
name); they enforce their own checks. `SyncOptions.IncludeGuardRoutes: true` opts out.
`SkipPrefixes` still excludes any other path prefix. Routes are stored in `guard_route`
(migration `00006`); removed routes are marked stale and existing grants are never
revoked. `res` lists created, skipped and stale entries; the admin panel shows them
under **Routes**.

## Super admin

`super_admin` is a system wildcard role (migration `00005`). Only a super admin may
grant, revoke or delete a privileged role (`admin`, `super_admin`, any wildcard role,
any role holding `role.write`, `role.assign` or `policy.write`), grant or revoke those
management permissions, write policies on resource `*`, `role` or `policy`, or change a
privileged user's account; the last super admin cannot lose the role, be banned or
suspended (`409 last_super_admin`). ABAC deny policies still apply to super admins.

```go
_, _ = g.EnsureSuperAdmin(ctx, hostUserID, email, password) // idempotent bootstrap
err := g.AssignRole(ctx, actorID, userID, "admin", nil)     // guard.ErrForbidden unless actor is super admin
```

Upgrading: existing admins are not promoted; call `EnsureSuperAdmin` once.
`examples/gin` reads `GUARD_SUPERADMIN_EMAIL` / `GUARD_SUPERADMIN_PASSWORD`.

## Access cache

`Config.AccessCache: &guard.AccessCacheOptions{}` (YAML `access_cache.enabled: true`)
caches role grants and policies per instance and invalidates all instances through a
Redis version key (default TTL 30s). Redis failures bypass to PostgreSQL.

Behind a load balancer add `L2: true` (YAML `access_cache.shared: true`) to also keep
the loaded grants and policies in Redis: an in-process miss on one instance is then
served from the copy another instance loaded instead of from PostgreSQL, which matters
most right after a deploy or an invalidation, when every instance would otherwise
reload at once. Shared entries are namespaced by the same version key, so one write
invalidates both levels; they expire after `L2TTL` (default twice `TTL`).

Call `g.InvalidateAccess(ctx)` after changes made outside Guard (e.g. deleting a host
user); `g.AccessStats()` exposes hit/miss counters.

## Audit buffering (Redis → PostgreSQL)

By default audit events are written to PostgreSQL synchronously (or in-process with
`AsyncAudit`). For high write volume, queue them in Redis and batch-insert:

```go
g, err := guard.New(guard.Config{
    // ...
    AuditBuffer: guard.AuditBuffer{
        Enabled:   true,
        BatchSize: 500,         // default 500
        Interval:  time.Second, // default 1s
    },
})
defer g.Close(ctx) // flushes the queue on shutdown
```

- Events are pushed to `<prefix>{audit}:queue`; one flusher across all instances holds
  `<prefix>{audit}:lock` (30s TTL, extended per batch; hash tag keeps keys in one Redis
  Cluster slot) and writes batches via `RecordBatch` (`ON CONFLICT (id) DO NOTHING`, so
  retries are idempotent).
- A failed PostgreSQL write leaves the batch queued for the next tick; undecodable
  entries, and single events PostgreSQL rejects while the rest of the batch succeeds,
  move to `<prefix>{audit}:dead`.
- If Redis is unreachable, `Record` falls back to a direct synchronous write.
- When `Enabled`, `AsyncAudit` is ignored.

Trade-offs vs `AsyncAudit`: queued events survive process restarts and are shared across
instances; but `List` (and `GET /guard/audit`) shows only flushed events, so reads lag
by up to `Interval`, and a PostgreSQL outage grows the Redis list — size Redis memory
and alert on queue length.

## Testing

```bash
make test               # unit tests; integration tests skip without services
make test-integration   # starts PostgreSQL + Redis (compose), go test -race with coverage
make cover              # fails if any package is below 100.0% statements
make lint vuln          # golangci-lint v2 (.golangci.yml), govulncheck
```

Manual integration run against your own services:

```bash
GUARD_TEST_DATABASE_URL=postgres://postgres:postgres@localhost:18432/guard?sslmode=disable \
GUARD_TEST_REDIS_ADDR=localhost:18379 \
go test -count=1 -race -covermode=atomic -coverprofile=coverage.out $(go list ./... | grep -v /examples/)
bash scripts/coverage-gate.sh coverage.out
```

CI (`.github/workflows/ci.yml`) runs the same gates on PostgreSQL 13 and 17.
