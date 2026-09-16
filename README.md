<p align="center">
  <img src="assets/banner.png" alt="Guard" width="180">
</p>

<h1 align="center">Guard</h1>

<p align="center">
  <b>Enterprise-grade authorization and API security platform for Go.</b>
</p>

<p align="center">
  <a href="#installation">Install</a> ·
  <a href="#quick-start">Quick Start</a> ·
  <a href="#core-components">Components</a> ·
  <a href="#roadmap">Roadmap</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Go-1.26%2B-00ADD8?logo=go&logoColor=white" alt="Go">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License">
  <img src="https://img.shields.io/badge/status-alpha-orange" alt="Status">
</p>

---

Guard is a Go-native security toolkit that simplifies authentication, authorization, and API protection for modern applications and microservices. It provides session management, RBAC, ABAC, API key authentication, rate limiting, audit logging, and security middleware with a developer-friendly API.

## Features

| | |
|---|---|
| 🔐 Session management | 👥 Role-Based Access Control (RBAC) |
| 🏷️ Attribute-Based Access Control (ABAC) | 🔑 API key authentication |
| ⚡ Configurable rate limiting | 📋 Audit logs |
| 🛡️ Security middleware (CSRF, headers, body limit) | 🔄 Automatic permission sync from routes |
| 🖥️ Server-rendered admin panel | 👑 Protected super admin role |
| 🚀 net/http, Gin, Echo, Fiber, Chi, Iris, Hertz, Beego, gorilla/mux, httprouter | 💾 PostgreSQL, Redis |

Planned (not yet available): MySQL, service-to-service authentication, security analytics, plugin architecture. See [Roadmap](#roadmap).

## Frameworks

The HTTP layer is plain `net/http` (`httpguard`): routes, middleware and the
admin panel all come as `http.Handler`, so the `net/http` router family works
with no adapter, and Echo, Fiber, Iris, Hertz and Beego get thin adapters in
their own Go modules — installing Guard pulls none of them in.

```go
mux := http.NewServeMux()
httpguard.Mount(mux, g, httpguard.Options{AuthPath: "/api/auth", AdminPath: "/api/guard"})
mux.Handle("/guard-admin/", adminui.Handler(g, adminui.Options{}))
mux.Handle("GET /api/invoices/{id}",
    httpguard.RequirePermission(g, opts, "invoice.read")(invoiceHandler))
```

Full table, per-framework snippets and the path-parameter wiring for chi,
gorilla/mux and httprouter: [docs/frameworks.md](docs/frameworks.md).

## Installation

```bash
go get github.com/bakhod1r/guard
```

Requirements: Go 1.26+, PostgreSQL 13+ (CI tests 13 and 17), Redis 6.2+ (CI tests 7).

## Quick Start

Guard does **not** create a users table. It detects your existing table (`users.id` — bigint, uuid, text…) and references it.

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

Link accounts for users you already have: `g.CreateAccount(ctx, userID, email, password, attrs, guard.RequestMeta{})`.

### Run the example

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

Load Guard from YAML (`${ENV}` expansion, unknown keys rejected, secrets from env) and protect host routes by derived permissions:

```go
cfg, _ := config.Load("guard.yaml")
g, _ := cfg.Open(ctx)                                  // PostgreSQL + Redis, migrations if auto_apply
api.Use(ginguard.Protect(g, cfg.HTTPOptions(), "/api")) // GET /api/reports/:id -> reports.read
ao, _ := cfg.AutoseedOptions()
_, _ = ginguard.Autoseed(ctx, g, r.Routes(), ao)       // create permissions; super role gets all, others denied
```

Key reference and caveats: [docs/configuration.md](docs/configuration.md).

## HTTP API (ginguard.Mount)

| Route | Guard |
|---|---|
| `POST /auth/register`, `POST /auth/login` | public |
| `POST /auth/logout`, `POST /auth/logout-all`, `GET /auth/me`, `PUT /auth/password` | session |
| `GET /auth/sessions`, `DELETE /auth/sessions/:id` | session |
| `GET /auth/me`, `POST /auth/authorize` | session or API key |
| `GET\|POST /auth/api-keys`, `DELETE /auth/api-keys/:id` | session (keys cannot mint keys) |
| `GET\|DELETE /guard/users/:id/api-keys` | `apikey.read` / `apikey.revoke` |
| `GET /guard/users/:id` | `user.read` or self |
| `PUT /guard/users/:id/status`, `PUT /guard/users/:id/attributes` | `user.write` |
| `GET /guard/users/:id/roles` | `role.read` or self |
| `POST /guard/users/:id/roles`, `DELETE /guard/users/:id/roles/:role` | `role.assign` |
| `GET\|DELETE /guard/users/:id/sessions` | `session.read` / `session.revoke` |
| `GET\|POST /guard/roles`, `GET\|DELETE /guard/roles/:name` | `role.read` / `role.write` |
| `POST /guard/roles/:name/permissions`, `DELETE /guard/roles/:name/permissions/:code` | `role.write` |
| `GET\|POST /guard/permissions` | `permission.read` / `permission.write` |
| `GET\|POST /guard/policies`, `GET\|PUT\|DELETE /guard/policies/:id` | `policy.read` / `policy.write` |
| `GET /guard/audit` | `audit.read` |

Credential: `X-API-Key: gk_...`, `Authorization: Bearer <token|gk_...>`, or the `guard_session` cookie (HttpOnly, Secure, SameSite=Strict).

API keys act as their owner narrowed by scopes (`invoice.read`, `invoice.*`, `*`); only the SHA-256 is stored and the token is shown once.

Rate limiting: `/auth/login` and `/auth/register` are limited per IP (default 10/min, `Options.AuthRateLimit`). Any route:
`ginguard.RateLimit(g, "reports", ratelimit.Rule{Limit: 100, Window: time.Minute}, ginguard.ByPrincipal)` — Redis sliding window, `X-RateLimit-*` and `Retry-After` headers, fails open if Redis errors.

## Authorization model

- **RBAC** — `role → permission (resource.action)`; `wildcard` roles pass everything; user roles may expire.
- **ABAC** — policies target `(resource, action)` (or `*`) with a condition tree (`and`/`or`, `negate`).
  Fields: `user.*`, `resource.*`, `env.*`; values starting with `$` reference attributes (`$user.id`).
- **Decision** — matching policies sorted by `priority` ASC; the strongest tier decides, DENY wins inside a tier;
  no policy matched → RBAC; otherwise deny (fail-closed).
- Seeded: roles `super_admin` / `admin` (wildcard) / `user`, self-service read policies, `blocked user denied` (priority 10).

## Super admin

`super_admin` is a system wildcard role (migration `00005`). Only a super admin may grant, revoke or delete a privileged role (`admin`, `super_admin`, any wildcard role, any role holding `role.write`, `role.assign` or `policy.write`), grant or revoke those management permissions, write policies on resource `*`, `role` or `policy`, or change a privileged user's account; the last super admin cannot lose the role, be banned or suspended (`409 last_super_admin`). ABAC deny policies still apply to super admins.

```go
_, _ = g.EnsureSuperAdmin(ctx, hostUserID, email, password) // idempotent bootstrap
err := g.AssignRole(ctx, actorID, userID, "admin", nil)     // guard.ErrForbidden unless actor is super admin
```

Upgrading: existing admins are not promoted; call `EnsureSuperAdmin` once. `examples/gin` reads `GUARD_SUPERADMIN_EMAIL` / `GUARD_SUPERADMIN_PASSWORD`.

## Route auto-discovery

```go
api.Use(ginguard.ProtectRoutes(g, opts, so))                  // GET /api/reports/:id -> reports.read
res, err := ginguard.SyncRoutes(ctx, g, r.Routes(), ginguard.SyncOptions{
	Prefix: "/api", SkipPrefixes: []string{"/api/auth", "/api/guard"},
	// FullRoles nil = admin + super_admin; UserActions nil = ["read"] for role "user"
	Overrides: map[string]string{"POST /api/reports/:id/approve": "reports.approve"},
})
```

Routes served by Guard's own handlers (`ginguard.Mount`, `adminui.Mount`) are skipped automatically by both `SyncRoutes` and `ProtectRoutes` (detected from gin's handler name); they enforce their own checks. `SyncOptions.IncludeGuardRoutes: true` opts out. `SkipPrefixes` still excludes any other path prefix. Routes are stored in `guard_route` (migration `00006`); removed routes are marked stale and existing grants are never revoked. `res` lists created, skipped and stale entries; the admin panel shows them under **Routes**.

## Access cache

`Config.AccessCache: &guard.AccessCacheOptions{}` (YAML `access_cache.enabled: true`) caches role grants and policies per instance and invalidates all instances through a Redis version key (default TTL 30s). Redis failures bypass to PostgreSQL. Behind a load balancer add `L2: true` (YAML `access_cache.shared: true`) to also keep the loaded grants and policies in Redis: an in-process miss on one instance is then served from the copy another instance loaded instead of from PostgreSQL, which matters most right after a deploy or an invalidation, when every instance would otherwise reload at once. Shared entries are namespaced by the same version key, so one write invalidates both levels; they expire after `L2TTL` (default twice `TTL`). Call `g.InvalidateAccess(ctx)` after changes made outside Guard (e.g. deleting a host user); `g.AccessStats()` exposes hit/miss counters.

## Layout (DDD)

| Context | domain | application | infrastructure |
|---|---|---|---|
| `identity` | user, email, status, lockout | register, authenticate, password | argon2id, PostgreSQL |
| `session` | token (SHA-256 id), idle/absolute timeout | start, resolve (sliding), revoke | Redis |
| `access` | role, permission, policy tree, `Decide` | authorize, role/policy admin | PostgreSQL, memory |
| `apikey` | key, scopes, expiry/revoke | issue, resolve, revoke | PostgreSQL, memory |

`kernel/migrations` (goose SQL templates rendered against your user table), `adminui` (html/template admin panel), `ratelimit` (Redis sliding window), `audit`, `ginguard` (interfaces), `guardtest` (in-memory Guard for tests).

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

## Audit buffering (Redis → PostgreSQL)

By default audit events are written to PostgreSQL synchronously (or in-process with `AsyncAudit`). For high write volume, queue them in Redis and batch-insert:

```go
g, err := guard.New(ctx, guard.Config{
    // ...
    AuditBuffer: guard.AuditBuffer{
        Enabled:   true,
        BatchSize: 500,         // default 500
        Interval:  time.Second, // default 1s
    },
})
defer g.Close(ctx) // flushes the queue on shutdown
```

- Events are pushed to `<prefix>{audit}:queue`; one flusher across all instances holds `<prefix>{audit}:lock` (30s TTL, extended per batch; hash tag keeps keys in one Redis Cluster slot) and writes batches via `RecordBatch` (`ON CONFLICT (id) DO NOTHING`, so retries are idempotent).
- A failed PostgreSQL write leaves the batch queued for the next tick; undecodable entries, and single events PostgreSQL rejects while the rest of the batch succeeds, move to `<prefix>{audit}:dead`.
- If Redis is unreachable, `Record` falls back to a direct synchronous write.
- When `Enabled`, `AsyncAudit` is ignored.

Trade-offs vs `AsyncAudit`: queued events survive process restarts and are shared across instances; but `List` (and `GET /guard/audit`) shows only flushed events, so reads lag by up to `Interval`, and a PostgreSQL outage grows the Redis list — size Redis memory and alert on queue length.

## Production checklist

Full list with rationale: [docs/production.md](docs/production.md). Minimum before going live:

- TLS; `InsecureCookie` false (default) in `ginguard` and `adminui`.
- `gin.Engine.SetTrustedProxies` set to your load balancers — otherwise `X-Forwarded-For` bypasses per-IP login limits.
- `adminui.Options.CSRFSecret` from a secret store, identical on all instances.
- Cookie clients send `X-Guard-CSRF: 1` (or a trusted `Origin`) on unsafe requests; set `TrustedOrigins` for cross-origin SPAs.
- One `super_admin` bootstrapped with `EnsureSuperAdmin`; `GUARD_SUPERADMIN_*` removed afterwards.
- Redis HA with auth/TLS; PostgreSQL pool sized per instance count; `sslmode=verify-full`.
- Migrations committed and applied by one release job (Guard holds a PostgreSQL advisory lock during `Migrate`).
- Audit retention job, backups with rehearsed restore, key/secret rotation.
- Logs redact `Authorization`, `X-API-Key`, cookies and credential request bodies.
- Admin panel behind VPN / IP allowlist.

Also: [configuration](docs/configuration.md) · [architecture](docs/architecture.md) · [HTTP API and error codes](docs/api.md) · [admin panel](docs/admin-panel.md) · [security policy](SECURITY.md) · [changelog](CHANGELOG.md).

## Core Components

| Component | Description |
|---|---|
| **Sessions** | Secure, stateful session management. |
| **Authorization** | RBAC and ABAC policy enforcement. |
| **API Keys** | Secure API key generation, rotation, and validation. |
| **Rate Limiting** | Route, user, session, or API key-based throttling. |
| **Audit** | Track authentication and authorization events. |
| **Service Identity** | Secure service-to-service authentication. |
| **Middleware** | Plug-and-play security for Go web frameworks. |

## Why Guard?

Most Go applications combine multiple libraries for sessions, authorization, API keys, rate limiting, and auditing. Guard brings these capabilities together in a single, cohesive platform with a consistent developer experience.

## Roadmap

- [x] Session management
- [x] RBAC & ABAC
- [x] API keys
- [x] Rate limiting
- [x] Audit logging
- [ ] Service-to-service authentication
- [x] Admin dashboard
- [ ] Security analytics
- [x] Policy engine
- [ ] Plugin ecosystem
- [x] Migration advisory lock (multi-replica `Migrate`)
- [ ] Echo / Fiber / Chi / net/http adapters
- [ ] v1.0 API freeze

## License

MIT License. See [LICENSE](LICENSE).
