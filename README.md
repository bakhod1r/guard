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
| 🛡️ Security middleware | 🌐 Service-to-service authentication |
| 📊 Security analytics support | 🔄 Automatic permission sync |
| 🚀 Gin, Echo, Fiber, Chi, net/http | 💾 PostgreSQL, MySQL, Redis |
| 🔌 Extensible plugin architecture | |

## Installation

```bash
go get github.com/bakhod1r/guard
```

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
docker compose -f examples/gin/docker-compose.yml up -d
DATABASE_URL=postgres://postgres:postgres@localhost:5432/guard?sslmode=disable REDIS_ADDR=localhost:6379 \
GUARD_ADMIN_EMAIL=admin@example.com GUARD_ADMIN_PASSWORD=change-me-now GUARD_INSECURE_COOKIE=1 \
go run ./examples/gin
# API:   http://localhost:8080/api/auth/login
# Panel: http://localhost:8080/guard-admin
```

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
- Seeded: roles `admin` (wildcard) / `user`, self-service read policies, `blocked user denied` (priority 10).

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
go test ./...
# integration (PostgreSQL + Redis)
GUARD_TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5432/guard?sslmode=disable \
GUARD_TEST_REDIS_ADDR=localhost:6379 go test -race -cover ./...   # 100% statements
```

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
- [ ] Admin dashboard
- [ ] Security analytics
- [x] Policy engine
- [ ] Plugin ecosystem

## License

MIT License. See [LICENSE](LICENSE).
