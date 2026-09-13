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

```go
pool, _ := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
rdb := redis.NewClient(&redis.Options{Addr: os.Getenv("REDIS_ADDR")})

g, _ := guard.New(guard.Config{DB: pool, Redis: rdb})

guard.WriteMigrations("./migrations/guard") // copies SQL into your project (never overwrites)
g.Migrate(ctx, "./migrations/guard")         // applies it (goose, table guard_schema_version)
g.EnsureAdmin(ctx, "admin@example.com", os.Getenv("ADMIN_PASSWORD"))

r := gin.Default()
api := r.Group("/api")
ginguard.Mount(api, g, ginguard.Options{})   // /api/auth/* and /api/guard/*

api.GET("/invoices/:id", ginguard.RequirePermission(g, ginguard.Options{}, "invoice.read"), handler)
```

Full runnable example: [examples/gin](examples/gin/main.go).

## HTTP API (ginguard.Mount)

| Route | Guard |
|---|---|
| `POST /auth/register`, `POST /auth/login` | public |
| `POST /auth/logout`, `POST /auth/logout-all`, `GET /auth/me`, `PUT /auth/password` | session |
| `GET /auth/sessions`, `DELETE /auth/sessions/:id`, `POST /auth/authorize` | session |
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

Token: `Authorization: Bearer <token>` or the `guard_session` cookie (HttpOnly, Secure, SameSite=Strict).

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

`kernel/migrations` (embedded goose SQL), `audit`, `ginguard` (interfaces), `guardtest` (in-memory Guard for tests).

## Testing

```bash
go test ./...
# integration (PostgreSQL + Redis)
GUARD_TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5432/guard?sslmode=disable \
GUARD_TEST_REDIS_ADDR=localhost:6379 go test -run Integration .
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
- [ ] API keys
- [ ] Rate limiting
- [x] Audit logging
- [ ] Service-to-service authentication
- [ ] Admin dashboard
- [ ] Security analytics
- [x] Policy engine
- [ ] Plugin ecosystem

## License

MIT License. See [LICENSE](LICENSE).
