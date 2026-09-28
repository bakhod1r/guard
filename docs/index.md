# Guard

**Enterprise-grade authorization and API security platform for Go.**

Guard is a Go-native security toolkit that covers authentication, authorization and
API protection for applications and microservices: session management, RBAC, ABAC,
API key authentication, rate limiting, audit logging and security middleware behind
one consistent API.

```bash
go get github.com/bakhod1r/guard
```

Requirements: Go 1.26+, PostgreSQL 13+ (CI tests 13 and 17), Redis 6.2+ (CI tests 7).

[Quick start](quick-start.md){ .md-button .md-button--primary }
[Frameworks](frameworks.md){ .md-button }
[Production checklist](production.md){ .md-button }

## Features

| | |
|---|---|
| 🔐 Session management | 👥 Role-Based Access Control (RBAC) |
| 🏷️ Attribute-Based Access Control (ABAC) | 🔑 API key authentication |
| ⚡ Configurable rate limiting | 📋 Audit logs |
| 🛡️ Security middleware (CSRF, headers, body limit) | 🔄 Automatic permission sync from routes |
| 🖥️ Server-rendered admin panel | 👑 Protected super admin role |
| 🚀 net/http, Gin, Echo, Fiber, Chi, Iris, Hertz, Beego, gorilla/mux, httprouter | 💾 PostgreSQL, Redis |

Planned (not yet available): MySQL, service-to-service authentication, security
analytics, plugin architecture.

## Where to go next

| Page | What it covers |
|---|---|
| [Quick start](quick-start.md) | Wiring Guard into an existing app, migrations, first admin |
| [Configuration](configuration.md) | YAML file, key reference, route autoseed |
| [Frameworks](frameworks.md) | `net/http`, chi, gorilla/mux, httprouter, Echo, Fiber, Iris, Hertz, Beego |
| [HTTP API](api.md) | Routes, credentials, error codes |
| [Admin panel](admin-panel.md) | Mounting, security model, pages and permissions |
| [Architecture](architecture.md) | Bounded contexts, request flow, decision algorithm, data model |
| [Production checklist](production.md) | Everything to verify before going live |

## Authorization model

- **RBAC** — `role → permission (resource.action)`; `wildcard` roles pass everything; user roles may expire.
- **ABAC** — policies target `(resource, action)` (or `*`) with a condition tree (`and`/`or`, `negate`).
  Fields: `user.*`, `resource.*`, `env.*`; values starting with `$` reference attributes (`$user.id`).
- **Decision** — matching policies sorted by `priority` ASC; the strongest tier decides, DENY wins inside a tier;
  no policy matched → RBAC; otherwise deny (fail-closed).
- Seeded: roles `super_admin` / `admin` (wildcard) / `user`, self-service read policies, `blocked user denied` (priority 10).

Full algorithm: [Architecture](architecture.md#decision-algorithm).

## Status

Guard is pre-1.0 (alpha). The API may change between minor releases; see the
[changelog](changelog.md) and the [security policy](security.md).

MIT licensed.
