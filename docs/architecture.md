# Architecture

Guard is a library, not a service. The host application owns the HTTP server,
the user table and the database; Guard adds tables prefixed `guard_` that
reference the host user table, and stores sessions in Redis.

## Bounded contexts (DDD)

Dependencies point inward: `interfaces → application → domain`; `infrastructure`
implements domain repository interfaces.

| Context | domain | application | infrastructure |
|---|---|---|---|
| `identity` | account, email, status, lockout, password rules | register, authenticate, change/reset password | argon2id hasher, PostgreSQL (`guard_account`) |
| `session` | token (only SHA-256 id stored), idle/absolute timeout | start, resolve (sliding), revoke | Redis |
| `access` | role, permission `resource.action`, policy condition tree, `Decide` | authorize, role/permission/policy admin | PostgreSQL, in-memory |
| `apikey` | key, scopes, expiry, revocation | issue, resolve, revoke | PostgreSQL (`guard_api_key`), in-memory |

Supporting packages:

| Package | Role |
|---|---|
| `guard` (root) | Facade wiring the contexts: `New`, `Login`, `Authenticate`, `Authorize`, `CreateAccount`, `EnsureAdmin`, `Migrate` |
| `kernel/migrations` | Detects host `users.id` type; renders goose SQL templates; `Up`/`Down` (version table `guard_schema_version`) |
| `kernel/pgerr` | PostgreSQL error classification |
| `audit` | Append-only audit events (`guard_audit_event`) |
| `ratelimit` | Redis sliding-window limiter |
| `ginguard` | Gin interface layer: JSON API, middleware, error mapping |
| `adminui` | Server-rendered admin panel (`html/template`, CSRF-protected forms) |
| `guardtest` | In-memory Guard for host application tests |

```mermaid
flowchart LR
  subgraph interfaces
    ginguard
    adminui
  end
  facade[guard facade]
  subgraph contexts
    identity
    session
    access
    apikey
  end
  ginguard --> facade
  adminui --> facade
  facade --> identity & session & access & apikey & audit & ratelimit
  identity & access & apikey & audit --> PG[(PostgreSQL)]
  session & ratelimit --> R[(Redis)]
```

## Request flow

1. Credential extraction (`ginguard`): `X-API-Key`, `Authorization: Bearer <session token | gk_...>`, or `guard_session` cookie.
2. Authentication: session token → Redis lookup by SHA-256 (sliding idle timeout, absolute cap); `gk_` key → `guard_api_key` by hash, rejected if expired/revoked.
3. Principal: account (must not be blocked), role grants (expired grants ignored), attributes. API keys act as their owner narrowed by scopes (`invoice.read`, `invoice.*`, `*`).
4. Authorization: `access/domain.Decide` (below). Result is audited where relevant.

## Decision algorithm

Source: `access/domain/access.go` `Decide`.

1. Load enabled policies whose `(resource, action)` matches the request (exact or `*`).
2. Keep policies whose condition tree holds (`and`/`or`, `negate`; operators `eq ne gt lt gte lte in not_in contains`; fields `user.*`, `resource.*`, `env.*`; values starting `$` dereference attributes, e.g. `$user.id`).
3. If any matched: sort by `priority` ascending (lower = stronger). Among policies with the **top** priority only, any `deny` → **deny**; otherwise **allow**. Weaker tiers are ignored.
4. If none matched: RBAC — allow if any role is `wildcard` or grants `resource.action`.
5. Otherwise **deny** (fail-closed).

```mermaid
flowchart TD
  A[request: subject, resource, action, env] --> B{matching enabled policies?}
  B -- yes --> C[sort by priority ASC; take top tier]
  C --> D{any deny in top tier?}
  D -- yes --> X[DENY]
  D -- no --> Y[ALLOW]
  B -- no --> E{role wildcard or grants resource.action?}
  E -- yes --> Y
  E -- no --> X
```

Seeded data: roles `admin` (wildcard, system) and `user`; self-service read policies; `blocked user denied` (priority 10).

## Data model

`{{UserIDType}}` is detected from the host table (bigint, uuid, text, …). Guard never creates or alters the host user table.

```mermaid
erDiagram
  users ||--o| guard_account : "has credentials"
  users ||--o{ guard_user_role : "granted"
  users ||--o{ guard_api_key : owns
  guard_role ||--o{ guard_user_role : ""
  guard_role ||--o{ guard_role_permission : ""
  guard_permission ||--o{ guard_role_permission : ""
  guard_policy ||--o{ guard_policy_condition_group : ""
  guard_policy_condition_group ||--o{ guard_policy_condition_group : "parent"
  guard_policy_condition_group ||--o{ guard_policy_condition : ""

  users { UserIDType id PK "host-owned" }
  guard_account { UserIDType user_id PK,FK
    varchar email
    varchar secret "argon2id"
    varchar status "pending|active|banned|suspended"
    jsonb attributes
    int failed_attempts }
  guard_role { uuid id PK
    varchar name UK
    bool is_system
    bool wildcard }
  guard_permission { uuid id PK
    varchar resource
    varchar action
    varchar code UK "resource.action" }
  guard_user_role { UserIDType user_id PK,FK
    uuid role_id PK,FK
    timestamptz expires_at }
  guard_role_permission { uuid role_id PK,FK
    uuid permission_id PK,FK }
  guard_policy { uuid id PK
    varchar resource
    varchar action
    varchar effect "allow|deny"
    int priority
    bool enabled }
  guard_policy_condition_group { uuid id PK
    uuid policy_id FK
    uuid parent_group_id FK
    varchar logical_operator "and|or"
    bool negate }
  guard_policy_condition { uuid id PK
    uuid group_id FK
    varchar field
    varchar operator
    varchar_array value }
  guard_api_key { uuid id PK
    UserIDType user_id FK
    char hash "sha256"
    varchar_array scopes
    timestamptz expires_at
    timestamptz revoked_at }
  guard_audit_event { uuid id PK
    timestamptz occurred_at
    UserIDType actor_id "no FK"
    varchar action
    bool success
    jsonb metadata }
```

Sessions (Redis, prefix `Config.RedisPrefix`, default `guard:`) are not in PostgreSQL.
