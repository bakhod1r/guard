# Configuration file and route autoseed

Source: `config/config.go` (`Load`, `File`), `ginguard/autoseed.go` (`Protect`, `Autoseed`), `access/application/autoseed.go` (`SeedRoutes`), `access/domain/route.go` (`RoutePermission`).

## Quick start

`guard.yaml`:

```yaml
database: { url: ${DATABASE_URL} }
redis: { addr: ${REDIS_ADDR}, password: ${REDIS_PASSWORD}, db: 0, prefix: "guard:" }
user_table: users
user_id_column: id
default_role: user
session: { idle: 30m, absolute: 168h }
lockout: { attempts: 5, window: 15m }
audit: { async_buffer: 0 }
migrations: { dir: ./migrations/guard, auto_apply: true }
http:
  cookie_name: guard_session
  insecure_cookie: false
  auth_path: /auth
  admin_path: /guard
  trusted_origins: []
  max_body_bytes: 1048576
  hsts: false
  auth_rate_limit: { limit: 10, window: 1m }
autoseed: { enabled: true, prefix: /api, super_role: admin, exclude: [/api/auth, /api/guard] }
```

```go
import (
    "github.com/bakhod1r/guard/config"
    "github.com/bakhod1r/guard/ginguard"
)

cfg, err := config.Load("guard.yaml")      // ${ENV} expanded, unknown keys rejected
if err != nil { log.Fatal(err) }
g, err := cfg.Open(ctx)                    // connects PostgreSQL + Redis, migrations if auto_apply
if err != nil { log.Fatal(err) }
defer g.Close(ctx)

opts := cfg.HTTPOptions()
r := gin.New()
api := r.Group("/api")
ginguard.Mount(api, g, opts)               // /api/auth/*, /api/guard/*

app := api.Group("")
app.Use(ginguard.Protect(g, opts, "/api")) // every host route requires its derived permission
app.GET("/reports/:id", getReport)         // reports.read
app.POST("/reports", createReport)         // reports.create

if ao, ok := cfg.AutoseedOptions(); ok {   // after all routes are registered
    if _, err := ginguard.Autoseed(ctx, g, r.Routes(), ao); err != nil { log.Fatal(err) }
}
r.Run(":8080")
```

## Loading rules

- `${NAME}` is replaced by the environment variable before parsing.
- Unknown keys are an error (typos fail at startup, not silently).
- Secrets (`database.url`, `redis.password`) must be given as `${ENV}` references, never literal values in the file.
- Durations use Go syntax (`30m`, `168h`).

## Key reference

| Key | Type | Example / default | Maps to |
|---|---|---|---|
| `database.url` | string, env | `${DATABASE_URL}` | PostgreSQL DSN (pgxpool) |
| `redis.addr` | string, env | `${REDIS_ADDR}` | Redis address |
| `redis.password` | string, env | `${REDIS_PASSWORD}` | Redis AUTH |
| `redis.db` | int | `0` | Redis database |
| `redis.prefix` | string | `"guard:"` | key prefix for sessions, rate limits, audit queue |
| `user_table` | string | `users` | `Config.UserTable` (host table) |
| `user_id_column` | string | `id` | `Config.UserIDColumn` |
| `default_role` | string | `user` | role given on register |
| `session.idle` | duration | `30m` | idle timeout (sliding) |
| `session.absolute` | duration | `168h` | absolute session lifetime |
| `lockout.attempts` | int | `5` | failed logins before lockout |
| `lockout.window` | duration | `15m` | lockout window |
| `audit.async_buffer` | int | `0` | in-process async audit buffer; `0` = synchronous |
| `audit.email_key` | base64 string | `""` | `Config.AuditEmailKey`; must decode to >= 32 bytes. Set: login audit metadata stores `email_hmac` (HMAC-SHA256, 32 hex chars); empty: `email_sha256` (unkeyed, 16 hex chars). Use `"${GUARD_AUDIT_EMAIL_KEY}"`; generate with `openssl rand -base64 32` |
| `audit.redis_buffer.enabled` | bool | `false` | `Config.AuditBuffer` (Redis queue, batch writes) |
| `audit.redis_buffer.batch_size` | int | `500` | events per batch |
| `audit.redis_buffer.interval` | duration | `1s` | flush interval |
| `access_cache.enabled` | bool | `false` | `Config.AccessCache` (role/policy cache) |
| `access_cache.ttl` | duration | `30s` | max staleness for writes bypassing Guard |
| `access_cache.max_entries` | int | `10000` | per in-process map |
| `access_cache.shared` | bool | `false` | also cache in Redis, shared by every instance behind the load balancer |
| `access_cache.shared_ttl` | duration | `2 × ttl` | lifetime of a shared Redis entry |
| `migrations.dir` | path | `./migrations/guard` | where rendered SQL is written |
| `migrations.auto_apply` | bool | `true` | `Open` writes and applies migrations |
| `http.cookie_name` | string | `guard_session` | session cookie name |
| `http.insecure_cookie` | bool | `false` | drop `Secure` flag (local HTTP only) |
| `http.auth_path` | string | `/auth` | `Options.AuthPath` |
| `http.admin_path` | string | `/guard` | `Options.AdminPath` |
| `http.trusted_origins` | list | `[]` | allowed `Origin` for state-changing requests |
| `http.max_body_bytes` | int | `1048576` | request body limit |
| `http.hsts` | bool | `false` | send `Strict-Transport-Security` |
| `http.auth_rate_limit.limit` | int | `10` | login/register requests per window per IP |
| `http.auth_rate_limit.window` | duration | `1m` | rate-limit window |
| `autoseed.enabled` | bool | `true` | `AutoseedOptions()` returns `ok` |
| `autoseed.prefix` | string | `/api` | stripped before deriving the resource |
| `autoseed.super_role` | string | `admin` | role granted every permission; `-` disables |
| `autoseed.exclude` | list | `[/api/auth, /api/guard]` | path prefixes not seeded |

`(*File).HTTPOptions()` returns the `http.*` block as `ginguard.Options`; `(*File).AutoseedOptions()` returns `ginguard.AutoseedOptions` and `false` when `autoseed.enabled` is false.

## Route permissions (`Protect` / `Autoseed`)

Permission code = `resource.action`, derived from the route pattern:

- **resource** — static path segments after the prefix joined with `_`; params (`:id`, `*x`) dropped; lowercased; characters other than `a-z 0-9 _ -` become `_`; max 64 chars.
- **action** — `GET`/`HEAD` → `read`, `POST` → `create`, `PUT`/`PATCH` → `update`, `DELETE` → `delete`, other methods → lowercased method.

| Route | Permission |
|---|---|
| `GET /api/reports/:id` | `reports.read` |
| `POST /api/reports` | `reports.create` |
| `PATCH /api/v1/invoice-items/:id` | `v1_invoice-items.update` |
| `DELETE /api/files/*path` | `files.delete` |

`ginguard.Protect(g, opts, prefix)` authorizes each request against the permission of the matched route (RBAC + ABAC as usual).

`ginguard.Autoseed(ctx, g, router.Routes(), ginguard.AutoseedOptions{Prefix, SuperRole, Exclude})`, called once after routes are registered:

1. Creates every derived permission (idempotent).
2. Super role (default `admin`) gets all of them: a wildcard role already passes; a non-wildcard role receives explicit grants; a missing role is created as wildcard.
3. No other role gets anything — new routes are **denied by default**.
4. Existing grants are never revoked.

Grant access to other roles in the admin panel or with `POST /guard/roles/:name/permissions` (`{"code":"reports.read"}`).

Caveats:

- Renaming a route path changes its permission code; the old permission stays orphaned (and its grants no longer apply). Re-grant, then delete the old one.
- Two routes with the same resource and action (`GET /reports` and `GET /reports/:id`) share one permission.
- Routes whose path yields no static segment are skipped.
