# Production checklist

Guard is pre-1.0. Treat each item as a release gate: verify it in the target
environment and record the evidence (config file, dashboard, runbook link).

## 1. Transport and cookies
- [ ] **TLS everywhere.** Terminate TLS at the edge or in-process; redirect HTTP→HTTPS; send `Strict-Transport-Security`.
- [ ] **Secure cookies.** `ginguard.Options.InsecureCookie` and `adminui.Options.InsecureCookie` MUST be `false` (default). The session cookie is `HttpOnly; Secure; SameSite=Strict`. `GUARD_INSECURE_COOKIE=1` in `examples/gin` is for localhost only.
- [ ] `CookieName` identical in `ginguard.Options` and `adminui.Options`; set `CookieDomain` only if sub-domains must share the session.

## 2. Client IP and proxies
- [ ] **Configure Gin trusted proxies.** Guard uses `c.ClientIP()` for the login/register rate limit (`ginguard.ByIP`), sessions and audit. Gin trusts **all** proxies by default, so `X-Forwarded-For` is client-controlled and the per-IP login limit can be bypassed.
  ```go
  r := gin.New()
  _ = r.SetTrustedProxies([]string{"10.0.0.0/8"}) // your LB CIDRs only; nil = trust none
  r.TrustedPlatform = gin.PlatformCloudflare       // or GCP App Engine, if applicable
  ```
  `examples/gin` reads `GUARD_TRUSTED_PROXIES` (comma-separated; unset = trust none).
- [ ] Set `ginguard.Options.TrustedOrigins` (YAML `http.trusted_origins`) when the SPA runs on another origin; list the API's own origin too, since a non-empty list replaces the same-host check.

## 3. CSRF secret (admin panel)
- [ ] Set `adminui.Options.CSRFSecret` (≥ 32 random bytes) from a secret store and **share it across all instances**. The default is random per process: behind a load balancer, a form rendered by instance A is rejected (403) by instance B, and every restart invalidates open forms.
- [ ] Rotate by deploying the new secret to all instances at once; open admin forms fail once with 403 and must be reloaded.

## 4. Redis
- [ ] Sessions and rate limits live in Redis. Loss of Redis = all users logged out; rate limiting **fails open** on Redis errors (by design) — alert on Redis errors.
- [ ] Use HA: Sentinel (`redis.NewFailoverClient`) or Cluster (`redis.NewClusterClient`); `Config.Redis` accepts `redis.UniversalClient`.
- [ ] Enable `requirepass`/ACL and TLS; set a unique `Config.RedisPrefix` per environment when sharing a Redis.
- [ ] `maxmemory-policy noeviction` (or `volatile-*`) so live sessions are not evicted under memory pressure.

## 5. PostgreSQL
- [ ] **Pool sizing.** Size `pgxpool` `max_conns` so `instances × max_conns` stays below `max_connections` minus admin/migration headroom (or front with PgBouncer in transaction mode). Start at `max_conns = 2 × vCPU` per instance and adjust from `pool.Stat()` wait counts.
- [ ] Set `pool_max_conn_lifetime` and `statement_timeout` in the DSN (`?pool_max_conns=10&pool_max_conn_lifetime=30m`).
- [ ] Minimum supported server: PostgreSQL 13 (CI matrix 13 and 17).
- [ ] `sslmode=verify-full` in production DSNs.

## 6. Migrations
- [ ] Render once with `g.WriteMigrations(ctx, dir)` and **commit** the SQL; review it like any schema change.
- [ ] Run migrations as a **single dedicated step** (init container / release job) before rolling out new instances, not from every replica at start-up.
- [ ] **Advisory lock.** `kernel/migrations.Up` runs goose with a PostgreSQL session locker (`lock.NewPostgresSessionLocker(lock.WithLockID(migrations.LockID))`, `kernel/migrations/migrations.go`), so concurrent `Migrate` calls from several replicas serialize instead of racing. The key differs from goose's default, so host goose migrations never wait on Guard. Still prefer one release job: a replica blocked on the lock delays its readiness. Migrations therefore need a session-capable connection (not PgBouncer transaction mode).
- [ ] Expand/contract: new code must work against both the previous and new schema during rollout. `migrations.Down` is for development; production rollback = forward fix or tested restore.

- [ ] **`migrations.auto_apply` (config file).** Convenient for one instance; with several replicas every `Open` writes and applies migrations (serialized by the advisory lock, but each replica needs write access to `migrations.dir` and DDL rights). Prefer `auto_apply: false` in app replicas and `true` only in the release job.

## 7. Audit
- [ ] Define retention (e.g. 400 days for SOC 2 / ISO evidence). Guard does not prune `guard_audit_event`; schedule a job:
  `DELETE FROM guard_audit_event WHERE occurred_at < now() - interval '400 days';` (batch it, or partition by month).
- [ ] Ship audit rows to your SIEM if tamper resistance is required; the application DB role can modify the table.
- [ ] Set `audit.email_key` / `Config.AuditEmailKey` (`GUARD_AUDIT_EMAIL_KEY=$(openssl rand -base64 32)`, stored as a secret). Login audit events never store raw emails; without a key they store an unkeyed `email_sha256` fingerprint that can be reversed by hashing a list of candidate addresses. Rotating the key breaks correlation with older `email_hmac` values.
- [ ] Alert on bursts of `success = false` login events.

## 8. Keys and secrets rotation
- [ ] API keys: only SHA-256 hashes are stored; rotate by issuing a new key, deploying it, then revoking the old one (`DELETE /auth/api-keys/:id`). Always set an expiry.
- [ ] Revoke all sessions for a user after password reset or compromise (`DELETE /guard/users/:id/sessions`).
- [ ] Rotate DB/Redis credentials and `CSRFSecret` on a schedule and on staff departure; keep them in a secret manager, never in images or compose files.
- [ ] Bootstrap admin (`GUARD_ADMIN_PASSWORD`) must be changed after first login and removed from the environment.

- [ ] **Config file.** Keep `guard.yaml` free of secrets: `database.url` and `redis.password` come from `${ENV}` (secret store / orchestrator), literal values are rejected. File readable only by the app user (`chmod 0640`), mounted read-only; unknown keys fail startup, so validate it in CI.
- [ ] **Autoseed.** New routes are denied to everyone except the super role until granted; review orphaned permissions after renaming routes.

## 9. Backups
- [ ] PostgreSQL: PITR (WAL archiving) + daily base backup; **rehearse a restore** and record RTO/RPO.
- [ ] Redis: sessions are disposable (users re-login); RDB/AOF optional. Document that a Redis restore is not required for recovery.

## 10. Rate limits
- [ ] Keep `ginguard.Options.AuthRateLimit` enabled (default 10/min per IP); never set `Limit < 0` in production.
- [ ] Add `ginguard.RateLimit(..., ginguard.ByPrincipal)` on expensive or enumeration-prone routes.
- [ ] Account lockout (`Config.Lockout`, default 5 attempts / 15 min) complements per-IP limits against distributed guessing.

## 11. Logging redaction
- [ ] Never log request bodies of `/auth/login`, `/auth/register`, `/auth/password`, `/guard/users/:id/password`, `/auth/api-keys` (response contains the one-time token).
- [ ] Redact `Authorization`, `X-API-Key`, `Cookie` and `Set-Cookie` headers in access logs and APM/tracing.
- [ ] `gin.Default()` logs paths only; if you add a body logger, filter the routes above. Run Gin with `GIN_MODE=release`.

## 12. Admin panel exposure
- [ ] Do not expose `/guard-admin` to the public internet. Restrict by VPN, private ingress, or IP allowlist at the LB, and/or mount it on a separate internal listener:
  ```go
  internal := gin.New()
  adminui.Mount(internal, g, adminui.Options{CSRFSecret: secret})
  go internal.Run("127.0.0.1:9090")
  ```
- [ ] Only `admin`-role (wildcard) staff; review `guard_user_role` grants quarterly; prefer expiring role grants.

## 13. Build and supply chain
- [ ] Build with a patched Go toolchain (govulncheck in CI must pass); set `toolchain` in `go.mod`.
- [ ] Container: `examples/gin/Dockerfile` pattern — `CGO_ENABLED=0`, `-trimpath`, distroless `nonroot`, read-only root FS where the migrations dir is not written at runtime.

## 14. Super admin and access cache
- [ ] Bootstrap one `super_admin` with `EnsureSuperAdmin`, then remove `GUARD_SUPERADMIN_*` from the environment and rotate the password. Keep at least two super admins so one lost account is recoverable.
- [ ] Ban/suspend of super admins and super_admin removal are serialised cluster-wide by a PostgreSQL advisory lock (`Access.LockSuperAdmins`, waits at most 10s, then fails). Each waiter holds one pool connection per process; keep `pgxpool` `MaxConns` >= 3. A custom role repository must implement `access/domain.SuperAdminLocker` for cross-replica safety. Deleting host user rows bypasses the rule entirely.
- [ ] With `AccessCache` enabled, call `InvalidateAccess` from host code that deletes or bans users outside Guard (otherwise grants may be stale for up to the TTL, default 30s).
