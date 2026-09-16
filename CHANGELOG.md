# Changelog

All notable changes are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning: [SemVer](https://semver.org/) (pre-1.0: minor versions may break APIs).

## [Unreleased]

### Added
- Shared access cache (L2): `AccessCacheOptions.L2` / `L2TTL` (YAML `access_cache.shared` / `shared_ttl`, default TTL twice the in-process TTL) also stores role grants and policies in Redis, shared by every instance behind a load balancer, so an in-process miss is served from Redis instead of PostgreSQL. Entries are namespaced by the existing version key, so one write invalidates both levels; a failed invalidation stops this instance trusting L2 for one `L2TTL`. Off unless enabled, and ignored without a Redis client. `CacheStats` gains `L2Hits`, `L2Misses`, `SerializeFailures`, `L2Distrusted`.

### Security
- **Privilege model (breaking):** "privileged" is no longer just the names `admin`/`super_admin`. Any wildcard role and any role holding `role.write`, `role.assign` or `policy.write` is privileged (`domain.Role.Privileged`), as is any policy on resource `*`, `role` or `policy` (`domain.Policy.Privileged`). Only a super admin may create a wildcard role, grant/revoke a management permission, assign/unassign/delete a privileged role, write/replace/delete a privileged policy, or change the account of a privileged role holder. Previously an admin could create a wildcard role or an allow-all policy and bypass the super admin boundary. New `Access.CreateRoleAs`, `DeleteRoleAs`, `RevokePermissionAs`, `SavePolicyAs`, `DeletePolicyAs`; `GrantPermission` checks a non-empty `grantedBy`. The JSON API and admin panel use them. Non-`As` methods stay trusted system calls.
- **Login lost update:** a login in flight could write back the account row it read, undoing a concurrent ban or password reset, and parallel guesses shared one lockout counter. New optional `identity/domain.AccountWriter` (implemented by PostgreSQL and memory stores) makes every account write column-level and atomic; attempts are reserved before the password check. `Guard.Login` re-reads the account after starting the session and revokes it if the hash or status changed.
- `Guard.ResetPassword` also revokes every API key of the user.
- `POST /login` (JSON API and admin panel) answers locked, banned and suspended accounts with `401 invalid_credentials`; the audit event keeps the cause. Previously distinct responses enumerated accounts and confirmed passwords of banned users.
- argon2id computations are bounded process-wide (`max(2, GOMAXPROCS)`) so parallel logins cannot exhaust memory; the unknown-email dummy hash now uses the configured hasher so timing matches custom parameters.
- `Guard.SetAttributes` refuses a user changing their own ABAC attributes unless super admin.
- Admin panel user page shows sessions and API keys only with `session.read` / `apikey.read`.
- `TrustedOrigins` entries with a scheme (`https://app.example.com`) now also require that scheme.

## [v0.1.2] - 2026-09-15

### Documentation
- v0.1.1 was withdrawn: its tag pointed at a commit without this change.
- README feature list now matches what ships: Gin only, PostgreSQL + Redis only. Echo/Fiber/Chi/net/http adapters, MySQL, service-to-service auth, security analytics and plugins are listed as planned.

## [v0.1.0] - 2026-09-14

### Security
- Privilege escalation fix: `ResetPassword`, `SetUserStatus` and the new `Guard.SetAttributes` on a user holding `admin` or `super_admin` now require a super admin actor (`ErrForbidden`, audited as `superadmin.denied`); users may still change their own account. Previously any `user.write` holder could reset a super admin's password and log in as them. Admin panel and `ginguard` attribute routes use `Guard.SetAttributes`.

### Added
- Identity (argon2id, lockout), Redis sessions (idle/absolute timeouts), RBAC and ABAC with priority-tiered policy decisions, audit log, goose migrations and Gin JSON API (`2e3734c`).
- Scoped API keys (`gk_` tokens, SHA-256 at rest, expiry/revocation) and Redis sliding-window rate limiting with `X-RateLimit-*` headers (`735f97f`).
- Server-rendered admin panel for users, RBAC, ABAC policies, sessions and API keys (`524129f`).
- Example app mounting the admin panel, docker-compose stack and host-user quick start (`dbed4a8`).
- CI workflow (gofmt, vet, golangci-lint v2, govulncheck, race tests on PostgreSQL 13 and 17, per-package 100% coverage gate `scripts/coverage-gate.sh`, example builds), `.golangci.yml`, `Makefile`, example `Dockerfile` (distroless nonroot), `docs/` (production checklist, architecture, API, admin panel), `SECURITY.md`.
- Redis-buffered audit log: `Config.AuditBuffer` (`BatchSize` default 500, `Interval` default 1s) queues events in Redis and batch-writes them to PostgreSQL via `audit.NewRedisBuffer` and `(*audit.Postgres).RecordBatch` (idempotent by event ID); single flusher via Redis lock, dead-letter list, direct-write fallback when Redis is down, flush on `Guard.Close`. Overrides `AsyncAudit`.
- YAML configuration package `config`: `config.Load`, `(*File).Open` (connects PostgreSQL + Redis, writes/applies migrations when `migrations.auto_apply`), `HTTPOptions`, `AutoseedOptions`; `${ENV}` expansion, unknown keys rejected, secrets required from env. Reference: `docs/configuration.md`.
- Route-derived permissions: `ginguard.Protect` requires `resource.action` from the matched route (`GET /api/reports/:id` → `reports.read`); `ginguard.Autoseed` / `access.Service.SeedRoutes` create them idempotently at startup, grant all to the super role (default `admin`, `-` disables) and nothing to other roles (deny by default); existing grants are never revoked.
- Super admin: system role `super_admin` (wildcard, migration `00005_guard_super_admin`); `Guard.EnsureSuperAdmin` (idempotent bootstrap, `GUARD_SUPERADMIN_EMAIL`/`GUARD_SUPERADMIN_PASSWORD` in `examples/gin`), `Guard.SuperAdmins`, `Guard.IsSuperAdmin`, audited `Guard.AssignRole` / `Guard.UnassignRole`, `Access.UnassignRoleAs`. Only a super admin may grant or revoke `admin`/`super_admin`; the last super admin cannot lose the role or be banned/suspended. ABAC deny still applies. Errors `ErrForbidden` (403 `forbidden`), `ErrLastSuperAdmin` (409 `last_super_admin`), `ErrSuperAdminExpiry` (400 `invalid_expiry`). Admin panel shows a super admin badge.
- Route auto-discovery: registry table `guard_route` (migration `00006_guard_route`), `Guard.SyncRoutes` / `Guard.ListRoutes`, `ginguard.SyncRoutes(ctx, g, engine.Routes(), SyncOptions{Prefix, SkipPrefixes, FullRoles, UserRole, UserActions, Overrides})` and `ginguard.ProtectRoutes`: `admin` and `super_admin` get every route permission, `user` gets `UserActions` (default `read`) for newly discovered routes, removed routes are marked stale (never revoked), `routes.sync` audit event. Read-only admin panel page `/routes` (`permission.read`).
- Access cache: `Config.AccessCache` (`*AccessCacheOptions`, nil = off; YAML `access_cache.enabled/ttl/max_entries`) caches role grants and policies in-process with Redis-versioned cluster-wide invalidation (default TTL 30s, 10 000 entries); `Guard.AccessStats`, `Guard.InvalidateAccess` (call after host user deletion).
- `Guard.RotateSession` (call after login or privilege change); `Config.PasswordHashParams` (argon2id, below-OWASP values rejected); legacy bcrypt hashes verified and upgraded on login.
- Password policy rejects ~1000 common leaked passwords and passwords equal to the email (`identity.ErrCommonPassword`, `ErrPasswordMatchesEmail`, both match `ErrWeakPassword`).
- HTTP hardening: cookie-authenticated unsafe requests to `ginguard` need `X-Guard-CSRF: 1` or an `Origin`/`Referer` matching the request host or `Options.TrustedOrigins` (Bearer and API key clients are exempt); admin panel sends a per-request nonce CSP, `no-store`, `X-Frame-Options: DENY`, body size limit.
- `examples/gin`: `GUARD_TRUSTED_PROXIES` (comma-separated, default: trust none) and route sync via `ginguard.SyncRoutes`.

### Changed
- **Breaking (audit data):** `auth.login` audit metadata no longer stores the raw `email`. Failed and successful logins record `email_hmac` (hex HMAC-SHA256, first 16 bytes) when `Config.AuditEmailKey` (>= 32 bytes, else `New` fails; YAML `audit.email_key`, base64, `GUARD_AUDIT_EMAIL_KEY` in `examples/gin`) is set, otherwise `email_sha256` (same 16-hex fingerprint as logs). Queries or SIEM rules on `metadata->>'email'` must switch to the fingerprint; existing rows are not rewritten.
- **Breaking:** Guard references the host application's existing user table (`Config.UserTable`, `Config.UserIDColumn`, id type auto-detected) instead of owning a users table (`850220f`).
- Guard migrations run under a PostgreSQL advisory lock (`migrations.LockID`), making concurrent `Migrate` from multiple replicas safe.
- Example compose now uses host ports 18432/18379/18080 and includes the app service with health checks.
- **Breaking:** `Access.AssignRole` with a non-empty `grantedBy` now requires an active `super_admin` actor for roles `admin` and `super_admin`. Existing admins are not promoted: run `Guard.EnsureSuperAdmin` (or set `GUARD_SUPERADMIN_EMAIL`/`GUARD_SUPERADMIN_PASSWORD` in the example) once after upgrading, otherwise nobody can grant `admin`.
- `SessionPolicy`: each zero field now gets its own default (previously setting only `MaxPerUser` left zero timeouts and sessions expired immediately).
- Toolchain pinned to `go1.26.6` and `quic-go` bumped to `v0.59.1` (govulncheck clean); golangci-lint v2.13.2 config: British spellings allowed, staticcheck `QF1008`/`QF1011` disabled.
- Route auto-discovery: `ginguard.SyncRoutes` / `ginguard.ProtectRoutes` skip routes whose final handler belongs to `ginguard` or `adminui` without needing `SkipPrefixes`; opt out with `SyncOptions.IncludeGuardRoutes`.
- Last-super-admin rule is now race-free: `Guard.SetUserStatus` (ban/suspend) and super_admin removal (`Guard.UnassignRole`, `Access.UnassignRoleAs`, `Access.UnassignRole`) run their check and write under one lock (`Access.LockSuperAdmins`: PostgreSQL `pg_advisory_xact_lock` on a constant key with `lock_timeout` 10s plus a per-process lock; memory store mutex), so concurrent "ban each other" or "ban A + remove B" across replicas always leave an active super admin. Role removal now counts only active holders (banned, suspended or account-less super admins no longer rescue the last one), and the revoking actor is re-authorized under the lock. New `domain.SuperAdminLocker`, `domain.BlockedFunc`, `Access.SetSuperAdminBlocked` (wired by `guard.Build`). Custom role repositories without `SuperAdminLocker` get only in-process exclusion.

### Tests
- 100% statement coverage across all packages (`65cd94f`).
