# HTTP API (`ginguard.Mount`)

Source: `ginguard/routes.go` (`Mount`), `ginguard/middleware.go` (`errorMap`, `abort`).
Paths are relative to the group passed to `Mount` (e.g. `/api`). `AuthPath` defaults to `/auth`, `AdminPath` to `/guard`.

## Authentication

| Credential | Accepted by |
|---|---|
| `guard_session` cookie (`HttpOnly; Secure; SameSite=Strict`) | session and "auth" routes |
| `Authorization: Bearer <session token>` | session and "auth" routes |
| `X-API-Key: gk_...` or `Authorization: Bearer gk_...` | "auth" and permission routes only; **session** routes return `403 session_required` |

CSRF: a state-changing request (POST/PUT/PATCH/DELETE) authenticated by the **cookie** must send `X-Guard-CSRF: 1` or an `Origin` (fallback `Referer`) whose host equals the request host, or one of `Options.TrustedOrigins` when set (then the own host is not implicitly trusted). Otherwise `403`. Bearer tokens and API keys are exempt.

Guards: **public** — none; **auth** — session or API key; **session** — session only;
**perm `x.y`** — RBAC/ABAC `Authorize(resource=x, action=y)`; **perm-or-self** — `Require(...)` with the path user as resource, so seeded self-service policies let a user act on their own id.

## Routes

| Method | Path | Guard | Notes |
|---|---|---|---|
| POST | `/auth/register` | public, rate limited | mounted only when `Options.CreateUser != nil` |
| POST | `/auth/login` | public, rate limited | `AuthRateLimit` default 10/min per IP |
| GET | `/auth/me` | auth | |
| POST | `/auth/authorize` | auth | ask for a decision |
| POST | `/auth/logout` | session | |
| POST | `/auth/logout-all` | session | |
| PUT | `/auth/password` | session | |
| GET | `/auth/sessions` | session | |
| DELETE | `/auth/sessions/:id` | session | |
| GET | `/auth/api-keys` | session | |
| POST | `/auth/api-keys` | session | token returned once; API keys cannot mint keys |
| DELETE | `/auth/api-keys/:id` | session | |
| GET | `/guard/users/:id` | `user.read` or self | |
| POST | `/guard/users/:id/account` | `user.write` | create credentials for an existing host user |
| PUT | `/guard/users/:id/password` | `user.write` | admin reset |
| PUT | `/guard/users/:id/status` | `user.write` (policy-evaluated) | |
| PUT | `/guard/users/:id/attributes` | `user.write` (policy-evaluated) | |
| GET | `/guard/users/:id/roles` | `role.read` or self | |
| POST | `/guard/users/:id/roles` | `role.assign` | |
| DELETE | `/guard/users/:id/roles/:role` | `role.assign` | |
| GET | `/guard/users/:id/sessions` | `session.read` or self | |
| DELETE | `/guard/users/:id/sessions` | `session.revoke` or self | |
| GET | `/guard/users/:id/api-keys` | `apikey.read` or self | |
| DELETE | `/guard/users/:id/api-keys` | `apikey.revoke` or self | |
| GET | `/guard/roles` | `role.read` | |
| POST | `/guard/roles` | `role.write` | |
| GET | `/guard/roles/:name` | `role.read` | |
| DELETE | `/guard/roles/:name` | `role.write` | system roles → `409 system_role` |
| POST | `/guard/roles/:name/permissions` | `role.write` | |
| DELETE | `/guard/roles/:name/permissions/:code` | `role.write` | |
| GET | `/guard/permissions` | `permission.read` | |
| POST | `/guard/permissions` | `permission.write` | |
| GET | `/guard/policies` | `policy.read` | |
| POST | `/guard/policies` | `policy.write` | |
| GET | `/guard/policies/:id` | `policy.read` | |
| PUT | `/guard/policies/:id` | `policy.write` | |
| DELETE | `/guard/policies/:id` | `policy.write` | |
| GET | `/guard/audit` | `audit.read` | |

"or self" is provided by seeded ABAC policies, not hard-coded; changing policies changes who passes.

## Host routes (`Protect` / `Autoseed`)

`ginguard.Protect(g, opts, prefix)` on a host group requires the permission derived from the matched route (`GET /api/reports/:id` → `reports.read`; `403` when denied, same error body as below). `ginguard.Autoseed` creates those permissions at startup and grants them only to the super role; grant others via `POST /guard/roles/:name/permissions`. Derivation rules: [configuration.md](configuration.md#route-permissions-protect--autoseed).

`ginguard.SyncRoutes` / `ProtectRoutes` add a route registry, `SyncOptions.Overrides` (`"METHOD /full/path"` → `resource.action`) and grant `admin`/`super_admin` all and `user` the `UserActions` (default `read`); see [README](../README.md#route-auto-discovery).

## Errors

Body: `{"error": {"code": "<code>", "message": "<text>"}}`.

| Status | Code | Cause |
|---|---|---|
| 400 | `invalid_body` | JSON binding failed |
| 400 | `invalid_email` | `identity.ErrInvalidEmail` |
| 400 | `weak_password` | `identity.ErrWeakPassword` |
| 400 | `invalid_status` | `identity.ErrInvalidStatus` |
| 400 | `invalid_user_id` | `identity.ErrInvalidUserID` |
| 400 | `invalid_name` | `access.ErrInvalidName`, `apikey.ErrInvalidName` |
| 400 | `invalid_permission` | `access.ErrInvalidPermission` |
| 400 | `invalid_policy` | `access.ErrInvalidPolicy` |
| 400 | `invalid_scope` | `apikey.ErrInvalidScope`, `apikey.ErrNoScopes` |
| 400 | `invalid_expiry` | `apikey.ErrBadExpiry`; `expires_at` not in the future; `access.ErrSuperAdminExpiry` (super_admin grants cannot expire) |
| 401 | `unauthenticated` | no credential; session not found/expired; user blocked; `apikey.ErrKeyInvalid` |
| 401 | `invalid_credentials` | `identity.ErrInvalidCredentials` |
| 403 | `forbidden` | authorization decision denied; `access.ErrForbidden` (non-super-admin granting/revoking `admin`/`super_admin`) |
| 403 | `session_required` | API key used on a session-only route |
| 403 | `account_blocked` | `identity.ErrUserBlocked` |
| 404 | `user_not_found` | `identity.ErrUserNotFound`, `access.ErrSubjectNotFound`, `apikey.ErrOwnerNotFound` |
| 404 | `session_not_found` | `session.ErrSessionNotFound` |
| 404 | `role_not_found` / `permission_not_found` / `policy_not_found` | access repository misses |
| 404 | `api_key_not_found` | `apikey.ErrKeyNotFound` |
| 409 | `email_taken` | `identity.ErrEmailTaken` |
| 409 | `account_exists` | `identity.ErrAccountExists` |
| 409 | `role_exists` | `access.ErrRoleExists` |
| 409 | `policy_name_taken` | `access.ErrPolicyNameTaken` |
| 409 | `system_role` | `access.ErrSystemRole` |
| 409 | `last_super_admin` | `access.ErrLastSuperAdmin` (last super admin unassigned, banned or suspended) |
| 429 | `account_locked` | `identity.ErrUserLocked` (lockout) |
| 429 | `rate_limited` | rate limiter; sets `Retry-After` and `X-RateLimit-*` |
| 500 | `internal` | anything unmapped; message is always `internal error`, cause attached via `c.Error` |

Note: mapped errors return `err.Error()` as `message`; do not surface wrapped infrastructure errors through mapped sentinels.
