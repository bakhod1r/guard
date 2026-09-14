# Admin panel (`adminui`)

Server-rendered HTML (`html/template`, no JavaScript build) for managing Guard.
Source: `adminui/adminui.go`, `dashboard.go`, `users.go`, `rbac.go`, `policies.go`, `security.go`.

## Mounting

```go
adminui.Mount(r, g, adminui.Options{
    Path:       "/guard-admin",            // default
    CookieName: "guard_session",           // must equal ginguard.Options.CookieName
    CSRFSecret: secretFromVault,           // >= 32 bytes, identical on every instance
    // InsecureCookie: true               // localhost HTTP only
})
```

The panel uses the same session cookie as `ginguard`; logging in at `/guard-admin/login` creates a normal Guard session. API keys are never accepted by the panel.

## Security model

- All pages except `GET/POST /login` require a session (`requireSession`); every authenticated POST checks a CSRF token (`_csrf`, HMAC-SHA256 of the session id keyed by `CSRFSecret`) → 403 on mismatch.
- Responses carry no-store caching headers (`noStore`).
- Each page/action is gated by the same permissions as the JSON API; navigation hides items the user cannot access.
- If `CSRFSecret` is unset a random per-process secret is used: fine for one instance, broken behind a load balancer (see `docs/production.md` §3).
- Expose only on an internal network / VPN / IP allowlist (`docs/production.md` §12).

## Pages and permissions

| Route (under `Path`) | Permission |
|---|---|
| `GET /login`, `POST /login` | public |
| `POST /logout` | session |
| `GET ""` (dashboard) | session; widgets by permission |
| `GET /users` | `user.read` |
| `GET /users/:id` | session (content by permission) |
| `POST /users/new`, `/users/:id/status`, `/users/:id/attributes`, `/users/:id/password` | `user.write` |
| `POST /users/:id/roles`, `/users/:id/roles/:role/remove` | `role.assign` |
| `POST /users/:id/sessions/revoke-all` | `session.revoke` |
| `POST /users/:id/api-keys/revoke-all` | `apikey.revoke` |
| `GET /roles`, `GET /roles/:name` | `role.read` |
| `POST /roles`, `/roles/:name/delete`, `/roles/:name/permissions`, `/roles/:name/permissions/revoke` | `role.write` |
| `GET /permissions` / `POST /permissions` | `permission.read` / `permission.write` |
| `GET /policies`, `/policies/new`, `/policies/:id`, `POST /policies/simulate` | `policy.read` |
| `POST /policies`, `/policies/:id`, `/policies/:id/delete`, `/policies/:id/toggle` | `policy.write` |
| `GET /security`; `POST /security/sessions/revoke-others`, `/security/sessions/:id/revoke`, `/security/api-keys`, `/security/api-keys/:id/revoke`, `/security/password` | session (own account) |
| `GET /audit` | `audit.read` |

## First admin

`g.EnsureAdmin(ctx, userID, email, password)` links credentials to an existing host user and grants `admin`. In `examples/gin` this runs from `GUARD_ADMIN_EMAIL` / `GUARD_ADMIN_PASSWORD`; rotate the password after first login and remove the variables.

## Super admin

Prefer `g.EnsureSuperAdmin(ctx, userID, email, password)` (`GUARD_SUPERADMIN_EMAIL` / `GUARD_SUPERADMIN_PASSWORD` in `examples/gin`). Only super admins can grant or revoke `admin` and `super_admin`; the panel shows a super admin badge and refuses to remove, ban or suspend the last one. The **Routes** page (`GET /routes`, `permission.read`) lists the discovered route registry, stale routes included.
