package httpguard

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/bakhod1r/guard"
	accessdomain "github.com/bakhod1r/guard/access/domain"
	identitydomain "github.com/bakhod1r/guard/identity/domain"
	sessiondomain "github.com/bakhod1r/guard/session/domain"
)

// Router is the subset of *http.ServeMux that Mount needs. Any router able to
// register an http.Handler under a method+path pattern can implement it.
type Router interface {
	Handle(pattern string, handler http.Handler)
}

// Mount registers every Guard route on r, using net/http route patterns
// ("POST /auth/login", "{id}" wildcards).
//
//	Self-service (AuthPath, default /auth):
//	  POST   /register  POST /login       (rate limited; /register only with Options.CreateUser)
//	  GET    /me        POST /authorize   (session or API key)
//	  POST   /logout    POST /logout-all  PUT /password           (session only)
//	  GET    /sessions  DELETE /sessions/{id}
//	  GET    /api-keys  POST /api-keys    DELETE /api-keys/{id}
//	Management (AdminPath, default /guard), each guarded by a permission:
//	  GET    /users/{id}                       user.read (or self)
//	  POST   /users/{id}/account               user.write  (link existing host user)
//	  PUT    /users/{id}/password              user.write  (reset, signs out everywhere)
//	  PUT    /users/{id}/status                user.write
//	  PUT    /users/{id}/attributes            user.write
//	  GET    /users/{id}/roles                 role.read
//	  POST   /users/{id}/roles                 role.assign
//	  DELETE /users/{id}/roles/{role}          role.assign
//	  GET    /users/{id}/sessions              session.read
//	  DELETE /users/{id}/sessions              session.revoke
//	  GET    /users/{id}/api-keys              apikey.read
//	  DELETE /users/{id}/api-keys              apikey.revoke
//	  GET    /roles  POST /roles               role.read / role.write
//	  GET    /roles/{name}  DELETE /roles/{name}
//	  POST   /roles/{name}/permissions         role.write
//	  DELETE /roles/{name}/permissions/{code}  role.write
//	  GET    /permissions  POST /permissions   permission.read / permission.write
//	  GET    /policies  POST /policies         policy.read / policy.write
//	  GET|PUT|DELETE /policies/{id}
//	  GET    /audit                            audit.read
func Mount(r Router, g *guard.Guard, opts Options) {
	o := opts.withDefaults()
	h := &handlers{g: g, o: o}
	common := []Middleware{ErrorLogging(o.ErrorLogger), SecurityHeaders(o), LimitBody(o.MaxBodyBytes)}

	var limited []Middleware
	if o.AuthRateLimit.Limit > 0 {
		limited = []Middleware{RateLimit(g, o, "auth", o.AuthRateLimit, ByIP)}
	}
	auth := func(pattern string, fn http.HandlerFunc, mw ...Middleware) {
		r.Handle(route(pattern, o.AuthPath), chain(fn, append(append([]Middleware{}, common...), mw...)...))
	}
	admin := func(pattern string, fn http.HandlerFunc, mw ...Middleware) {
		r.Handle(route(pattern, o.AdminPath), chain(fn, append(append([]Middleware{}, common...), mw...)...))
	}
	perm := func(code string) Middleware { return RequirePermission(g, o, code) }
	requireAuth := RequireAuth(g, o)
	requireSession := RequireSession(g, o)

	if o.CreateUser != nil {
		auth("POST /register", h.register, limited...)
	}
	auth("POST /login", h.login, limited...)
	auth("GET /me", h.me, requireAuth)
	auth("POST /authorize", h.authorize, requireAuth)
	auth("POST /logout", h.logout, requireSession)
	auth("POST /logout-all", h.logoutAll, requireSession)
	auth("PUT /password", h.changePassword, requireSession)
	auth("GET /sessions", h.mySessions, requireSession)
	auth("DELETE /sessions/{id}", h.revokeMySession, requireSession)
	auth("GET /api-keys", h.myAPIKeys, requireSession)
	auth("POST /api-keys", h.issueAPIKey, requireSession)
	auth("DELETE /api-keys/{id}", h.revokeMyAPIKey, requireSession)

	admin("GET /users/{id}", h.getUser, Require(g, o, "user", "read", ParamResource("id")))
	admin("POST /users/{id}/account", h.createAccount, perm("user.write"))
	admin("PUT /users/{id}/password", h.resetPassword, perm("user.write"))
	admin("PUT /users/{id}/status", h.setStatus, Require(g, o, "user", "write", ParamResource("id")))
	admin("PUT /users/{id}/attributes", h.setAttributes, Require(g, o, "user", "write", ParamResource("id")))
	admin("GET /users/{id}/roles", h.userRoles, Require(g, o, "role", "read", userOwned))
	admin("POST /users/{id}/roles", h.assignRole, perm("role.assign"))
	admin("DELETE /users/{id}/roles/{role}", h.unassignRole, perm("role.assign"))
	admin("GET /users/{id}/sessions", h.userSessions, Require(g, o, "session", "read", userOwned))
	admin("DELETE /users/{id}/sessions", h.revokeUserSessions, Require(g, o, "session", "revoke", userOwned))
	admin("GET /users/{id}/api-keys", h.userAPIKeys, Require(g, o, "apikey", "read", userOwned))
	admin("DELETE /users/{id}/api-keys", h.revokeUserAPIKeys, Require(g, o, "apikey", "revoke", userOwned))

	admin("GET /roles", h.listRoles, perm("role.read"))
	admin("POST /roles", h.createRole, perm("role.write"))
	admin("GET /roles/{name}", h.getRole, perm("role.read"))
	admin("DELETE /roles/{name}", h.deleteRole, perm("role.write"))
	admin("POST /roles/{name}/permissions", h.grantPermission, perm("role.write"))
	admin("DELETE /roles/{name}/permissions/{code}", h.revokePermission, perm("role.write"))

	admin("GET /permissions", h.listPermissions, perm("permission.read"))
	admin("POST /permissions", h.createPermission, perm("permission.write"))

	admin("GET /policies", h.listPolicies, perm("policy.read"))
	admin("POST /policies", h.createPolicy, perm("policy.write"))
	admin("GET /policies/{id}", h.getPolicy, perm("policy.read"))
	admin("PUT /policies/{id}", h.updatePolicy, perm("policy.write"))
	admin("DELETE /policies/{id}", h.deletePolicy, perm("policy.write"))

	admin("GET /audit", h.listAudit, perm("audit.read"))
}

// Handler mounts every Guard route on a private ServeMux and returns it, for
// hosts that plug a single http.Handler into their router (chi.Mount,
// gorilla/mux PathPrefix, echo.WrapHandler, fiber adaptor...). Paths are
// relative to the handler, so strip any prefix you mount it under.
func Handler(g *guard.Guard, opts Options) http.Handler {
	mux := http.NewServeMux()
	Mount(mux, g, opts)
	return mux
}

// route joins a method+path pattern with the group prefix:
// ("POST /login", "/auth") -> "POST /auth/login".
func route(pattern, prefix string) string {
	method, path, _ := strings.Cut(pattern, " ")
	return method + " " + strings.TrimRight(prefix, "/") + path
}

// userOwned exposes {id} as resource.owner_id so "self" policies can match.
func userOwned(r *http.Request, o Options) (guard.Resource, error) {
	id := o.PathValue(r, "id")
	return guard.Resource{ID: id, Attributes: map[string]any{"owner_id": id}}, nil
}

type handlers struct {
	g *guard.Guard
	o Options
}

func (h *handlers) param(r *http.Request, name string) string { return h.o.PathValue(r, name) }

func (h *handlers) actor(r *http.Request) string { return string(PrincipalFrom(r).User.ID) }

type userDTO struct {
	ID          string         `json:"id"`
	Email       string         `json:"email"`
	Status      string         `json:"status"`
	Attributes  map[string]any `json:"attributes"`
	LastLoginAt *time.Time     `json:"last_login_at,omitempty"`
	CreatedAt   time.Time      `json:"created_at"`
}

func toUser(u *guard.User) userDTO {
	attrs := u.Attributes
	if attrs == nil {
		attrs = map[string]any{}
	}
	return userDTO{ID: string(u.ID), Email: string(u.Email), Status: string(u.Status), Attributes: attrs, LastLoginAt: u.LastLoginAt, CreatedAt: u.CreatedAt}
}

type sessionDTO struct {
	ID         string    `json:"id"`
	Current    bool      `json:"current"`
	IP         string    `json:"ip,omitempty"`
	UserAgent  string    `json:"user_agent,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	LastSeenAt time.Time `json:"last_seen_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

func toSessions(list []*guard.Session, current sessiondomain.ID) []sessionDTO {
	out := make([]sessionDTO, 0, len(list))
	for _, s := range list {
		out = append(out, sessionDTO{ID: string(s.ID), Current: s.ID == current, IP: s.IP, UserAgent: s.UserAgent,
			CreatedAt: s.CreatedAt, LastSeenAt: s.LastSeenAt, ExpiresAt: s.ExpiresAt})
	}
	return out
}

// bind decodes the JSON body and reports missing required fields the way gin's
// binding:"required" tag did, so both adapters answer with the same codes.
func bind(w http.ResponseWriter, r *http.Request, dst any, required ...check) bool {
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(dst); err != nil {
		if isTooLarge(err) {
			abort(w, r, http.StatusRequestEntityTooLarge, "body_too_large", "request body too large")
			return false
		}
		abort(w, r, http.StatusBadRequest, "invalid_body", err.Error())
		return false
	}
	for _, c := range required {
		if !c.ok() {
			abort(w, r, http.StatusBadRequest, "invalid_body", "field "+c.name+" is required")
			return false
		}
	}
	return true
}

// check is a required-field rule evaluated after the body is decoded.
type check struct {
	name string
	ok   func() bool
}

// req marks a field required; present is evaluated after decoding.
func req(name string, present func() bool) check { return check{name: name, ok: present} }

// ---------- self-service ----------

type credentials struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (h *handlers) register(w http.ResponseWriter, r *http.Request) {
	var in credentials
	if !bind(w, r, &in, req("email", func() bool { return in.Email != "" }), req("password", func() bool { return in.Password != "" })) {
		return
	}
	ctx := r.Context()
	userID, err := h.o.CreateUser(ctx, in.Email)
	if err != nil {
		fail(w, r, err)
		return
	}
	u, err := h.g.CreateAccount(ctx, userID, in.Email, in.Password, nil, meta(r, h.o))
	if err != nil {
		fail(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusCreated, toUser(u))
}

func (h *handlers) login(w http.ResponseWriter, r *http.Request) {
	var in credentials
	if !bind(w, r, &in, req("email", func() bool { return in.Email != "" }), req("password", func() bool { return in.Password != "" })) {
		return
	}
	res, err := h.g.Login(r.Context(), in.Email, in.Password, meta(r, h.o))
	if err != nil {
		fail(w, r, loginError(err))
		return
	}
	h.revokeCookieSession(r)
	http.SetCookie(w, h.cookie(string(res.Token), int(time.Until(res.Session.ExpiresAt).Seconds())))
	writeJSON(w, r, http.StatusOK, map[string]any{"token": res.Token, "expires_at": res.Session.ExpiresAt, "user": toUser(res.User)})
}

func (h *handlers) cookie(value string, maxAge int) *http.Cookie {
	//nolint:gosec // G124: HttpOnly and SameSite=Strict are set below; Secure is
	// on unless Options.InsecureCookie opts out for local HTTP development.
	return &http.Cookie{
		Name: h.o.CookieName, Value: value, Path: "/", Domain: h.o.CookieDomain,
		MaxAge: maxAge, Secure: !h.o.InsecureCookie, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	}
}

// loginError hides lockout and ban from login responses: both are reported
// only for existing accounts (ban only with the right password), so exposing
// them enumerates accounts and confirms passwords. The audit log keeps the cause.
func loginError(err error) error {
	if errors.Is(err, identitydomain.ErrUserLocked) || errors.Is(err, identitydomain.ErrUserBlocked) {
		return identitydomain.ErrInvalidCredentials
	}
	return err
}

// revokeCookieSession ends the session the login request already carried, so
// a planted or stale cookie session cannot outlive the fresh login.
func (h *handlers) revokeCookieSession(r *http.Request) {
	c, err := r.Cookie(h.o.CookieName)
	if err != nil || c.Value == "" {
		return
	}
	ctx := r.Context()
	p, err := h.g.Authenticate(ctx, c.Value)
	if err != nil || p.Session == nil {
		return
	}
	if err := h.g.Sessions.Revoke(ctx, p.Session.ID); err != nil {
		logError(r, err)
	}
}

func (h *handlers) clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, h.cookie("", -1))
}

func (h *handlers) logout(w http.ResponseWriter, r *http.Request) {
	if err := h.g.Logout(r.Context(), PrincipalFrom(r), meta(r, h.o)); err != nil {
		fail(w, r, err)
		return
	}
	h.clearCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

func (h *handlers) logoutAll(w http.ResponseWriter, r *http.Request) {
	if err := h.g.Sessions.RevokeAll(r.Context(), h.actor(r)); err != nil {
		fail(w, r, err)
		return
	}
	h.clearCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

func (h *handlers) me(w http.ResponseWriter, r *http.Request) {
	p := PrincipalFrom(r)
	out := map[string]any{"user": toUser(p.User), "roles": p.Roles}
	if p.Session != nil {
		out["session_expires_at"] = p.Session.ExpiresAt
	}
	if p.APIKey != nil {
		out["api_key"] = p.APIKey
	}
	writeJSON(w, r, http.StatusOK, out)
}

func (h *handlers) changePassword(w http.ResponseWriter, r *http.Request) {
	var in struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if !bind(w, r, &in, req("old_password", func() bool { return in.OldPassword != "" }), req("new_password", func() bool { return in.NewPassword != "" })) {
		return
	}
	ctx := r.Context()
	p := PrincipalFrom(r)
	if err := h.g.Identity.ChangePassword(ctx, p.User.ID, in.OldPassword, in.NewPassword); err != nil {
		fail(w, r, err)
		return
	}
	// Every other session is signed out; the current one stays.
	list, err := h.g.Sessions.List(ctx, string(p.User.ID))
	if err != nil {
		fail(w, r, err)
		return
	}
	for _, s := range list {
		if s.ID != p.Session.ID {
			_ = h.g.Sessions.Revoke(ctx, s.ID)
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handlers) mySessions(w http.ResponseWriter, r *http.Request) {
	p := PrincipalFrom(r)
	list, err := h.g.Sessions.List(r.Context(), string(p.User.ID))
	if err != nil {
		fail(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusOK, map[string]any{"sessions": toSessions(list, p.Session.ID)})
}

func (h *handlers) revokeMySession(w http.ResponseWriter, r *http.Request) {
	p := PrincipalFrom(r)
	ctx := r.Context()
	list, err := h.g.Sessions.List(ctx, string(p.User.ID))
	if err != nil {
		fail(w, r, err)
		return
	}
	for _, s := range list {
		if string(s.ID) == h.param(r, "id") {
			if err := h.g.Sessions.Revoke(ctx, s.ID); err != nil {
				fail(w, r, err)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}
	fail(w, r, sessiondomain.ErrSessionNotFound)
}

func (h *handlers) authorize(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Action   string `json:"action"`
		Resource struct {
			Type       string         `json:"type"`
			ID         string         `json:"id"`
			Attributes map[string]any `json:"attributes"`
		} `json:"resource"`
	}
	if !bind(w, r, &in, req("action", func() bool { return in.Action != "" }), req("resource.type", func() bool { return in.Resource.Type != "" })) {
		return
	}
	d, err := h.g.Authorize(r.Context(), PrincipalFrom(r), in.Action,
		guard.Resource{Type: in.Resource.Type, ID: in.Resource.ID, Attributes: in.Resource.Attributes}, Environment(r, h.o))
	if err != nil {
		fail(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusOK, d)
}

// ---------- API keys ----------

func (h *handlers) myAPIKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := h.g.APIKeys.List(r.Context(), h.actor(r))
	if err != nil {
		fail(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusOK, map[string]any{"api_keys": keys})
}

func (h *handlers) issueAPIKey(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name      string     `json:"name"`
		Scopes    []string   `json:"scopes"`
		ExpiresAt *time.Time `json:"expires_at"`
	}
	if !bind(w, r, &in, req("name", func() bool { return in.Name != "" }), req("scopes", func() bool { return in.Scopes != nil })) {
		return
	}
	k, tok, err := h.g.IssueAPIKey(r.Context(), PrincipalFrom(r), in.Name, in.Scopes, in.ExpiresAt, meta(r, h.o))
	if err != nil {
		fail(w, r, err)
		return
	}
	// The token is never retrievable again.
	writeJSON(w, r, http.StatusCreated, map[string]any{"api_key": k, "token": tok})
}

func (h *handlers) revokeMyAPIKey(w http.ResponseWriter, r *http.Request) {
	if err := h.g.APIKeys.Revoke(r.Context(), h.actor(r), h.param(r, "id")); err != nil {
		fail(w, r, err)
		return
	}
	h.audit(r, "apikey.revoke", h.param(r, "id"), nil)
	w.WriteHeader(http.StatusNoContent)
}

func (h *handlers) userAPIKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := h.g.APIKeys.List(r.Context(), h.param(r, "id"))
	if err != nil {
		fail(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusOK, map[string]any{"api_keys": keys})
}

func (h *handlers) revokeUserAPIKeys(w http.ResponseWriter, r *http.Request) {
	if err := h.g.APIKeys.RevokeAll(r.Context(), h.param(r, "id")); err != nil {
		fail(w, r, err)
		return
	}
	h.audit(r, "apikey.revoke_all", h.param(r, "id"), nil)
	w.WriteHeader(http.StatusNoContent)
}

// ---------- users ----------

func (h *handlers) createAccount(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email      string         `json:"email"`
		Password   string         `json:"password"`
		Attributes map[string]any `json:"attributes"`
	}
	if !bind(w, r, &in, req("email", func() bool { return in.Email != "" }), req("password", func() bool { return in.Password != "" })) {
		return
	}
	u, err := h.g.CreateAccount(r.Context(), h.param(r, "id"), in.Email, in.Password, in.Attributes, meta(r, h.o))
	if err != nil {
		fail(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusCreated, toUser(u))
}

func (h *handlers) resetPassword(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Password string `json:"password"`
	}
	if !bind(w, r, &in, req("password", func() bool { return in.Password != "" })) {
		return
	}
	if err := h.g.ResetPassword(r.Context(), h.actor(r), h.param(r, "id"), in.Password); err != nil {
		fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handlers) getUser(w http.ResponseWriter, r *http.Request) {
	u, err := h.g.Identity.User(r.Context(), identitydomain.UserID(h.param(r, "id")))
	if err != nil {
		fail(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusOK, toUser(u))
}

func (h *handlers) setStatus(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Status string `json:"status"`
	}
	if !bind(w, r, &in, req("status", func() bool { return in.Status != "" })) {
		return
	}
	st, err := identitydomain.ParseStatus(in.Status)
	if err != nil {
		fail(w, r, err)
		return
	}
	if err := h.g.SetUserStatus(r.Context(), h.actor(r), h.param(r, "id"), st); err != nil {
		fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handlers) setAttributes(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Attributes map[string]any `json:"attributes"`
	}
	if !bind(w, r, &in, req("attributes", func() bool { return in.Attributes != nil })) {
		return
	}
	if err := h.g.SetAttributes(r.Context(), h.actor(r), h.param(r, "id"), in.Attributes); err != nil {
		fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handlers) userRoles(w http.ResponseWriter, r *http.Request) {
	grants, err := h.g.Access.Grants(r.Context(), h.param(r, "id"))
	if err != nil {
		fail(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusOK, map[string]any{"grants": grants})
}

func (h *handlers) assignRole(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Role      string     `json:"role"`
		ExpiresAt *time.Time `json:"expires_at"`
	}
	if !bind(w, r, &in, req("role", func() bool { return in.Role != "" })) {
		return
	}
	ctx := r.Context()
	id := h.param(r, "id")
	if _, err := h.g.Identity.User(ctx, identitydomain.UserID(id)); err != nil {
		fail(w, r, err)
		return
	}
	if in.ExpiresAt != nil && !in.ExpiresAt.After(time.Now()) {
		abort(w, r, http.StatusBadRequest, "invalid_expiry", "expires_at must be in the future")
		return
	}
	if err := h.g.Access.AssignRole(ctx, id, in.Role, h.actor(r), in.ExpiresAt); err != nil {
		fail(w, r, err)
		return
	}
	h.audit(r, "role.assign", id, map[string]any{"role": in.Role})
	w.WriteHeader(http.StatusNoContent)
}

func (h *handlers) unassignRole(w http.ResponseWriter, r *http.Request) {
	id, role := h.param(r, "id"), h.param(r, "role")
	if err := h.g.Access.UnassignRoleAs(r.Context(), h.actor(r), id, role); err != nil {
		fail(w, r, err)
		return
	}
	h.audit(r, "role.unassign", id, map[string]any{"role": role})
	w.WriteHeader(http.StatusNoContent)
}

func (h *handlers) userSessions(w http.ResponseWriter, r *http.Request) {
	list, err := h.g.Sessions.List(r.Context(), h.param(r, "id"))
	if err != nil {
		fail(w, r, err)
		return
	}
	var current sessiondomain.ID
	if s := PrincipalFrom(r).Session; s != nil {
		current = s.ID
	}
	writeJSON(w, r, http.StatusOK, map[string]any{"sessions": toSessions(list, current)})
}

func (h *handlers) revokeUserSessions(w http.ResponseWriter, r *http.Request) {
	if err := h.g.Sessions.RevokeAll(r.Context(), h.param(r, "id")); err != nil {
		fail(w, r, err)
		return
	}
	h.audit(r, "session.revoke_all", h.param(r, "id"), nil)
	w.WriteHeader(http.StatusNoContent)
}

// ---------- roles & permissions ----------

func (h *handlers) listRoles(w http.ResponseWriter, r *http.Request) {
	roles, err := h.g.Access.ListRoles(r.Context())
	if err != nil {
		fail(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusOK, map[string]any{"roles": roles})
}

func (h *handlers) createRole(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name        string `json:"name"`
		Title       string `json:"title"`
		Description string `json:"description"`
		Wildcard    bool   `json:"wildcard"`
	}
	if !bind(w, r, &in, req("name", func() bool { return in.Name != "" })) {
		return
	}
	role, err := h.g.Access.CreateRoleAs(r.Context(), h.actor(r), in.Name, in.Title, in.Description, in.Wildcard)
	if err != nil {
		fail(w, r, err)
		return
	}
	h.audit(r, "role.create", in.Name, nil)
	writeJSON(w, r, http.StatusCreated, role)
}

func (h *handlers) getRole(w http.ResponseWriter, r *http.Request) {
	role, err := h.g.Access.Role(r.Context(), h.param(r, "name"))
	if err != nil {
		fail(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusOK, role)
}

func (h *handlers) deleteRole(w http.ResponseWriter, r *http.Request) {
	name := h.param(r, "name")
	if err := h.g.Access.DeleteRoleAs(r.Context(), h.actor(r), name); err != nil {
		fail(w, r, err)
		return
	}
	h.audit(r, "role.delete", name, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (h *handlers) grantPermission(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Code string `json:"code"`
	}
	if !bind(w, r, &in, req("code", func() bool { return in.Code != "" })) {
		return
	}
	name := h.param(r, "name")
	if err := h.g.Access.GrantPermission(r.Context(), name, in.Code, h.actor(r)); err != nil {
		fail(w, r, err)
		return
	}
	h.audit(r, "role.grant", name, map[string]any{"permission": in.Code})
	w.WriteHeader(http.StatusNoContent)
}

func (h *handlers) revokePermission(w http.ResponseWriter, r *http.Request) {
	name, code := h.param(r, "name"), h.param(r, "code")
	if err := h.g.Access.RevokePermissionAs(r.Context(), h.actor(r), name, code); err != nil {
		fail(w, r, err)
		return
	}
	h.audit(r, "role.revoke", name, map[string]any{"permission": code})
	w.WriteHeader(http.StatusNoContent)
}

func (h *handlers) listPermissions(w http.ResponseWriter, r *http.Request) {
	list, err := h.g.Access.ListPermissions(r.Context())
	if err != nil {
		fail(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusOK, map[string]any{"permissions": list})
}

func (h *handlers) createPermission(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Code        string `json:"code"`
		Description string `json:"description"`
	}
	if !bind(w, r, &in, req("code", func() bool { return in.Code != "" })) {
		return
	}
	p, err := h.g.Access.CreatePermission(r.Context(), in.Code, in.Description)
	if err != nil {
		fail(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusCreated, map[string]any{"code": p.Code(), "resource": p.Resource, "action": p.Action, "description": p.Description})
}

// ---------- policies ----------

func (h *handlers) listPolicies(w http.ResponseWriter, r *http.Request) {
	list, err := h.g.Access.ListPolicies(r.Context())
	if err != nil {
		fail(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusOK, map[string]any{"policies": list})
}

func (h *handlers) createPolicy(w http.ResponseWriter, r *http.Request) {
	var p accessdomain.Policy
	if !bind(w, r, &p) {
		return
	}
	p.ID = ""
	if err := h.g.Access.SavePolicyAs(r.Context(), h.actor(r), &p); err != nil {
		fail(w, r, err)
		return
	}
	h.audit(r, "policy.create", p.ID, map[string]any{"name": p.Name})
	writeJSON(w, r, http.StatusCreated, p)
}

func (h *handlers) getPolicy(w http.ResponseWriter, r *http.Request) {
	p, err := h.g.Access.Policy(r.Context(), h.param(r, "id"))
	if err != nil {
		fail(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusOK, p)
}

func (h *handlers) updatePolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := h.param(r, "id")
	if _, err := h.g.Access.Policy(ctx, id); err != nil {
		fail(w, r, err)
		return
	}
	var p accessdomain.Policy
	if !bind(w, r, &p) {
		return
	}
	p.ID = id
	if err := h.g.Access.SavePolicyAs(ctx, h.actor(r), &p); err != nil {
		fail(w, r, err)
		return
	}
	h.audit(r, "policy.update", p.ID, map[string]any{"name": p.Name})
	writeJSON(w, r, http.StatusOK, p)
}

func (h *handlers) deletePolicy(w http.ResponseWriter, r *http.Request) {
	id := h.param(r, "id")
	if err := h.g.Access.DeletePolicyAs(r.Context(), h.actor(r), id); err != nil {
		fail(w, r, err)
		return
	}
	h.audit(r, "policy.delete", id, nil)
	w.WriteHeader(http.StatusNoContent)
}

// ---------- audit ----------

func (h *handlers) listAudit(w http.ResponseWriter, r *http.Request) {
	if h.g.Audit == nil {
		writeJSON(w, r, http.StatusOK, map[string]any{"events": []guard.AuditEvent{}})
		return
	}
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		limit, _ = strconv.Atoi(v)
	}
	events, err := h.g.Audit.List(r.Context(), r.URL.Query().Get("actor_id"), limit)
	if err != nil {
		fail(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusOK, map[string]any{"events": events})
}

func (h *handlers) audit(r *http.Request, action, target string, md map[string]any) {
	if h.g.Audit == nil {
		return
	}
	m := meta(r, h.o)
	_ = h.g.Audit.Record(r.Context(), guard.AuditEvent{ActorID: h.actor(r), Action: action,
		Target: target, Success: true, IP: m.IP, UserAgent: m.UserAgent, Metadata: md})
}
