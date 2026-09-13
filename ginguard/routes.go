package ginguard

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/bakhod1r/guard"
	accessdomain "github.com/bakhod1r/guard/access/domain"
	identitydomain "github.com/bakhod1r/guard/identity/domain"
	sessiondomain "github.com/bakhod1r/guard/session/domain"
)

// Mount registers every Guard route on r.
//
//	Self-service (AuthPath, default /auth):
//	  POST   /register              POST /login          POST /logout
//	  POST   /logout-all            GET  /me             PUT  /password
//	  GET    /sessions              DELETE /sessions/:id POST /authorize
//	Management (AdminPath, default /guard), each guarded by a permission:
//	  GET    /users/:id                       user.read (or self)
//	  PUT    /users/:id/status                user.write
//	  PUT    /users/:id/attributes            user.write
//	  GET    /users/:id/roles                 role.read
//	  POST   /users/:id/roles                 role.assign
//	  DELETE /users/:id/roles/:role           role.assign
//	  GET    /users/:id/sessions              session.read
//	  DELETE /users/:id/sessions              session.revoke
//	  GET    /roles  POST /roles              role.read / role.write
//	  GET    /roles/:name  DELETE /roles/:name
//	  POST   /roles/:name/permissions         role.write
//	  DELETE /roles/:name/permissions/:code   role.write
//	  GET    /permissions  POST /permissions  permission.read / permission.write
//	  GET    /policies  POST /policies        policy.read / policy.write
//	  GET|PUT|DELETE /policies/:id
//	  GET    /audit                           audit.read
func Mount(r gin.IRouter, g *guard.Guard, opts Options) {
	o := opts.withDefaults()
	h := &handlers{g: g, o: o}
	perm := func(code string) gin.HandlerFunc { return RequirePermission(g, o, code) }

	a := r.Group(o.AuthPath)
	a.POST("/register", h.register)
	a.POST("/login", h.login)
	authed := a.Group("", RequireAuth(g, o))
	authed.POST("/logout", h.logout)
	authed.POST("/logout-all", h.logoutAll)
	authed.GET("/me", h.me)
	authed.PUT("/password", h.changePassword)
	authed.GET("/sessions", h.mySessions)
	authed.DELETE("/sessions/:id", h.revokeMySession)
	authed.POST("/authorize", h.authorize)

	m := r.Group(o.AdminPath)
	m.GET("/users/:id", Require(g, o, "user", "read", ParamResource("id")), h.getUser)
	m.PUT("/users/:id/status", Require(g, o, "user", "write", ParamResource("id")), h.setStatus)
	m.PUT("/users/:id/attributes", Require(g, o, "user", "write", ParamResource("id")), h.setAttributes)
	m.GET("/users/:id/roles", Require(g, o, "role", "read", userOwned), h.userRoles)
	m.POST("/users/:id/roles", perm("role.assign"), h.assignRole)
	m.DELETE("/users/:id/roles/:role", perm("role.assign"), h.unassignRole)
	m.GET("/users/:id/sessions", Require(g, o, "session", "read", userOwned), h.userSessions)
	m.DELETE("/users/:id/sessions", Require(g, o, "session", "revoke", userOwned), h.revokeUserSessions)

	m.GET("/roles", perm("role.read"), h.listRoles)
	m.POST("/roles", perm("role.write"), h.createRole)
	m.GET("/roles/:name", perm("role.read"), h.getRole)
	m.DELETE("/roles/:name", perm("role.write"), h.deleteRole)
	m.POST("/roles/:name/permissions", perm("role.write"), h.grantPermission)
	m.DELETE("/roles/:name/permissions/:code", perm("role.write"), h.revokePermission)

	m.GET("/permissions", perm("permission.read"), h.listPermissions)
	m.POST("/permissions", perm("permission.write"), h.createPermission)

	m.GET("/policies", perm("policy.read"), h.listPolicies)
	m.POST("/policies", perm("policy.write"), h.createPolicy)
	m.GET("/policies/:id", perm("policy.read"), h.getPolicy)
	m.PUT("/policies/:id", perm("policy.write"), h.updatePolicy)
	m.DELETE("/policies/:id", perm("policy.write"), h.deletePolicy)

	m.GET("/audit", perm("audit.read"), h.listAudit)
}

// userOwned exposes :id as resource.owner_id so "self" policies can match.
func userOwned(c *gin.Context) (guard.Resource, error) {
	return guard.Resource{ID: c.Param("id"), Attributes: map[string]any{"owner_id": c.Param("id")}}, nil
}

type handlers struct {
	g *guard.Guard
	o Options
}

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

func bind(c *gin.Context, dst any) bool {
	if err := c.ShouldBindJSON(dst); err != nil {
		abort(c, http.StatusBadRequest, "invalid_body", err.Error())
		return false
	}
	return true
}

// ---------- self-service ----------

type credentials struct {
	Email    string `json:"email" binding:"required"`
	Password string `json:"password" binding:"required"`
}

func (h *handlers) register(c *gin.Context) {
	var in credentials
	if !bind(c, &in) {
		return
	}
	u, err := h.g.Register(c.Request.Context(), in.Email, in.Password, nil, meta(c))
	if err != nil {
		fail(c, err)
		return
	}
	c.JSON(http.StatusCreated, toUser(u))
}

func (h *handlers) login(c *gin.Context) {
	var in credentials
	if !bind(c, &in) {
		return
	}
	res, err := h.g.Login(c.Request.Context(), in.Email, in.Password, meta(c))
	if err != nil {
		fail(c, err)
		return
	}
	maxAge := int(time.Until(res.Session.ExpiresAt).Seconds())
	c.SetSameSite(http.SameSiteStrictMode)
	c.SetCookie(h.o.CookieName, string(res.Token), maxAge, "/", h.o.CookieDomain, !h.o.InsecureCookie, true)
	c.JSON(http.StatusOK, gin.H{"token": res.Token, "expires_at": res.Session.ExpiresAt, "user": toUser(res.User)})
}

func (h *handlers) clearCookie(c *gin.Context) {
	c.SetSameSite(http.SameSiteStrictMode)
	c.SetCookie(h.o.CookieName, "", -1, "/", h.o.CookieDomain, !h.o.InsecureCookie, true)
}

func (h *handlers) logout(c *gin.Context) {
	if err := h.g.Logout(c.Request.Context(), PrincipalFrom(c), meta(c)); err != nil {
		fail(c, err)
		return
	}
	h.clearCookie(c)
	c.Status(http.StatusNoContent)
}

func (h *handlers) logoutAll(c *gin.Context) {
	if err := h.g.Sessions.RevokeAll(c.Request.Context(), string(PrincipalFrom(c).User.ID)); err != nil {
		fail(c, err)
		return
	}
	h.clearCookie(c)
	c.Status(http.StatusNoContent)
}

func (h *handlers) me(c *gin.Context) {
	p := PrincipalFrom(c)
	c.JSON(http.StatusOK, gin.H{"user": toUser(p.User), "roles": p.Roles, "session_expires_at": p.Session.ExpiresAt})
}

func (h *handlers) changePassword(c *gin.Context) {
	var in struct {
		OldPassword string `json:"old_password" binding:"required"`
		NewPassword string `json:"new_password" binding:"required"`
	}
	if !bind(c, &in) {
		return
	}
	ctx := c.Request.Context()
	p := PrincipalFrom(c)
	if err := h.g.Identity.ChangePassword(ctx, p.User.ID, in.OldPassword, in.NewPassword); err != nil {
		fail(c, err)
		return
	}
	// Every other session is signed out; the current one stays.
	list, err := h.g.Sessions.List(ctx, string(p.User.ID))
	if err != nil {
		fail(c, err)
		return
	}
	for _, s := range list {
		if s.ID != p.Session.ID {
			_ = h.g.Sessions.Revoke(ctx, s.ID)
		}
	}
	c.Status(http.StatusNoContent)
}

func (h *handlers) mySessions(c *gin.Context) {
	p := PrincipalFrom(c)
	list, err := h.g.Sessions.List(c.Request.Context(), string(p.User.ID))
	if err != nil {
		fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"sessions": toSessions(list, p.Session.ID)})
}

func (h *handlers) revokeMySession(c *gin.Context) {
	p := PrincipalFrom(c)
	ctx := c.Request.Context()
	list, err := h.g.Sessions.List(ctx, string(p.User.ID))
	if err != nil {
		fail(c, err)
		return
	}
	for _, s := range list {
		if string(s.ID) == c.Param("id") {
			if err := h.g.Sessions.Revoke(ctx, s.ID); err != nil {
				fail(c, err)
				return
			}
			c.Status(http.StatusNoContent)
			return
		}
	}
	fail(c, sessiondomain.ErrSessionNotFound)
}

func (h *handlers) authorize(c *gin.Context) {
	var in struct {
		Action   string `json:"action" binding:"required"`
		Resource struct {
			Type       string         `json:"type" binding:"required"`
			ID         string         `json:"id"`
			Attributes map[string]any `json:"attributes"`
		} `json:"resource"`
	}
	if !bind(c, &in) {
		return
	}
	d, err := h.g.Authorize(c.Request.Context(), PrincipalFrom(c), in.Action,
		guard.Resource{Type: in.Resource.Type, ID: in.Resource.ID, Attributes: in.Resource.Attributes}, Environment(c))
	if err != nil {
		fail(c, err)
		return
	}
	c.JSON(http.StatusOK, d)
}

// ---------- users ----------

func (h *handlers) getUser(c *gin.Context) {
	u, err := h.g.Identity.User(c.Request.Context(), identitydomain.UserID(c.Param("id")))
	if err != nil {
		fail(c, err)
		return
	}
	c.JSON(http.StatusOK, toUser(u))
}

func (h *handlers) setStatus(c *gin.Context) {
	var in struct {
		Status string `json:"status" binding:"required"`
	}
	if !bind(c, &in) {
		return
	}
	st, err := identitydomain.ParseStatus(in.Status)
	if err != nil {
		fail(c, err)
		return
	}
	if err := h.g.SetUserStatus(c.Request.Context(), string(PrincipalFrom(c).User.ID), c.Param("id"), st); err != nil {
		fail(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *handlers) setAttributes(c *gin.Context) {
	var in struct {
		Attributes map[string]any `json:"attributes" binding:"required"`
	}
	if !bind(c, &in) {
		return
	}
	if err := h.g.Identity.SetAttributes(c.Request.Context(), identitydomain.UserID(c.Param("id")), in.Attributes); err != nil {
		fail(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *handlers) userRoles(c *gin.Context) {
	grants, err := h.g.Access.Grants(c.Request.Context(), c.Param("id"))
	if err != nil {
		fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"grants": grants})
}

func (h *handlers) assignRole(c *gin.Context) {
	var in struct {
		Role      string     `json:"role" binding:"required"`
		ExpiresAt *time.Time `json:"expires_at"`
	}
	if !bind(c, &in) {
		return
	}
	ctx := c.Request.Context()
	if _, err := h.g.Identity.User(ctx, identitydomain.UserID(c.Param("id"))); err != nil {
		fail(c, err)
		return
	}
	if in.ExpiresAt != nil && !in.ExpiresAt.After(time.Now()) {
		abort(c, http.StatusBadRequest, "invalid_expiry", "expires_at must be in the future")
		return
	}
	actor := string(PrincipalFrom(c).User.ID)
	if err := h.g.Access.AssignRole(ctx, c.Param("id"), in.Role, actor, in.ExpiresAt); err != nil {
		fail(c, err)
		return
	}
	h.audit(c, "role.assign", c.Param("id"), map[string]any{"role": in.Role})
	c.Status(http.StatusNoContent)
}

func (h *handlers) unassignRole(c *gin.Context) {
	if err := h.g.Access.UnassignRole(c.Request.Context(), c.Param("id"), c.Param("role")); err != nil {
		fail(c, err)
		return
	}
	h.audit(c, "role.unassign", c.Param("id"), map[string]any{"role": c.Param("role")})
	c.Status(http.StatusNoContent)
}

func (h *handlers) userSessions(c *gin.Context) {
	list, err := h.g.Sessions.List(c.Request.Context(), c.Param("id"))
	if err != nil {
		fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"sessions": toSessions(list, PrincipalFrom(c).Session.ID)})
}

func (h *handlers) revokeUserSessions(c *gin.Context) {
	if err := h.g.Sessions.RevokeAll(c.Request.Context(), c.Param("id")); err != nil {
		fail(c, err)
		return
	}
	h.audit(c, "session.revoke_all", c.Param("id"), nil)
	c.Status(http.StatusNoContent)
}

// ---------- roles & permissions ----------

func (h *handlers) listRoles(c *gin.Context) {
	roles, err := h.g.Access.ListRoles(c.Request.Context())
	if err != nil {
		fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"roles": roles})
}

func (h *handlers) createRole(c *gin.Context) {
	var in struct {
		Name        string `json:"name" binding:"required"`
		Title       string `json:"title"`
		Description string `json:"description"`
		Wildcard    bool   `json:"wildcard"`
	}
	if !bind(c, &in) {
		return
	}
	role, err := h.g.Access.CreateRole(c.Request.Context(), in.Name, in.Title, in.Description, in.Wildcard)
	if err != nil {
		fail(c, err)
		return
	}
	h.audit(c, "role.create", in.Name, nil)
	c.JSON(http.StatusCreated, role)
}

func (h *handlers) getRole(c *gin.Context) {
	role, err := h.g.Access.Role(c.Request.Context(), c.Param("name"))
	if err != nil {
		fail(c, err)
		return
	}
	c.JSON(http.StatusOK, role)
}

func (h *handlers) deleteRole(c *gin.Context) {
	if err := h.g.Access.DeleteRole(c.Request.Context(), c.Param("name")); err != nil {
		fail(c, err)
		return
	}
	h.audit(c, "role.delete", c.Param("name"), nil)
	c.Status(http.StatusNoContent)
}

func (h *handlers) grantPermission(c *gin.Context) {
	var in struct {
		Code string `json:"code" binding:"required"`
	}
	if !bind(c, &in) {
		return
	}
	actor := string(PrincipalFrom(c).User.ID)
	if err := h.g.Access.GrantPermission(c.Request.Context(), c.Param("name"), in.Code, actor); err != nil {
		fail(c, err)
		return
	}
	h.audit(c, "role.grant", c.Param("name"), map[string]any{"permission": in.Code})
	c.Status(http.StatusNoContent)
}

func (h *handlers) revokePermission(c *gin.Context) {
	if err := h.g.Access.RevokePermission(c.Request.Context(), c.Param("name"), c.Param("code")); err != nil {
		fail(c, err)
		return
	}
	h.audit(c, "role.revoke", c.Param("name"), map[string]any{"permission": c.Param("code")})
	c.Status(http.StatusNoContent)
}

func (h *handlers) listPermissions(c *gin.Context) {
	list, err := h.g.Access.ListPermissions(c.Request.Context())
	if err != nil {
		fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"permissions": list})
}

func (h *handlers) createPermission(c *gin.Context) {
	var in struct {
		Code        string `json:"code" binding:"required"`
		Description string `json:"description"`
	}
	if !bind(c, &in) {
		return
	}
	p, err := h.g.Access.CreatePermission(c.Request.Context(), in.Code, in.Description)
	if err != nil {
		fail(c, err)
		return
	}
	c.JSON(http.StatusCreated, gin.H{"code": p.Code(), "resource": p.Resource, "action": p.Action, "description": p.Description})
}

// ---------- policies ----------

func (h *handlers) listPolicies(c *gin.Context) {
	list, err := h.g.Access.ListPolicies(c.Request.Context())
	if err != nil {
		fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"policies": list})
}

func (h *handlers) createPolicy(c *gin.Context) {
	var p accessdomain.Policy
	if !bind(c, &p) {
		return
	}
	p.ID = ""
	if err := h.g.Access.SavePolicy(c.Request.Context(), &p); err != nil {
		fail(c, err)
		return
	}
	h.audit(c, "policy.create", p.ID, map[string]any{"name": p.Name})
	c.JSON(http.StatusCreated, p)
}

func (h *handlers) getPolicy(c *gin.Context) {
	p, err := h.g.Access.Policy(c.Request.Context(), c.Param("id"))
	if err != nil {
		fail(c, err)
		return
	}
	c.JSON(http.StatusOK, p)
}

func (h *handlers) updatePolicy(c *gin.Context) {
	ctx := c.Request.Context()
	if _, err := h.g.Access.Policy(ctx, c.Param("id")); err != nil {
		fail(c, err)
		return
	}
	var p accessdomain.Policy
	if !bind(c, &p) {
		return
	}
	p.ID = c.Param("id")
	if err := h.g.Access.SavePolicy(ctx, &p); err != nil {
		fail(c, err)
		return
	}
	h.audit(c, "policy.update", p.ID, map[string]any{"name": p.Name})
	c.JSON(http.StatusOK, p)
}

func (h *handlers) deletePolicy(c *gin.Context) {
	if err := h.g.Access.DeletePolicy(c.Request.Context(), c.Param("id")); err != nil {
		fail(c, err)
		return
	}
	h.audit(c, "policy.delete", c.Param("id"), nil)
	c.Status(http.StatusNoContent)
}

// ---------- audit ----------

func (h *handlers) listAudit(c *gin.Context) {
	if h.g.Audit == nil {
		c.JSON(http.StatusOK, gin.H{"events": []guard.AuditEvent{}})
		return
	}
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))
	events, err := h.g.Audit.List(c.Request.Context(), c.Query("actor_id"), limit)
	if err != nil {
		fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"events": events})
}

func (h *handlers) audit(c *gin.Context, action, target string, md map[string]any) {
	if h.g.Audit == nil {
		return
	}
	m := meta(c)
	_ = h.g.Audit.Record(c.Request.Context(), guard.AuditEvent{ActorID: string(PrincipalFrom(c).User.ID), Action: action,
		Target: target, Success: true, IP: m.IP, UserAgent: m.UserAgent, Metadata: md})
}
