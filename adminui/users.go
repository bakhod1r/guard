package adminui

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/bakhod1r/guard"
	identitydomain "github.com/bakhod1r/guard/identity/domain"
)

const usersPageSize = 25

var userStatuses = []identitydomain.Status{identitydomain.StatusPending, identitydomain.StatusActive,
	identitydomain.StatusBanned, identitydomain.StatusSuspended}

func (a *app) registerUsers(r *gin.RouterGroup) {
	r.GET("/users", a.require("user.read"), a.usersList)
	r.GET("/users/:id", a.userDetail)
	r.POST("/users/new", a.require("user.write"), a.userCreate)
	r.POST("/users/:id/status", a.require("user.write"), a.userStatus)
	r.POST("/users/:id/attributes", a.require("user.write"), a.userAttributes)
	r.POST("/users/:id/password", a.require("user.write"), a.userPassword)
	r.POST("/users/:id/roles", a.require("role.assign"), a.userAssignRole)
	r.POST("/users/:id/roles/:role/remove", a.require("role.assign"), a.userUnassignRole)
	r.POST("/users/:id/sessions/revoke-all", a.require("session.revoke"), a.userRevokeSessions)
	r.POST("/users/:id/api-keys/revoke-all", a.require("apikey.revoke"), a.userRevokeAPIKeys)
}

func userPath(id string) string { return "/users/" + url.PathEscape(id) }

// usersError renders the error page; internal causes are logged, never shown.
func (a *app) usersError(c *gin.Context, status int, msg string, err error) {
	if err != nil {
		_ = c.Error(err)
	}
	a.render(c, status, "error", http.StatusText(status), "users", map[string]string{"Message": msg})
}

type usersListData struct {
	Users              []guard.User
	Total, Page        int
	PrevPage, NextPage int // 0 = no link
	Search, Status     string
	Statuses           []identitydomain.Status
	CanWrite           bool
}

func (a *app) usersList(c *gin.Context) {
	d := usersListData{Search: c.Query("q"), Status: c.Query("status"), Statuses: userStatuses, CanWrite: a.can(c, "user.write")}
	q := identitydomain.ListQuery{Search: d.Search, Limit: usersPageSize}
	if d.Status != "" {
		st, err := identitydomain.ParseStatus(d.Status)
		if err != nil {
			a.usersError(c, http.StatusBadRequest, err.Error(), nil)
			return
		}
		q.Status = st
	}
	d.Page, _ = strconv.Atoi(c.Query("page"))
	d.Page = max(d.Page, 1)
	q.Offset = (d.Page - 1) * usersPageSize
	users, total, err := a.g.Identity.ListUsers(c.Request.Context(), q)
	if err != nil {
		a.usersError(c, http.StatusInternalServerError, "internal error", err)
		return
	}
	d.Users, d.Total = users, total
	if d.Page > 1 {
		d.PrevPage = d.Page - 1
	}
	if q.Offset+len(users) < total {
		d.NextPage = d.Page + 1
	}
	a.render(c, http.StatusOK, "users_list", "Users", "users", d)
}

type userAttribute struct{ Key, Value string }

type userDetailData struct {
	Account                                               *guard.User
	Attributes                                            []userAttribute
	AttributesJSON                                        string
	Grants                                                []guard.RoleGrant
	Sessions                                              []*guard.Session
	APIKeys                                               []guard.APIKey
	Roles                                                 []guard.Role
	Statuses                                              []identitydomain.Status
	CanWrite, CanAssign, CanRevokeSessions, CanRevokeKeys bool
}

func (a *app) userDetail(c *gin.Context) {
	id := c.Param("id")
	if !a.canOn(c, "user.read", guard.Resource{ID: id}) {
		a.usersError(c, http.StatusForbidden, "You need the user.read permission to view this account.", nil)
		return
	}
	ctx := c.Request.Context()
	u, err := a.g.Identity.User(ctx, identitydomain.UserID(id))
	if errors.Is(err, identitydomain.ErrUserNotFound) {
		a.usersError(c, http.StatusNotFound, "Account not found.", nil)
		return
	}
	if err != nil {
		a.usersError(c, http.StatusInternalServerError, "internal error", err)
		return
	}
	d := userDetailData{Account: u, Statuses: userStatuses,
		CanWrite: a.can(c, "user.write"), CanAssign: a.can(c, "role.assign"),
		CanRevokeSessions: a.can(c, "session.revoke"), CanRevokeKeys: a.can(c, "apikey.revoke")}
	var e1, e2, e3, e4 error
	d.Grants, e1 = a.g.Access.Grants(ctx, id)
	d.Sessions, e2 = a.g.Sessions.List(ctx, id)
	d.APIKeys, e3 = a.g.APIKeys.List(ctx, id)
	d.Roles, e4 = a.g.Access.ListRoles(ctx)
	if err := errors.Join(e1, e2, e3, e4); err != nil {
		a.usersError(c, http.StatusInternalServerError, "internal error", err)
		return
	}
	for k, v := range u.Attributes {
		d.Attributes = append(d.Attributes, userAttribute{Key: k, Value: userJSON(v, "")})
	}
	sort.Slice(d.Attributes, func(i, j int) bool { return d.Attributes[i].Key < d.Attributes[j].Key })
	d.AttributesJSON = userJSON(u.Attributes, "  ")
	a.render(c, http.StatusOK, "users_detail", string(u.Email), "users", d)
}

func (a *app) userCreate(c *gin.Context) {
	u, err := a.g.CreateAccount(c.Request.Context(), c.PostForm("user_id"), c.PostForm("email"), c.PostForm("password"), nil, a.meta(c))
	if err != nil {
		a.fail(c, "/users", err)
		return
	}
	a.redirect(c, userPath(string(u.ID)), "account linked")
}

func (a *app) userStatus(c *gin.Context) {
	id := c.Param("id")
	st, err := identitydomain.ParseStatus(c.PostForm("status"))
	if err == nil {
		err = a.g.SetUserStatus(c.Request.Context(), a.actor(c), id, st)
	}
	if err != nil {
		a.fail(c, userPath(id), err)
		return
	}
	a.redirect(c, userPath(id), "status set to "+string(st))
}

func (a *app) userAttributes(c *gin.Context) {
	id := c.Param("id")
	var attrs map[string]any
	if err := json.Unmarshal([]byte(c.PostForm("attributes")), &attrs); err != nil {
		a.fail(c, userPath(id), fmt.Errorf("%w: attributes must be a JSON object", errBadInput))
		return
	}
	if err := a.g.Identity.SetAttributes(c.Request.Context(), identitydomain.UserID(id), attrs); err != nil {
		a.fail(c, userPath(id), err)
		return
	}
	a.audit(c, "user.attributes", id, nil)
	a.redirect(c, userPath(id), "attributes saved")
}

func (a *app) userPassword(c *gin.Context) {
	id := c.Param("id")
	if err := a.g.ResetPassword(c.Request.Context(), a.actor(c), id, c.PostForm("password")); err != nil {
		a.fail(c, userPath(id), err)
		return
	}
	a.redirect(c, userPath(id), "password reset; all sessions revoked")
}

func (a *app) userAssignRole(c *gin.Context) {
	id, role := c.Param("id"), c.PostForm("role")
	ctx := c.Request.Context()
	var expires *time.Time
	md := map[string]any{"role": role}
	if raw := c.PostForm("expires_at"); raw != "" {
		t, err := time.ParseInLocation("2006-01-02T15:04", raw, time.Local)
		if err != nil || !t.After(time.Now()) {
			a.fail(c, userPath(id), fmt.Errorf("%w: expiry must be a future date and time", errBadInput))
			return
		}
		expires = &t
		md["expires_at"] = t.UTC().Format(time.RFC3339)
	}
	_, err := a.g.Identity.User(ctx, identitydomain.UserID(id))
	if err == nil {
		err = a.g.Access.AssignRole(ctx, id, role, a.actor(c), expires)
	}
	if err != nil {
		a.fail(c, userPath(id), err)
		return
	}
	a.audit(c, "role.assign", id, md)
	a.redirect(c, userPath(id), "role "+role+" assigned")
}

func (a *app) userUnassignRole(c *gin.Context) {
	id, role := c.Param("id"), c.Param("role")
	if err := a.g.Access.UnassignRole(c.Request.Context(), id, role); err != nil {
		a.fail(c, userPath(id), err)
		return
	}
	a.audit(c, "role.unassign", id, map[string]any{"role": role})
	a.redirect(c, userPath(id), "role "+role+" removed")
}

func (a *app) userRevokeSessions(c *gin.Context) {
	id := c.Param("id")
	if err := a.g.Sessions.RevokeAll(c.Request.Context(), id); err != nil {
		a.fail(c, userPath(id), err)
		return
	}
	a.audit(c, "session.revoke_all", id, nil)
	a.redirect(c, userPath(id), "all sessions revoked")
}

func (a *app) userRevokeAPIKeys(c *gin.Context) {
	id := c.Param("id")
	if err := a.g.APIKeys.RevokeAll(c.Request.Context(), id); err != nil {
		a.fail(c, userPath(id), err)
		return
	}
	a.audit(c, "apikey.revoke_all", id, nil)
	a.redirect(c, userPath(id), "all API keys revoked")
}

// userJSON encodes without \u003c escaping; html/template escapes on output.
func userJSON(v any, indent string) string {
	var buf strings.Builder
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", indent)
	_ = enc.Encode(v)
	return strings.TrimSuffix(buf.String(), "\n")
}
