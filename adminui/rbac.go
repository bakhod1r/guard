package adminui

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"

	accessdomain "github.com/bakhod1r/guard/access/domain"
)

func (a *app) registerRBAC(r *gin.RouterGroup) {
	r.GET("/roles", a.require("role.read"), a.rolesList)
	r.POST("/roles", a.require("role.write"), a.roleCreate)
	r.GET("/roles/:name", a.require("role.read"), a.roleDetail)
	r.POST("/roles/:name/delete", a.require("role.write"), a.roleDelete)
	r.POST("/roles/:name/permissions", a.require("role.write"), a.roleGrant)
	r.POST("/roles/:name/permissions/revoke", a.require("role.write"), a.roleRevoke)
	r.GET("/permissions", a.require("permission.read"), a.permissionsList)
	r.POST("/permissions", a.require("permission.write"), a.permissionCreate)
}

func rbacRolePath(name string) string { return "/roles/" + url.PathEscape(name) }

// rbacInternalError renders a 500 page for storage failures on GET pages.
func (a *app) rbacInternalError(c *gin.Context, err error) {
	a.logError(c, err)
	a.render(c, http.StatusInternalServerError, "error", "Error", "", map[string]string{
		"Message": "Internal error while loading this page. Try again later.",
	})
}

func (a *app) rolesList(c *gin.Context) {
	roles, err := a.g.Access.ListRoles(c.Request.Context())
	if err != nil {
		a.rbacInternalError(c, err)
		return
	}
	a.render(c, http.StatusOK, "roles_list", "Roles", "roles", map[string]any{
		"Roles": roles, "CanWrite": a.can(c, "role.write"),
	})
}

func (a *app) roleCreate(c *gin.Context) {
	role, err := a.g.Access.CreateRoleAs(c.Request.Context(), a.actor(c), c.PostForm("name"), c.PostForm("title"),
		c.PostForm("description"), c.PostForm("wildcard") != "")
	if err != nil {
		a.fail(c, "/roles", err)
		return
	}
	a.audit(c, "role.create", role.Name, map[string]any{"wildcard": role.Wildcard})
	a.redirect(c, rbacRolePath(role.Name), "role "+role.Name+" created")
}

func (a *app) roleDetail(c *gin.Context) {
	ctx := c.Request.Context()
	role, err := a.g.Access.Role(ctx, c.Param("name"))
	if errors.Is(err, accessdomain.ErrRoleNotFound) {
		a.render(c, http.StatusNotFound, "error", "Role not found", "roles", map[string]string{
			"Message": "Role not found.",
		})
		return
	}
	if err != nil {
		a.rbacInternalError(c, err)
		return
	}
	all, err := a.g.Access.ListPermissions(ctx)
	if err != nil {
		a.rbacInternalError(c, err)
		return
	}
	granted := map[string]bool{}
	for _, p := range role.Permissions {
		granted[p.Code()] = true
	}
	var grantable []accessdomain.Permission
	for _, p := range all {
		if !granted[p.Code()] {
			grantable = append(grantable, p)
		}
	}
	a.render(c, http.StatusOK, "roles_detail", "Role "+role.Name, "roles", map[string]any{
		"Role": role, "Grantable": grantable, "CanWrite": a.can(c, "role.write"),
	})
}

func (a *app) roleDelete(c *gin.Context) {
	name := c.Param("name")
	if err := a.g.Access.DeleteRoleAs(c.Request.Context(), a.actor(c), name); err != nil {
		back := "/roles"
		if errors.Is(err, accessdomain.ErrSystemRole) {
			back = rbacRolePath(name)
		}
		a.fail(c, back, err)
		return
	}
	a.audit(c, "role.delete", name, nil)
	a.redirect(c, "/roles", "role "+name+" deleted")
}

func (a *app) roleGrant(c *gin.Context) {
	name, code := c.Param("name"), c.PostForm("code")
	if err := a.g.Access.GrantPermission(c.Request.Context(), name, code, a.actor(c)); err != nil {
		a.fail(c, rbacRolePath(name), err)
		return
	}
	a.audit(c, "role.grant", name, map[string]any{"permission": code})
	a.redirect(c, rbacRolePath(name), code+" granted")
}

func (a *app) roleRevoke(c *gin.Context) {
	name, code := c.Param("name"), c.PostForm("code")
	if err := a.g.Access.RevokePermissionAs(c.Request.Context(), a.actor(c), name, code); err != nil {
		a.fail(c, rbacRolePath(name), err)
		return
	}
	a.audit(c, "role.revoke", name, map[string]any{"permission": code})
	a.redirect(c, rbacRolePath(name), code+" revoked")
}

type rbacPermissionRow struct {
	Code, Description string
	Roles             []string
}

func (a *app) permissionsList(c *gin.Context) {
	ctx := c.Request.Context()
	roles, err := a.g.Access.ListRoles(ctx)
	if err != nil {
		a.rbacInternalError(c, err)
		return
	}
	perms, err := a.g.Access.ListPermissions(ctx)
	if err != nil {
		a.rbacInternalError(c, err)
		return
	}
	holders := map[string][]string{}
	for _, r := range roles {
		for _, p := range r.Permissions {
			holders[p.Code()] = append(holders[p.Code()], r.Name)
		}
	}
	rows := make([]rbacPermissionRow, 0, len(perms))
	for _, p := range perms {
		rows = append(rows, rbacPermissionRow{Code: p.Code(), Description: p.Description, Roles: holders[p.Code()]})
	}
	a.render(c, http.StatusOK, "permissions", "Permissions", "permissions", map[string]any{
		"Permissions": rows, "CanWrite": a.can(c, "permission.write"),
	})
}

func (a *app) permissionCreate(c *gin.Context) {
	p, err := a.g.Access.CreatePermission(c.Request.Context(), c.PostForm("code"), c.PostForm("description"))
	if err != nil {
		a.fail(c, "/permissions", err)
		return
	}
	a.audit(c, "permission.create", p.Code(), nil)
	a.redirect(c, "/permissions", "permission "+p.Code()+" created")
}
