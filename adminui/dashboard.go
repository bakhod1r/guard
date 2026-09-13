package adminui

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/bakhod1r/guard"
)

// Stat is one dashboard card. Err is shown instead of Value when loading failed.
type Stat struct {
	Key, Label, Href string
	Value            int
	Err              string
}

type dashboardData struct {
	Roles []string
	Stats []Stat
}

func (a *app) registerDashboard(r *gin.RouterGroup) {
	r.GET("", a.dashboard)
}

func statOf[T any](key, label, href string, items []T, err error) Stat {
	s := Stat{Key: key, Label: label, Href: href, Value: len(items)}
	if err != nil {
		s.Err = "could not load"
	}
	return s
}

func (a *app) dashboard(c *gin.Context) {
	ctx := c.Request.Context()
	p := ginPrincipal(c)
	d := dashboardData{}
	for _, role := range p.Roles {
		d.Roles = append(d.Roles, role.Name)
	}
	if a.can(c, "role.read") {
		v, err := a.g.Access.ListRoles(ctx)
		d.Stats = append(d.Stats, statOf("roles", "Roles", "/roles", v, err))
	}
	if a.can(c, "permission.read") {
		v, err := a.g.Access.ListPermissions(ctx)
		d.Stats = append(d.Stats, statOf("permissions", "Permissions", "/permissions", v, err))
	}
	if a.can(c, "policy.read") {
		v, err := a.g.Access.ListPolicies(ctx)
		d.Stats = append(d.Stats, statOf("policies", "Policies", "/policies", v, err))
	}
	sessions, err := a.g.Sessions.List(ctx, a.actor(c))
	d.Stats = append(d.Stats, statOf("sessions", "My active sessions", "/security", sessions, err))
	keys, err := a.g.APIKeys.List(ctx, a.actor(c))
	d.Stats = append(d.Stats, statOf("apikeys", "My API keys", "/security", keys, err))
	for _, s := range d.Stats {
		if s.Err != "" {
			_ = c.Error(fmt.Errorf("adminui: dashboard stat %s failed", s.Key))
		}
	}
	a.render(c, http.StatusOK, "dashboard", "Dashboard", "dashboard", d)
}

// ---------- audit ----------

type auditRow struct {
	Event    guard.AuditEvent
	Metadata []string // escaped by html/template on output
}

type auditData struct {
	ActorID    string
	Limit      int
	Configured bool
	Err        string
	Rows       []auditRow
}

const (
	auditDefaultLimit = 100
	auditMaxLimit     = 500
)

func (a *app) registerAudit(r *gin.RouterGroup) {
	r.GET("/audit", a.require("audit.read"), a.auditPage)
}

func auditLimit(raw string) int {
	n, err := strconv.Atoi(raw)
	switch {
	case err != nil || n <= 0:
		return auditDefaultLimit
	case n > auditMaxLimit:
		return auditMaxLimit
	}
	return n
}

func (a *app) auditPage(c *gin.Context) {
	d := auditData{ActorID: c.Query("actor_id"), Limit: auditLimit(c.Query("limit")), Configured: a.g.Audit != nil}
	if d.Configured {
		events, err := a.g.Audit.List(c.Request.Context(), d.ActorID, d.Limit)
		if err != nil {
			_ = c.Error(err)
			d.Err = "could not load audit events"
		}
		for _, e := range events {
			row := auditRow{Event: e}
			for k, v := range e.Metadata {
				row.Metadata = append(row.Metadata, fmt.Sprintf("%s=%v", k, v))
			}
			sort.Strings(row.Metadata)
			d.Rows = append(d.Rows, row)
		}
	}
	a.render(c, http.StatusOK, "audit", "Audit log", "audit", d)
}
