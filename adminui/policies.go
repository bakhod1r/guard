package adminui

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	accessdomain "github.com/bakhod1r/guard/access/domain"
	identitydomain "github.com/bakhod1r/guard/identity/domain"
)

func (a *app) registerPolicies(r *gin.RouterGroup) {
	read, write := a.require("policy.read"), a.require("policy.write")
	r.GET("/policies", read, a.policiesList)
	r.GET("/policies/new", read, a.policyNew)
	r.GET("/policies/:id", read, a.policyEdit)
	r.POST("/policies", write, a.policyCreate)
	r.POST("/policies/simulate", read, a.policySimulate)
	r.POST("/policies/:id", write, a.policyUpdate)
	r.POST("/policies/:id/delete", write, a.policyDelete)
	r.POST("/policies/:id/toggle", write, a.policyToggle)
}

// describe renders a condition tree as readable text, e.g.
// (user.department eq finance AND NOT (resource.tags contains secret)).
func describe(g *accessdomain.ConditionGroup) string {
	if g == nil {
		return "always"
	}
	parts := make([]string, 0, len(g.Conditions)+len(g.Groups))
	for _, c := range g.Conditions {
		v := strings.Join(c.Value, ", ")
		if c.Operator == accessdomain.OpIn || c.Operator == accessdomain.OpNotIn {
			v = "[" + v + "]"
		}
		parts = append(parts, c.Field+" "+string(c.Operator)+" "+v)
	}
	for i := range g.Groups {
		parts = append(parts, describe(&g.Groups[i]))
	}
	sep := " AND "
	if g.Operator == accessdomain.Or {
		sep = " OR "
	}
	out := "(always)"
	if len(parts) > 0 {
		out = "(" + strings.Join(parts, sep) + ")"
	}
	if g.Negate {
		out = "NOT " + out
	}
	return out
}

type policyRow struct {
	accessdomain.Policy
	Summary string
}

type policySim struct {
	UserID, Action, ResourceType, ResourceID, Attributes, Env string
	Done, Allowed                                             bool
	Reason, Error                                             string
}

type policiesListData struct {
	Policies []policyRow
	CanWrite bool
	Sim      policySim
}

type policyFormData struct {
	ID, Name, Resource, Action, Effect, Priority, Root string
	Enabled, CanWrite                                  bool
	Error                                              string
	Fields, Operators                                  []string
	Example                                            string
}

const policyExample = `{
  "operator": "and",
  "conditions": [
    {"field": "user.department", "operator": "eq", "value": ["finance"]},
    {"field": "resource.owner_id", "operator": "eq", "value": ["$user.id"]}
  ],
  "groups": [
    {"operator": "or", "negate": true, "conditions": [
      {"field": "resource.tags", "operator": "contains", "value": ["secret"]}
    ]}
  ]
}`

func (a *app) internalError(c *gin.Context, err error) {
	a.logError(c, err)
	a.render(c, http.StatusInternalServerError, "error", "Error", "policies", map[string]string{"Message": "internal error"})
}

func (a *app) policiesList(c *gin.Context) {
	a.renderPolicies(c, http.StatusOK, policySim{})
}

func (a *app) renderPolicies(c *gin.Context, status int, sim policySim) {
	all, err := a.g.Access.ListPolicies(c.Request.Context())
	if err != nil {
		a.internalError(c, err)
		return
	}
	rows := make([]policyRow, len(all))
	for i, p := range all {
		rows[i] = policyRow{Policy: p, Summary: describe(p.Root)}
	}
	// Repositories already return policies ordered by priority, then name.
	a.render(c, status, "policies_list", "Policies", "policies",
		policiesListData{Policies: rows, CanWrite: a.can(c, "policy.write"), Sim: sim})
}

func (a *app) renderPolicyForm(c *gin.Context, status int, f policyFormData) {
	f.CanWrite = a.can(c, "policy.write")
	f.Fields = []string{"user.<attr> / subject.<attr> (id, roles, email, status, custom)", "resource.<attr> (id, type, custom)", "env.<key> (now, ip, custom)"}
	f.Operators = []string{"eq", "ne", "gt", "lt", "gte", "lte", "in", "not_in", "contains"}
	f.Example = policyExample
	title := "New policy"
	if f.ID != "" {
		title = "Edit policy"
	}
	a.render(c, status, "policies_form", title, "policies", f)
}

func (a *app) policyNew(c *gin.Context) {
	a.renderPolicyForm(c, http.StatusOK, policyFormData{Resource: "*", Action: "*", Effect: "allow", Priority: "100", Enabled: true})
}

// loadPolicy fetches :id or renders 404/500; ok=false means a response was written.
func (a *app) loadPolicy(c *gin.Context) (*accessdomain.Policy, bool) {
	p, err := a.g.Access.Policy(c.Request.Context(), c.Param("id"))
	if errors.Is(err, accessdomain.ErrPolicyNotFound) {
		a.render(c, http.StatusNotFound, "error", "Not found", "policies", map[string]string{"Message": "Policy not found."})
		return nil, false
	}
	if err != nil {
		a.internalError(c, err)
		return nil, false
	}
	return p, true
}

func (a *app) policyEdit(c *gin.Context) {
	p, ok := a.loadPolicy(c)
	if !ok {
		return
	}
	root := ""
	if p.Root != nil {
		b, _ := json.MarshalIndent(p.Root, "", "  ")
		root = string(b)
	}
	a.renderPolicyForm(c, http.StatusOK, policyFormData{ID: p.ID, Name: p.Name, Resource: p.Resource, Action: p.Action,
		Effect: string(p.Effect), Priority: strconv.Itoa(p.Priority), Enabled: p.Enabled, Root: root})
}

// decodeStrict decodes a single JSON value rejecting unknown fields and trailing data.
func decodeStrict(raw string, v any) error {
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("unexpected data after JSON value")
	}
	return nil
}

func (a *app) policySave(c *gin.Context, id, action string) {
	f := policyFormData{ID: id, Name: c.PostForm("name"), Resource: strings.TrimSpace(c.PostForm("resource")),
		Action: strings.TrimSpace(c.PostForm("action")), Effect: c.PostForm("effect"),
		Priority: strings.TrimSpace(c.PostForm("priority")), Root: c.PostForm("root"), Enabled: c.PostForm("enabled") != ""}
	p, err := parsePolicy(f)
	if err == nil {
		err = a.g.Access.SavePolicy(c.Request.Context(), p)
	}
	if err != nil {
		if !isDomainError(err) {
			a.internalError(c, err)
			return
		}
		f.Error = err.Error()
		a.renderPolicyForm(c, http.StatusUnprocessableEntity, f)
		return
	}
	a.audit(c, action, p.ID, map[string]any{"name": p.Name})
	a.redirect(c, "/policies", "Policy saved")
}

func parsePolicy(f policyFormData) (*accessdomain.Policy, error) {
	prio := 0
	if f.Priority != "" {
		n, err := strconv.Atoi(f.Priority)
		if err != nil {
			return nil, fmt.Errorf("%w: priority must be an integer", errBadInput)
		}
		prio = n
	}
	p := &accessdomain.Policy{ID: f.ID, Name: strings.TrimSpace(f.Name), Resource: f.Resource, Action: f.Action,
		Effect: accessdomain.Effect(f.Effect), Priority: prio, Enabled: f.Enabled}
	if strings.TrimSpace(f.Root) != "" {
		p.Root = &accessdomain.ConditionGroup{}
		if err := decodeStrict(f.Root, p.Root); err != nil {
			return nil, fmt.Errorf("%w: condition JSON: %v", errBadInput, err)
		}
	}
	return p, nil
}

func (a *app) policyCreate(c *gin.Context) { a.policySave(c, "", "policy.create") }

func (a *app) policyUpdate(c *gin.Context) {
	p, ok := a.loadPolicy(c)
	if !ok {
		return
	}
	a.policySave(c, p.ID, "policy.update")
}

func (a *app) policyDelete(c *gin.Context) {
	id := c.Param("id")
	if err := a.g.Access.DeletePolicy(c.Request.Context(), id); err != nil {
		a.fail(c, "/policies", err)
		return
	}
	a.audit(c, "policy.delete", id, nil)
	a.redirect(c, "/policies", "Policy deleted")
}

func (a *app) policyToggle(c *gin.Context) {
	ctx := c.Request.Context()
	p, err := a.g.Access.Policy(ctx, c.Param("id"))
	if err == nil {
		p.Enabled = !p.Enabled
		err = a.g.Access.SavePolicy(ctx, p)
	}
	if err != nil {
		a.fail(c, "/policies", err)
		return
	}
	a.audit(c, "policy.toggle", p.ID, map[string]any{"enabled": p.Enabled})
	a.redirect(c, "/policies", "Policy "+map[bool]string{true: "enabled", false: "disabled"}[p.Enabled])
}

func decodeObject(raw, what string) (map[string]any, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var m map[string]any
	dec := json.NewDecoder(bytes.NewBufferString(raw))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("%w: %s must be a JSON object: %v", errBadInput, what, err)
	}
	return m, nil
}

func (a *app) policySimulate(c *gin.Context) {
	sim := policySim{UserID: strings.TrimSpace(c.PostForm("user_id")), Action: strings.TrimSpace(c.PostForm("action")),
		ResourceType: strings.TrimSpace(c.PostForm("resource_type")), ResourceID: strings.TrimSpace(c.PostForm("resource_id")),
		Attributes: c.PostForm("resource_attributes"), Env: c.PostForm("env")}
	d, err := a.simulate(c, sim)
	if err != nil {
		sim.Error = "internal error"
		if isDomainError(err) {
			sim.Error = err.Error()
		} else {
			a.logError(c, err)
		}
		a.renderPolicies(c, http.StatusUnprocessableEntity, sim)
		return
	}
	sim.Done, sim.Allowed, sim.Reason = true, d.Allowed, d.Reason
	a.renderPolicies(c, http.StatusOK, sim)
}

func (a *app) simulate(c *gin.Context, sim policySim) (accessdomain.Decision, error) {
	ctx := c.Request.Context()
	attrs, err := decodeObject(sim.Attributes, "resource attributes")
	if err != nil {
		return accessdomain.Decision{}, err
	}
	env, err := decodeObject(sim.Env, "env")
	if err != nil {
		return accessdomain.Decision{}, err
	}
	u, err := a.g.Identity.User(ctx, identitydomain.UserID(sim.UserID))
	if err != nil {
		return accessdomain.Decision{}, err
	}
	subject := map[string]any{}
	for k, v := range u.Attributes {
		subject[k] = v
	}
	subject["email"], subject["status"] = string(u.Email), string(u.Status)
	// Roles nil: Access.Authorize loads the user's active roles (ActiveRoles).
	return a.g.Access.Authorize(ctx, accessdomain.Request{
		Subject:     accessdomain.Subject{ID: string(u.ID), Attributes: subject},
		Action:      sim.Action,
		Resource:    accessdomain.Resource{Type: sim.ResourceType, ID: sim.ResourceID, Attributes: attrs},
		Environment: env,
	})
}
