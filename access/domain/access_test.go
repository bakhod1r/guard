package domain

import (
	"testing"
	"time"
)

func TestParsePermission(t *testing.T) {
	p, err := ParsePermission("user.read")
	if err != nil || p.Resource != "user" || p.Action != "read" || p.Code() != "user.read" {
		t.Fatal(p, err)
	}
	for _, bad := range []string{"user", ".read", "user.", "User.Read", "a.b.c"} {
		if _, err := ParsePermission(bad); err != ErrInvalidPermission {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestRoleAllows(t *testing.T) {
	admin := Role{Name: "admin", Wildcard: true}
	editor := Role{Name: "editor", Permissions: []Permission{{Resource: "doc", Action: "read"}}}
	if !admin.Allows("anything", "delete") {
		t.Fatal("wildcard role must allow all")
	}
	if !editor.Allows("doc", "read") || editor.Allows("doc", "delete") {
		t.Fatal("permission matching wrong")
	}
}

func TestRoleGrantExpiry(t *testing.T) {
	now := time.Now()
	past := now.Add(-time.Minute)
	if (RoleGrant{ExpiresAt: &past}).Active(now) {
		t.Fatal("expired grant active")
	}
	if !(RoleGrant{}).Active(now) {
		t.Fatal("permanent grant inactive")
	}
}

func req(action string) Request {
	return Request{
		Subject: Subject{ID: "u1", Roles: []Role{{Name: "editor", Permissions: []Permission{{Resource: "doc", Action: "read"}}}},
			Attributes: map[string]any{"department": "sales", "level": 3.0, "status": "active"}},
		Action:      action,
		Resource:    Resource{Type: "doc", ID: "d1", Attributes: map[string]any{"owner_id": "u1", "department": "sales", "tags": []any{"public"}}},
		Environment: map[string]any{"ip_trusted": true},
	}
}

func cond(field string, op Operator, v ...string) Condition {
	return Condition{Field: field, Operator: op, Value: v}
}

func TestDecideRBACFallback(t *testing.T) {
	if !Decide(req("read"), nil).Allowed {
		t.Fatal("role permission ignored")
	}
	if Decide(req("delete"), nil).Allowed {
		t.Fatal("default must be deny")
	}
}

func TestDecideSelfService(t *testing.T) {
	self := Policy{Name: "self", Resource: "doc", Action: "write", Effect: Allow, Priority: 100, Enabled: true,
		Root: &ConditionGroup{Operator: And, Conditions: []Condition{cond("resource.owner_id", OpEq, "$user.id")}}}
	r := req("write")
	if !Decide(r, []Policy{self}).Allowed {
		t.Fatal("owner denied")
	}
	r.Subject.ID = "u2"
	if Decide(r, []Policy{self}).Allowed {
		t.Fatal("non-owner allowed")
	}
	self.Enabled = false
	r.Subject.ID = "u1"
	if Decide(r, []Policy{self}).Allowed {
		t.Fatal("disabled policy applied")
	}
}

func TestDecidePriorityAndDenyOverrides(t *testing.T) {
	admin := req("delete")
	admin.Subject.Roles = []Role{{Name: "admin", Wildcard: true}}
	admin.Subject.Attributes["status"] = "banned"

	blocked := Policy{Name: "blocked", Resource: "*", Action: "*", Effect: Deny, Priority: 10, Enabled: true,
		Root: &ConditionGroup{Conditions: []Condition{cond("user.status", OpIn, "banned", "suspended")}}}
	allowAll := Policy{Name: "allow-all", Resource: "*", Action: "*", Effect: Allow, Priority: 100, Enabled: true}

	d := Decide(admin, []Policy{allowAll, blocked})
	if d.Allowed || d.Reason != "denied by policy blocked" {
		t.Fatalf("stronger deny ignored: %+v", d)
	}

	sameTier := allowAll
	sameTier.Priority = 10
	if Decide(admin, []Policy{sameTier, blocked}).Allowed {
		t.Fatal("deny must override allow at equal priority")
	}

	strongAllow := allowAll
	strongAllow.Priority = 1
	if !Decide(admin, []Policy{blocked, strongAllow}).Allowed {
		t.Fatal("stronger allow must win")
	}

	admin.Subject.Attributes["status"] = "active"
	if !Decide(admin, []Policy{blocked}).Allowed {
		t.Fatal("active admin must fall back to RBAC wildcard")
	}
}

func TestConditionOperators(t *testing.T) {
	r := req("read")
	ok := []Condition{
		cond("user.department", OpEq, "$resource.department"),
		cond("subject.level", OpGte, "3"),
		cond("subject.level", OpLt, "4.5"),
		cond("user.department", OpIn, "sales", "hr"),
		cond("user.department", OpNotIn, "hr"),
		cond("resource.tags", OpContains, "public"),
		cond("user.roles", OpContains, "editor"),
		cond("env.ip_trusted", OpEq, "true"),
		cond("resource.type", OpNe, "user"),
	}
	for _, c := range ok {
		if !c.holds(r) {
			t.Errorf("expected %+v to hold", c)
		}
	}
	bad := []Condition{
		cond("user.missing", OpEq, "x"),
		cond("subject.level", OpGt, "abc"),
		cond("user.department", OpEq, "$user.missing"),
	}
	for _, c := range bad {
		if c.holds(r) {
			t.Errorf("expected %+v to fail", c)
		}
	}
}

func TestConditionTree(t *testing.T) {
	r := req("read")
	// (department = hr OR level >= 3) AND NOT(tags contains secret)
	tree := ConditionGroup{Operator: And, Groups: []ConditionGroup{
		{Operator: Or, Conditions: []Condition{cond("user.department", OpEq, "hr"), cond("user.level", OpGte, "3")}},
		{Operator: And, Negate: true, Conditions: []Condition{cond("resource.tags", OpContains, "secret")}},
	}}
	if !tree.holds(r, 1) {
		t.Fatal("tree should hold")
	}
	r.Resource.Attributes["tags"] = []any{"secret"}
	if tree.holds(r, 1) {
		t.Fatal("negated group ignored")
	}
}

func TestDepthFailClosed(t *testing.T) {
	g := ConditionGroup{}
	for i := 0; i < MaxConditionDepth+1; i++ {
		g = ConditionGroup{Groups: []ConditionGroup{g}}
	}
	if g.holds(req("read"), 1) {
		t.Fatal("too deep tree must be false")
	}
	p := Policy{Name: "deep", Resource: "*", Action: "*", Effect: Allow, Root: &g}
	if p.Validate() == nil {
		t.Fatal("too deep tree must fail validation")
	}
}

func TestPolicyValidate(t *testing.T) {
	p := Policy{Name: "x", Effect: Allow, Resource: "doc", Action: "read",
		Root: &ConditionGroup{Conditions: []Condition{cond("foo.bar", OpEq, "1")}}}
	if p.Validate() == nil {
		t.Fatal("bad field accepted")
	}
	p.Root.Conditions[0] = cond("user.bar", OpEq, "1", "2")
	if p.Validate() == nil {
		t.Fatal("scalar operator with two values accepted")
	}
	p.Root.Conditions[0] = cond("user.bar", OpIn, "1", "2")
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
}
