package domain

import (
	"errors"
	"reflect"
	"testing"
)

func TestValidateNormalizesRoles(t *testing.T) {
	p := Policy{Name: "x", Resource: "*", Action: "*", Effect: Allow, Roles: []string{"editor", "author", "editor"}}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(p.Roles, []string{"author", "editor"}) {
		t.Fatalf("roles = %v", p.Roles)
	}
	for _, bad := range []string{"", "A", "x", "has space"} {
		p := Policy{Name: "x", Resource: "*", Action: "*", Effect: Allow, Roles: []string{bad}}
		if err := p.Validate(); !errors.Is(err, ErrInvalidPolicy) {
			t.Fatalf("role %q: want ErrInvalidPolicy, got %v", bad, err)
		}
	}
	empty := Policy{Name: "x", Resource: "*", Action: "*", Effect: Allow, Roles: []string{}}
	if err := empty.Validate(); err != nil || empty.Roles != nil {
		t.Fatalf("empty roles: %v %v", err, empty.Roles)
	}
}

func TestAppliesToRole(t *testing.T) {
	global := Policy{}
	bound := Policy{Roles: []string{"editor"}}
	if !global.AppliesToRole("anyone") || !bound.AppliesToRole("editor") || bound.AppliesToRole("author") {
		t.Fatal("AppliesToRole")
	}
}

func TestDecideRoleBinding(t *testing.T) {
	deny := Policy{Name: "editors denied", Resource: "post", Action: "delete", Effect: Deny, Enabled: true, Roles: []string{"editor"}}
	req := func(roles ...Role) Request {
		return Request{Subject: Subject{ID: "1", Roles: roles}, Action: "delete", Resource: Resource{Type: "post"}}
	}
	editor := Role{Name: "editor", Permissions: []Permission{{Resource: "post", Action: "delete"}}}
	author := Role{Name: "author", Permissions: []Permission{{Resource: "post", Action: "delete"}}}
	admin := Role{Name: "admin", Wildcard: true}

	if d := Decide(req(editor), []Policy{deny}); d.Allowed {
		t.Fatal("bound deny must apply to editor")
	}
	if d := Decide(req(author), []Policy{deny}); !d.Allowed {
		t.Fatalf("bound deny must skip author: %s", d.Reason)
	}
	// Wildcard roles do not match a binding implicitly.
	if d := Decide(req(admin), []Policy{deny}); !d.Allowed {
		t.Fatalf("binding must not match wildcard role: %s", d.Reason)
	}
	// Unbound policy applies to everyone.
	deny.Roles = nil
	if d := Decide(req(author), []Policy{deny}); d.Allowed {
		t.Fatal("unbound deny must apply to everyone")
	}
}

func rolesContains(roles ...string) ConditionGroup {
	g := ConditionGroup{Operator: Or}
	for _, r := range roles {
		g.Conditions = append(g.Conditions, Condition{Field: "user.roles", Operator: OpContains, Value: []string{r}})
	}
	return g
}

func TestLiftRoleConditions(t *testing.T) {
	body := ConditionGroup{Operator: And, Conditions: []Condition{{Field: "resource.owner_id", Operator: OpEq, Value: []string{"$user.id"}}}}

	p := Policy{Root: &ConditionGroup{Operator: And, Groups: []ConditionGroup{rolesContains("editor", "author"), body}}}
	if !LiftRoleConditions(&p) {
		t.Fatal("legacy shape with body not lifted")
	}
	if !reflect.DeepEqual(p.Roles, []string{"author", "editor"}) || !reflect.DeepEqual(*p.Root, body) {
		t.Fatalf("got roles=%v root=%+v", p.Roles, p.Root)
	}
	if LiftRoleConditions(&p) {
		t.Fatal("second run must be a no-op")
	}

	only := Policy{Root: &ConditionGroup{Operator: And, Groups: []ConditionGroup{rolesContains("editor")}}}
	if !LiftRoleConditions(&only) || only.Root != nil || !reflect.DeepEqual(only.Roles, []string{"editor"}) {
		t.Fatalf("legacy shape without body: %+v", only)
	}

	negated := rolesContains("editor")
	negated.Negate = true
	andGate := rolesContains("editor")
	andGate.Operator = And
	nested := rolesContains("editor")
	nested.Groups = []ConditionGroup{body}
	other := rolesContains("editor")
	other.Conditions = append(other.Conditions, Condition{Field: "user.department", Operator: OpContains, Value: []string{"x"}})
	multi := rolesContains("editor")
	multi.Conditions[0].Value = []string{"editor", "author"}
	untouched := []*ConditionGroup{
		nil,
		{Operator: And, Groups: []ConditionGroup{negated, body}},
		{Operator: And, Groups: []ConditionGroup{andGate, body}},
		{Operator: And, Groups: []ConditionGroup{nested}},
		{Operator: And, Groups: []ConditionGroup{other, body}},
		{Operator: And, Groups: []ConditionGroup{multi}},
		{Operator: Or, Groups: []ConditionGroup{rolesContains("editor"), body}},
		{Operator: And, Negate: true, Groups: []ConditionGroup{rolesContains("editor"), body}},
		{Operator: And, Conditions: body.Conditions, Groups: []ConditionGroup{rolesContains("editor")}},
		{Operator: And, Groups: []ConditionGroup{rolesContains("editor"), body, body}},
		{Operator: And, Groups: []ConditionGroup{body, rolesContains("editor")}},
	}
	for i, root := range untouched {
		p := Policy{Root: root}
		if LiftRoleConditions(&p) || p.Roles != nil || p.Root != root {
			t.Fatalf("shape %d must stay untouched", i)
		}
	}
	bound := Policy{Roles: []string{"x1"}, Root: &ConditionGroup{Operator: And, Groups: []ConditionGroup{rolesContains("editor")}}}
	if LiftRoleConditions(&bound) {
		t.Fatal("already bound policy must stay untouched")
	}
}
