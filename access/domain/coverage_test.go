package domain

import (
	"errors"
	"testing"
)

func TestNewRoleDefaultsTitleAndRejectsBadName(t *testing.T) {
	r, err := NewRole("editor", "  ", "d", true)
	if err != nil || r.Title != "editor" || !r.Wildcard || r.Permissions == nil {
		t.Fatalf("got %+v %v", r, err)
	}
	r, err = NewRole("editor", "Editor", "", false)
	if err != nil || r.Title != "Editor" {
		t.Fatalf("got %+v %v", r, err)
	}
	if _, err := NewRole("Bad Name", "", "", false); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("want ErrInvalidName, got %v", err)
	}
}

func TestPermissionAllowsOwnCode(t *testing.T) {
	if !(Permission{Resource: "a", Action: "b"}).Allows("a", "b") {
		t.Fatal("permission must allow its own code")
	}
}

func TestPolicyValidateErrors(t *testing.T) {
	ok := func() Policy { return Policy{Name: "p", Effect: Deny, Resource: "*", Action: "read"} }
	cases := map[string]func(p *Policy){
		"bad effect":         func(p *Policy) { p.Effect = "maybe" },
		"empty name":         func(p *Policy) { p.Name = " " },
		"bad resource":       func(p *Policy) { p.Resource = "Doc!" },
		"bad action":         func(p *Policy) { p.Action = "" },
		"bad group operator": func(p *Policy) { p.Root = &ConditionGroup{Operator: "xor"} },
		"unknown operator":   func(p *Policy) { p.Root = &ConditionGroup{Conditions: []Condition{cond("user.a", "like", "x")}} },
		"empty value":        func(p *Policy) { p.Root = &ConditionGroup{Conditions: []Condition{cond("user.a", OpEq)}} },
		"bad nested group": func(p *Policy) {
			p.Root = &ConditionGroup{Operator: Or, Groups: []ConditionGroup{{Operator: "nand"}}}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := ok()
			mutate(&p)
			if err := p.Validate(); !errors.Is(err, ErrInvalidPolicy) {
				t.Fatalf("want ErrInvalidPolicy, got %v", err)
			}
		})
	}
	p := ok()
	if err := p.Validate(); err != nil {
		t.Fatalf("valid policy without root rejected: %v", err)
	}
	p.Root = &ConditionGroup{Groups: []ConditionGroup{{}}}
	if err := p.Validate(); err != nil || p.Root.Operator != And {
		t.Fatalf("empty group operator must default to and: %v %q", err, p.Root.Operator)
	}
}

func TestPolicyMatchesTargets(t *testing.T) {
	r := req("read")
	p := Policy{Resource: "user", Action: "*", Enabled: true}
	if p.Matches(r) {
		t.Fatal("other resource matched")
	}
	p = Policy{Resource: "*", Action: "write", Enabled: true}
	if p.Matches(r) {
		t.Fatal("other action matched")
	}
	p = Policy{Resource: "doc", Action: "read", Enabled: true}
	if !p.Matches(r) {
		t.Fatal("no-root policy must match target")
	}
}

func TestOrGroupFallsThroughToSubgroups(t *testing.T) {
	r := req("read")
	g := ConditionGroup{Operator: Or,
		Conditions: []Condition{cond("user.department", OpEq, "hr")},
		Groups:     []ConditionGroup{{Conditions: []Condition{cond("user.id", OpEq, "u1")}}}}
	if !g.holds(r, 1) {
		t.Fatal("or must be satisfied by subgroup")
	}
	g.Groups[0].Conditions[0] = cond("user.id", OpEq, "u9")
	if g.holds(r, 1) {
		t.Fatal("or with no true member must fail")
	}
}

func TestLookupAndDig(t *testing.T) {
	r := req("read")
	r.Subject.Attributes["org"] = map[string]any{"team": map[string]any{"name": "core"}, "nil": nil}
	cases := []struct {
		path string
		want any
		ok   bool
	}{
		{"resource.type", "doc", true},
		{"resource.id", "d1", true},
		{"subject.id", "u1", true},
		{"user.org.team.name", "core", true},
		{"user.org.team.name.deeper", nil, false}, // dig into non-map
		{"user.org.nil", nil, false},              // nil value not found
		{"user.org.absent", nil, false},
		{"other.x", nil, false},
	}
	for _, c := range cases {
		got, ok := r.lookup(c.path)
		if ok != c.ok || (c.ok && got != c.want) {
			t.Errorf("%s: got %v %v", c.path, got, ok)
		}
	}
}

func TestToFloatNumericTypes(t *testing.T) {
	for _, v := range []any{float64(2), float32(2), int(2), int32(2), int64(2), uint(2), uint64(2), "2"} {
		if f, ok := toFloat(v); !ok || f != 2 {
			t.Errorf("%T: %v %v", v, f, ok)
		}
	}
	for _, v := range []any{"x", true, nil, int8(1)} {
		if _, ok := toFloat(v); ok {
			t.Errorf("%T accepted", v)
		}
	}
}

func TestEqualContainsCompare(t *testing.T) {
	if !equal(int64(3), "3.0") || equal("a", "b") || !equal(true, "true") {
		t.Fatal("equal wrong")
	}
	if !contains([]string{"a", "b"}, "b") || contains([]string{"a"}, "z") {
		t.Fatal("[]string contains wrong")
	}
	if !contains("hello world", "lo w") || contains("hello", "zz") || contains("hello", 1) {
		t.Fatal("string contains wrong")
	}
	if contains([]any{"a"}, "z") || contains(42, 4) {
		t.Fatal("contains wrong")
	}
	strCases := []struct {
		op   Operator
		a, b string
		want bool
	}{
		{OpGt, "10:30", "09:00", true},
		{OpGte, "09:00", "09:00", true},
		{OpLt, "2026-01-01T00:00:00Z", "2026-02-01T00:00:00Z", true},
		{OpLte, "b", "a", false},
	}
	for _, c := range strCases {
		if compare(c.op, c.a, c.b) != c.want {
			t.Errorf("compare %s %q %q", c.op, c.a, c.b)
		}
	}
	if !compare(OpLte, 1, 2) || compare(OpGt, true, 1) || compare(OpEq, 1, 1) {
		t.Fatal("compare numeric/non-comparable/unknown operator wrong")
	}
}

func TestConditionHoldsEdgeCases(t *testing.T) {
	r := req("read")
	holds := []Condition{
		cond("user.id", OpNotIn, "$user.missing", "u2"),
		cond("user.department", OpIn, "$resource.tags", "sales"),
		cond("user.department", OpContains, "ale"),
	}
	for _, c := range holds {
		if !c.holds(r) {
			t.Errorf("expected %+v to hold", c)
		}
	}
	fails := []Condition{
		{Field: "user.id", Operator: OpEq},
		cond("user.id", "like", "u1"),
		cond("user.id", OpNe, "u1"),
	}
	for _, c := range fails {
		if c.holds(r) {
			t.Errorf("expected %+v to fail", c)
		}
	}
}
