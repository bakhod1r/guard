package domain

import (
	"fmt"
	"strconv"
	"strings"
)

func (g *ConditionGroup) holds(r Request, depth int) bool {
	if depth > MaxConditionDepth {
		return false // fail-closed
	}
	var result bool
	if g.Operator == Or {
		result = false
		for _, c := range g.Conditions {
			if c.holds(r) {
				result = true
				break
			}
		}
		for i := 0; !result && i < len(g.Groups); i++ {
			result = g.Groups[i].holds(r, depth+1)
		}
	} else {
		result = true
		for _, c := range g.Conditions {
			if !c.holds(r) {
				result = false
				break
			}
		}
		for i := 0; result && i < len(g.Groups); i++ {
			result = g.Groups[i].holds(r, depth+1)
		}
	}
	return result != g.Negate
}

func (r Request) lookup(path string) (any, bool) {
	scope, key, _ := strings.Cut(path, ".")
	switch scope {
	case "user", "subject":
		switch key {
		case "id":
			return r.Subject.ID, true
		case "roles":
			out := make([]any, len(r.Subject.Roles))
			for i, v := range r.Subject.Roles {
				out[i] = v.Name
			}
			return out, true
		}
		return dig(r.Subject.Attributes, key)
	case "resource":
		switch key {
		case "id":
			return r.Resource.ID, true
		case "type":
			return r.Resource.Type, true
		}
		return dig(r.Resource.Attributes, key)
	case "env":
		return dig(r.Environment, key)
	}
	return nil, false
}

// dig resolves dotted keys through nested maps.
func dig(m map[string]any, key string) (any, bool) {
	var cur any = m
	for _, part := range strings.Split(key, ".") {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		if cur, ok = mm[part]; !ok {
			return nil, false
		}
	}
	return cur, cur != nil
}

// operand resolves "$path" references; plain values stay literal strings.
func (r Request) operand(v string) (any, bool) {
	if strings.HasPrefix(v, "$") {
		return r.lookup(v[1:])
	}
	return v, true
}

func (c Condition) holds(r Request) bool {
	left, ok := r.lookup(c.Field)
	if !ok || len(c.Value) == 0 {
		return false
	}
	switch c.Operator {
	case OpIn, OpNotIn:
		found := false
		for _, v := range c.Value {
			right, ok := r.operand(v)
			if ok && (equal(left, right) || contains(right, left)) {
				found = true
				break
			}
		}
		return found == (c.Operator == OpIn)
	}
	right, ok := r.operand(c.Value[0])
	if !ok {
		return false
	}
	switch c.Operator {
	case OpEq:
		return equal(left, right)
	case OpNe:
		return !equal(left, right)
	case OpContains:
		return contains(left, right)
	case OpGt, OpGte, OpLt, OpLte:
		return compare(c.Operator, left, right)
	}
	return false
}

func toFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int32:
		return float64(n), true
	case int64:
		return float64(n), true
	case uint:
		return float64(n), true
	case uint64:
		return float64(n), true
	case string:
		f, err := strconv.ParseFloat(n, 64)
		return f, err == nil
	}
	return 0, false
}

func equal(a, b any) bool {
	fa, okA := toFloat(a)
	fb, okB := toFloat(b)
	if okA && okB {
		return fa == fb
	}
	return fmt.Sprint(a) == fmt.Sprint(b)
}

func contains(list, v any) bool {
	switch l := list.(type) {
	case []any:
		for _, x := range l {
			if equal(x, v) {
				return true
			}
		}
	case []string:
		for _, x := range l {
			if equal(x, v) {
				return true
			}
		}
	case string:
		s, ok := v.(string)
		return ok && strings.Contains(l, s)
	}
	return false
}

func compare(op Operator, a, b any) bool {
	fa, okA := toFloat(a)
	fb, okB := toFloat(b)
	if !okA || !okB {
		sa, okA := a.(string)
		sb, okB := b.(string)
		if !okA || !okB {
			return false
		}
		// Lexical order: valid for RFC3339 timestamps and "HH:MM" clock times.
		fa, fb = float64(strings.Compare(sa, sb)), 0
	}
	switch op {
	case OpGt:
		return fa > fb
	case OpGte:
		return fa >= fb
	case OpLt:
		return fa < fb
	case OpLte:
		return fa <= fb
	}
	return false
}
