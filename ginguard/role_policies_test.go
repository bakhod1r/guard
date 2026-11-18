package ginguard_test

import (
	"context"
	"testing"
)

func TestRolePoliciesListsBoundAndGlobal(t *testing.T) {
	e := newEnv(t, envConfig{createUser: func(context.Context, string) (string, error) { return "77", nil }})
	r := e.do("GET", "/guard/roles/user/policies", e.admin, nil)
	if r.code != 200 {
		t.Fatalf("role policies: %d %v", r.code, r.body)
	}
	if _, ok := r.body["policies"].([]any); !ok {
		t.Fatalf("body: %v", r.body)
	}
}
