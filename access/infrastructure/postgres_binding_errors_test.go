package infrastructure

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/bakhod1r/guard/access/domain"
)

func TestPostgresPolicyRoleStorageErrors(t *testing.T) {
	e := newPG(t)
	r, ctx := e.repo, context.Background()
	if err := r.CreateRole(ctx, &domain.Role{Name: "editor", Title: "Editor"}); err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{"DELETE FROM guard_policy_role", "INSERT INTO guard_policy_role"} {
		t.Run(marker, func(t *testing.T) {
			p := &domain.Policy{ID: uuid.Must(uuid.NewV7()).String(), Name: "p-" + uuid.NewString(), Resource: "*", Action: "*",
				Effect: domain.Allow, Roles: []string{"editor"}}
			e.tracer.failOn(marker)
			wantAnyErr(t, r.SavePolicy(ctx, p))
			e.tracer.failOn("")
			_, err := r.Policy(ctx, p.ID)
			wantErr(t, err, domain.ErrPolicyNotFound)
		})
	}
}

func TestPostgresDeleteRoleDisableBoundPoliciesFails(t *testing.T) {
	e := newPG(t)
	r, ctx := e.repo, context.Background()
	if err := r.CreateRole(ctx, &domain.Role{Name: "editor", Title: "Editor"}); err != nil {
		t.Fatal(err)
	}
	e.tracer.failOn("UPDATE guard_policy p SET enabled=false")
	wantAnyErr(t, r.DeleteRole(ctx, "editor"))
	e.tracer.failOn("")
	if _, err := r.Role(ctx, "editor"); err != nil {
		t.Fatalf("role must survive the rolled-back delete: %v", err)
	}
}
