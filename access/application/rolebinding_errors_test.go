package application

import (
	"context"
	"errors"
	"testing"

	"github.com/bakhod1r/guard/access/domain"
	"github.com/bakhod1r/guard/access/infrastructure"
)

// bindFail wraps Memory and fails the chosen calls once armed.
type bindFail struct {
	*infrastructure.Memory
	list, save bool
	roleErr    string // Role(name) fails with errBoom
}

func (b *bindFail) ListPolicies(ctx context.Context) ([]domain.Policy, error) {
	if b.list {
		return nil, errBoom
	}
	return b.Memory.ListPolicies(ctx)
}

func (b *bindFail) SavePolicy(ctx context.Context, p *domain.Policy) error {
	if b.save {
		return errBoom
	}
	return b.Memory.SavePolicy(ctx, p)
}

func (b *bindFail) Role(ctx context.Context, n string) (*domain.Role, error) {
	if n == b.roleErr {
		return nil, errBoom
	}
	return b.Memory.Role(ctx, n)
}

func legacyPolicy(role string) *domain.Policy {
	gate := domain.ConditionGroup{Operator: domain.Or, Conditions: []domain.Condition{
		{Field: "user.roles", Operator: domain.OpContains, Value: []string{role}}}}
	return &domain.Policy{Name: "legacy", Resource: "post", Action: "edit", Effect: domain.Allow, Enabled: true,
		Root: &domain.ConditionGroup{Operator: domain.And, Groups: []domain.ConditionGroup{gate}}}
}

func newBindFail(t *testing.T) (*Service, *bindFail) {
	t.Helper()
	m := &bindFail{Memory: infrastructure.NewMemory()}
	s := NewService(m, m)
	if _, err := s.CreateRole(context.Background(), "editor", "editor", "", false); err != nil {
		t.Fatal(err)
	}
	if err := s.SavePolicy(context.Background(), legacyPolicy("editor")); err != nil {
		t.Fatal(err)
	}
	return s, m
}

func TestListPoliciesForRoleListError(t *testing.T) {
	s, m := newBindFail(t)
	m.list = true
	if _, err := s.ListPoliciesForRole(context.Background(), "editor"); !errors.Is(err, errBoom) {
		t.Fatalf("err: %v", err)
	}
}

func TestMigrateRoleConditionsErrors(t *testing.T) {
	ctx := context.Background()

	s, m := newBindFail(t)
	m.list = true
	if _, err := s.MigrateRoleConditions(ctx); !errors.Is(err, errBoom) {
		t.Fatalf("list: %v", err)
	}

	s, m = newBindFail(t)
	m.roleErr = "editor"
	if _, err := s.MigrateRoleConditions(ctx); !errors.Is(err, errBoom) {
		t.Fatalf("role lookup: %v", err)
	}

	s, m = newBindFail(t)
	m.save = true
	if _, err := s.MigrateRoleConditions(ctx); !errors.Is(err, errBoom) {
		t.Fatalf("save: %v", err)
	}
}
