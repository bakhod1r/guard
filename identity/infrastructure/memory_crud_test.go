package infrastructure

import (
	"context"
	"errors"
	"testing"

	"github.com/bakhod1r/guard/identity/domain"
)

func TestMemoryUsersCRUD(t *testing.T) {
	ctx := context.Background()
	m := NewMemoryUsers()
	u := &domain.User{ID: "1", Email: "a@b.uz", Status: domain.StatusActive}
	if err := m.Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	if err := m.Create(ctx, &domain.User{ID: "1", Email: "z@b.uz"}); !errors.Is(err, domain.ErrAccountExists) {
		t.Fatalf("dup id: %v", err)
	}
	if err := m.Create(ctx, &domain.User{ID: "2", Email: "a@b.uz"}); !errors.Is(err, domain.ErrEmailTaken) {
		t.Fatalf("dup email: %v", err)
	}
	u.Status = domain.StatusBanned
	if err := m.Update(ctx, u); err != nil {
		t.Fatal(err)
	}
	if err := m.Update(ctx, &domain.User{ID: "missing"}); !errors.Is(err, domain.ErrUserNotFound) {
		t.Fatalf("update missing: %v", err)
	}
	if got, err := m.ByID(ctx, "1"); err != nil || got.Status != domain.StatusBanned {
		t.Fatalf("by id: %+v %v", got, err)
	}
	if _, err := m.ByID(ctx, "missing"); !errors.Is(err, domain.ErrUserNotFound) {
		t.Fatalf("by id missing: %v", err)
	}
	if got, err := m.ByEmail(ctx, "a@b.uz"); err != nil || got.ID != "1" {
		t.Fatalf("by email: %+v %v", got, err)
	}
	if _, err := m.ByEmail(ctx, "no@b.uz"); !errors.Is(err, domain.ErrUserNotFound) {
		t.Fatalf("by email missing: %v", err)
	}
}
