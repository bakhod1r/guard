package infrastructure

import (
	"context"
	"testing"
	"time"

	"github.com/bakhod1r/guard/identity/domain"
)

func TestMemoryList(t *testing.T) {
	ctx := context.Background()
	m := NewMemoryUsers()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	seed := []domain.User{
		{ID: "b", Email: "Bob@x.uz", Status: domain.StatusActive, CreatedAt: base},
		{ID: "a", Email: "alice@x.uz", Status: domain.StatusActive, CreatedAt: base},
		{ID: "z9", Email: "carol@y.uz", Status: domain.StatusBanned, CreatedAt: base.Add(time.Hour)},
	}
	for i := range seed {
		if err := m.Create(ctx, &seed[i]); err != nil {
			t.Fatal(err)
		}
	}
	ids := func(us []domain.User) string {
		s := ""
		for _, u := range us {
			s += string(u.ID)
		}
		return s
	}
	cases := []struct {
		q     domain.ListQuery
		want  string
		total int
	}{
		{domain.ListQuery{Limit: 10}, "z9ab", 3},
		{domain.ListQuery{Limit: 1, Offset: 1}, "a", 3},
		{domain.ListQuery{Limit: 10, Offset: 5}, "", 3},
		{domain.ListQuery{Limit: 10, Search: "BOB"}, "b", 1},
		{domain.ListQuery{Limit: 10, Search: "x.uz"}, "ab", 2},
		{domain.ListQuery{Limit: 10, Search: "z9"}, "z9", 1},
		{domain.ListQuery{Limit: 10, Status: domain.StatusActive}, "ab", 2},
		{domain.ListQuery{Limit: 10, Search: "y.uz", Status: domain.StatusActive}, "", 0},
	}
	for _, tc := range cases {
		got, total, err := m.List(ctx, tc.q)
		if err != nil || ids(got) != tc.want || total != tc.total {
			t.Fatalf("%+v: got %q %d %v want %q %d", tc.q, ids(got), total, err, tc.want, tc.total)
		}
	}
}

func TestEscapeLike(t *testing.T) {
	if got := escapeLike(`50%_a\b`); got != `50\%\_a\\b` {
		t.Fatalf("escape: %q", got)
	}
}
