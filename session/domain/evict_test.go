package domain

import (
	"reflect"
	"testing"
	"time"
)

func TestEvictSelectsOldestBeyondLimitAndKeepsCurrent(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	at := func(id string, m int) *Session {
		return &Session{ID: ID(id), LastSeenAt: t0.Add(time.Duration(m) * time.Minute)}
	}
	// "cur" is the oldest by LastSeenAt but must never be evicted.
	all := []*Session{at("c", 3), at("a", 1), at("cur", 0), at("b", 2), at("b2", 2), at("d", 4)}
	cases := []struct {
		max  int
		want []ID
	}{
		{0, nil},
		{-1, nil},
		{6, nil},
		{10, nil},
		{5, []ID{"a"}},
		{3, []ID{"a", "b", "b2"}},
		{1, []ID{"a", "b", "b2", "c", "d"}},
	}
	for _, c := range cases {
		if got := Evict(all, c.max, "cur"); !reflect.DeepEqual(got, c.want) {
			t.Errorf("max %d: got %v want %v", c.max, got, c.want)
		}
	}
	if all[0].ID != "c" {
		t.Fatal("Evict must not reorder the input")
	}
}
