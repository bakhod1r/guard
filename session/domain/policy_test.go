package domain

import (
	"errors"
	"testing"
	"time"
)

func TestDefaultPolicy(t *testing.T) {
	p := DefaultPolicy()
	if p.IdleTimeout != 30*time.Minute || p.AbsoluteTimeout != 7*24*time.Hour {
		t.Fatalf("unexpected default policy %+v", p)
	}
}

func TestValidExpiryBranches(t *testing.T) {
	p := Policy{IdleTimeout: 10 * time.Minute, AbsoluteTimeout: time.Hour}
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		now  time.Time
		want error
	}{
		{"alive", t0.Add(time.Minute), nil},
		{"exactly at absolute expiry", t0.Add(time.Hour), ErrSessionExpired},
		{"idle exactly at timeout", t0.Add(10 * time.Minute), ErrSessionExpired},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := &Session{CreatedAt: t0, LastSeenAt: t0, ExpiresAt: t0.Add(time.Hour)}
			if c.name == "exactly at absolute expiry" {
				s.LastSeenAt = c.now // keep idle fresh
			}
			if err := s.Valid(c.now, p); !errors.Is(err, c.want) && err != c.want {
				t.Fatalf("want %v got %v", c.want, err)
			}
		})
	}
}

func TestTTLCappedByIdle(t *testing.T) {
	p := Policy{IdleTimeout: 10 * time.Minute, AbsoluteTimeout: time.Hour}
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s, _ := New("u", t0, p)
	if got := s.TTL(t0, p); got != 10*time.Minute {
		t.Fatalf("got %v", got)
	}
}
