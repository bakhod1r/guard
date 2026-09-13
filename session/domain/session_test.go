package domain

import (
	"testing"
	"time"
)

func TestSessionLifetime(t *testing.T) {
	p := Policy{IdleTimeout: 10 * time.Minute, AbsoluteTimeout: time.Hour}
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s, tok, err := New("u1", t0, p)
	if err != nil {
		t.Fatal(err)
	}
	if s.ID != tok.ID() || string(s.ID) == string(tok) {
		t.Fatal("session id must be hash of token")
	}
	if s.Valid(t0.Add(9*time.Minute), p) != nil {
		t.Fatal("fresh session invalid")
	}
	if s.Valid(t0.Add(10*time.Minute), p) != ErrSessionExpired {
		t.Fatal("idle session still valid")
	}
	for m := 9; m < 60; m += 9 {
		s.Touch(t0.Add(time.Duration(m) * time.Minute))
	}
	if s.Valid(t0.Add(60*time.Minute), p) != ErrSessionExpired {
		t.Fatal("absolute timeout not enforced")
	}
	if got := s.TTL(t0.Add(54*time.Minute), p); got != 6*time.Minute {
		t.Fatalf("ttl capped by absolute expiry: got %v", got)
	}
}

func TestTokensUnique(t *testing.T) {
	a, _ := NewToken()
	b, _ := NewToken()
	if a == b || len(a) < 40 {
		t.Fatal("weak tokens")
	}
}
