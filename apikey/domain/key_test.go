package domain

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestNewKey(t *testing.T) {
	now := time.Now()
	k, tok, err := New("id", "u1", " ci ", []string{"report.read", "invoice.*", "report.read"}, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if !LooksLikeKey(string(tok)) || !strings.HasPrefix(string(tok), k.Prefix) || len(tok) < 40 {
		t.Fatalf("token format: %q prefix %q", tok, k.Prefix)
	}
	if k.Hash != tok.Hash() || strings.Contains(k.Hash, string(tok)) {
		t.Fatal("hash must be derived, not raw token")
	}
	if k.Name != "ci" || len(k.Scopes) != 2 {
		t.Fatalf("normalisation: %+v", k)
	}
}

func TestNewKeyValidation(t *testing.T) {
	now := time.Now()
	past := now.Add(-time.Second)
	cases := []struct {
		name   string
		scopes []string
		exp    *time.Time
		want   error
	}{
		{"", []string{"*"}, nil, ErrInvalidName},
		{"x", nil, nil, ErrNoScopes},
		{"x", []string{"Report.Read"}, nil, ErrInvalidScope},
		{"x", []string{"*.read"}, nil, ErrInvalidScope},
		{"x", []string{"report"}, nil, ErrInvalidScope},
		{"x", []string{"*"}, &past, ErrBadExpiry},
		{"x", manyScopes(MaxScopes + 1), nil, ErrTooManyScopes},
		{"x", []string{strings.Repeat("a", 65) + ".read"}, nil, ErrInvalidScope},
		{"x", []string{strings.Repeat("a", 64) + "." + strings.Repeat("b", 65)}, nil, ErrInvalidScope},
		{"x", []string{strings.Repeat("a", 1<<20)}, nil, ErrInvalidScope},
	}
	for _, c := range cases {
		if _, _, err := New("id", "u", c.name, c.scopes, c.exp, now); err != c.want {
			t.Errorf("%+v: want %v got %v", c, c.want, err)
		}
	}
}

func TestScopes(t *testing.T) {
	k := &Key{Scopes: []string{"report.read", "invoice.*"}}
	if !k.Allows("report", "read") || !k.Allows("invoice", "delete") {
		t.Fatal("scope should allow")
	}
	if k.Allows("report", "write") || k.Allows("user", "read") {
		t.Fatal("scope too broad")
	}
	if !(&Key{Scopes: []string{"*"}}).Allows("any", "thing") {
		t.Fatal("star scope")
	}
}

func TestUsable(t *testing.T) {
	now := time.Now()
	exp := now.Add(time.Minute)
	k := &Key{ExpiresAt: &exp}
	if k.Usable(now) != nil {
		t.Fatal("fresh key unusable")
	}
	if k.Usable(exp) != ErrKeyInvalid {
		t.Fatal("expired key usable")
	}
	k.ExpiresAt, k.RevokedAt = nil, &now
	if k.Usable(now) != ErrKeyInvalid {
		t.Fatal("revoked key usable")
	}
}

func manyScopes(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = "r" + strconv.Itoa(i) + ".read"
	}
	return out
}

func TestNewKeyScopeLimits(t *testing.T) {
	longest := strings.Repeat("a", 64) + "." + strings.Repeat("b", 64)
	if len(longest) != MaxScopeLength {
		t.Fatalf("longest valid scope is %d chars, MaxScopeLength = %d", len(longest), MaxScopeLength)
	}
	k, _, err := New("id", "u", "x", append(manyScopes(MaxScopes-1), longest), nil, time.Now())
	if err != nil || len(k.Scopes) != MaxScopes {
		t.Fatalf("at limits: %v %v", k, err)
	}
}
