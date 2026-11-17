package token

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	sessiondomain "github.com/bakhod1r/guard/session/domain"
)

var (
	k1 = Key{ID: "k1", Secret: []byte(strings.Repeat("a", 32))}
	k2 = Key{ID: "k2", Secret: []byte(strings.Repeat("b", 32))}
	t0 = time.Date(2026, 11, 17, 10, 0, 0, 0, time.UTC)
)

func issuer(t *testing.T, keys ...Key) *Issuer {
	t.Helper()
	i, err := New(Options{Keys: keys, TTL: 3 * time.Hour, Issuer: "iss", Audience: "aud"})
	if err != nil {
		t.Fatal(err)
	}
	return i
}

func TestNewValidates(t *testing.T) {
	for name, o := range map[string]Options{
		"no keys":   {},
		"short":     {Keys: []Key{{ID: "x", Secret: []byte("short")}}},
		"duplicate": {Keys: []Key{k1, k1}},
		"negative":  {Keys: []Key{k1}, TTL: -time.Second},
	} {
		if _, err := New(o); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
	i, err := New(Options{Keys: []Key{k1}})
	if err != nil || i.TTL() != DefaultTTL {
		t.Fatalf("default ttl = %v, %v", i.TTL(), err)
	}
}

func TestIssueVerify(t *testing.T) {
	i := issuer(t, k1)
	raw, c := i.Issue("42", "sid1", "fam1", t0)
	if !LooksLikeJWT(raw) || LooksLikeJWT("abcdef") || LooksLikeJWT("gk_x.y.z") {
		t.Fatal("LooksLikeJWT")
	}
	got, err := i.Verify(raw, t0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if got != c || got.UserID != "42" || got.SessionID != "sid1" || got.Family != "fam1" || !got.ExpiresAt.Equal(t0.Add(3*time.Hour)) {
		t.Fatalf("claims = %+v, issued %+v", got, c)
	}
}

func TestVerifyRejects(t *testing.T) {
	i := issuer(t, k1)
	raw, _ := i.Issue("42", "s", "f", t0)
	parts := strings.Split(raw, ".")

	if _, err := i.Verify(raw, t0.Add(3*time.Hour+time.Minute)); !errors.Is(err, ErrExpired) || !errors.Is(err, sessiondomain.ErrSessionExpired) {
		t.Errorf("expired: %v", err)
	}
	if _, err := i.Verify(raw, t0.Add(-time.Hour)); !errors.Is(err, ErrInvalid) {
		t.Errorf("not yet valid: %v", err)
	}
	none := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT","kid":"k1"}`))
	bad := map[string]string{
		"garbage":  "eyJ.x",
		"tampered": parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"1","exp":99999999999,"iss":"iss","aud":"aud"}`)) + "." + parts[2],
		"alg none": none + "." + parts[1] + ".",
		"bad sig":  parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString([]byte("nope")),
		"other key": func() string {
			r, _ := issuer(t, Key{ID: "k1", Secret: []byte(strings.Repeat("z", 32))}).Issue("1", "s", "f", t0)
			return r
		}(),
		"other aud": func() string {
			j, _ := New(Options{Keys: []Key{k1}, Issuer: "iss", Audience: "x"})
			r, _ := j.Issue("1", "s", "f", t0)
			return r
		}(),
		"unknown kid": func() string { r, _ := issuer(t, k2).Issue("1", "s", "f", t0); return r }(),
	}
	for name, tok := range bad {
		if _, err := i.Verify(tok, t0.Add(time.Minute)); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err = %v, want invalid", name, err)
		}
	}
}

func TestKeyRotation(t *testing.T) {
	old, _ := issuer(t, k1).Issue("1", "s", "f", t0)
	rotated := issuer(t, k2, k1) // k2 signs, k1 still verifies
	if _, err := rotated.Verify(old, t0.Add(time.Minute)); err != nil {
		t.Fatalf("old key: %v", err)
	}
	fresh, _ := rotated.Issue("1", "s", "f", t0)
	if _, err := issuer(t, k1).Verify(fresh, t0.Add(time.Minute)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("k1-only issuer must reject k2 tokens: %v", err)
	}
}

func TestRevocations(t *testing.T) {
	ctx := context.Background()
	mr := miniredis.RunT(t)
	r := NewRevocations(redis.NewClient(&redis.Options{Addr: mr.Addr()}), "", time.Hour)
	i := issuer(t, k1)
	now := time.Now()
	_, a := i.Issue("1", "s1", "famA", now)
	_, b := i.Issue("1", "s2", "famB", now)
	_, other := i.Issue("2", "s3", "famC", now)

	if err := r.Check(ctx, a); err != nil {
		t.Fatal(err)
	}
	if err := r.RevokeFamily(ctx, "famA"); err != nil {
		t.Fatal(err)
	}
	if err := r.Check(ctx, a); !errors.Is(err, ErrRevoked) {
		t.Fatalf("family: %v", err)
	}
	if err := r.Check(ctx, b); err != nil {
		t.Fatalf("other family: %v", err)
	}
	if err := r.RevokeUser(ctx, "1", now.Add(time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if err := r.Check(ctx, b); !errors.Is(err, ErrRevoked) {
		t.Fatalf("user: %v", err)
	}
	_, later := i.Issue("1", "s4", "famD", now.Add(time.Second))
	if err := r.Check(ctx, later); err != nil {
		t.Fatalf("token issued after RevokeUser: %v", err)
	}
	if err := r.Check(ctx, other); err != nil {
		t.Fatalf("other user: %v", err)
	}
	if ttl := mr.TTL("guard:access:revoked:fam:famA"); ttl <= time.Hour || ttl > time.Hour+time.Minute {
		t.Fatalf("ttl = %v", ttl)
	}
	mr.Close()
	if err := r.Check(ctx, a); err == nil || errors.Is(err, ErrRevoked) {
		t.Fatalf("outage must be an error, not a verdict: %v", err)
	}
}
