package token

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func forge(t *testing.T, k Key, w wire) string {
	t.Helper()
	h, _ := json.Marshal(header{Alg: "HS256", Typ: "JWT", Kid: k.ID})
	p, _ := json.Marshal(w)
	signing := b64.EncodeToString(h) + "." + b64.EncodeToString(p)
	return signing + "." + b64.EncodeToString(sign(k.Secret, signing))
}

func TestVerifyBadBase64InEachPart(t *testing.T) {
	i := issuer(t, k1)
	for _, raw := range []string{"!!.e30.e30", "e30.!!.e30", "e30.e30.!!"} {
		if _, err := i.Verify(raw, t0); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%q: %v", raw, err)
		}
	}
}

func TestVerifyWithoutMillisecondIatFallsBackToSeconds(t *testing.T) {
	i := issuer(t, k1)
	raw := forge(t, k1, wire{Iss: "iss", Aud: "aud", Sub: "1", Sid: "s", Fam: "f", Jti: "j",
		Iat: t0.Unix(), Nbf: t0.Unix(), Exp: t0.Add(time.Hour).Unix()})
	c, err := i.Verify(raw, t0)
	if err != nil {
		t.Fatal(err)
	}
	if !c.IssuedAt.Equal(t0) {
		t.Fatalf("iat: %v", c.IssuedAt)
	}
}

func TestRevokeFamilyEmptyIsNoop(t *testing.T) {
	mr := miniredis.RunT(t)
	r := NewRevocations(redis.NewClient(&redis.Options{Addr: mr.Addr()}), "p:", 0)
	if err := r.RevokeFamily(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if len(mr.Keys()) != 0 {
		t.Fatalf("keys: %v", mr.Keys())
	}
}
