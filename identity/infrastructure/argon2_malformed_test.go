package infrastructure

import (
	"errors"
	"testing"
)

func TestNewArgon2HasherUsesOWASPParameters(t *testing.T) {
	h := NewArgon2Hasher()
	if *h != (Argon2Hasher{Memory: 64 * 1024, Time: 3, Threads: 2, KeyLen: 32, SaltLen: 16}) {
		t.Fatalf("got %+v", *h)
	}
}

func TestArgon2VerifyRejectsMalformedHash(t *testing.T) {
	h := &Argon2Hasher{Memory: 1024, Time: 1, Threads: 1, KeyLen: 32, SaltLen: 16}
	cases := map[string]string{
		"too few parts":   "$argon2id$v=19$m=1024,t=1,p=1$c2FsdA",
		"wrong algorithm": "$argon2i$v=19$m=1024,t=1,p=1$c2FsdA$a2V5",
		"bad params":      "$argon2id$v=19$m=x,t=1,p=1$c2FsdA$a2V5",
		"bad base64 salt": "$argon2id$v=19$m=1024,t=1,p=1$!!!$a2V5",
		"bad base64 key":  "$argon2id$v=19$m=1024,t=1,p=1$c2FsdA$!!!",
	}
	for name, enc := range cases {
		if ok, err := h.Verify("password1", enc); ok || !errors.Is(err, errBadHash) {
			t.Errorf("%s: ok=%v err=%v", name, ok, err)
		}
	}
}
