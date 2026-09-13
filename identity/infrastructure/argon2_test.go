package infrastructure

import "testing"

func TestArgon2RoundTrip(t *testing.T) {
	h := &Argon2Hasher{Memory: 1024, Time: 1, Threads: 1, KeyLen: 32, SaltLen: 16}
	enc, err := h.Hash("correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := h.Verify("correct horse", enc); !ok {
		t.Fatal("valid password rejected")
	}
	if ok, _ := h.Verify("wrong", enc); ok {
		t.Fatal("wrong password accepted")
	}
	if _, err := h.Verify("x", "garbage"); err == nil {
		t.Fatal("malformed hash accepted")
	}
}
