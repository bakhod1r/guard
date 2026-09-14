package infrastructure

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/bakhod1r/guard/identity/domain"
)

var (
	_ domain.Rehasher       = (*Argon2Hasher)(nil)
	_ domain.Rehasher       = (*MultiHasher)(nil)
	_ domain.PasswordHasher = (*MultiHasher)(nil)
)

func TestNewArgon2HasherWithParamsValidates(t *testing.T) {
	h, err := NewArgon2HasherWithParams(19456, 2, 1, 16, 16)
	if err != nil || *h != (Argon2Hasher{Memory: 19456, Time: 2, Threads: 1, KeyLen: 16, SaltLen: 16}) {
		t.Fatalf("min params: %+v %v", h, err)
	}
	bad := [][5]uint32{
		{19455, 2, 1, 32, 16},
		{19456, 1, 1, 32, 16},
		{19456, 2, 0, 32, 16},
		{19456, 2, 1, 15, 16},
		{19456, 2, 1, 32, 15},
	}
	for _, p := range bad {
		if h, err := NewArgon2HasherWithParams(p[0], p[1], uint8(p[2]), p[3], p[4]); h != nil || !errors.Is(err, ErrWeakHashParams) {
			t.Errorf("%v: %v %v", p, h, err)
		}
	}
}

func TestArgon2VerifyRejectsUnsafeEncodedParams(t *testing.T) {
	h := &Argon2Hasher{Memory: 1024, Time: 1, Threads: 1, KeyLen: 32, SaltLen: 16}
	for _, enc := range []string{
		"$argon2id$v=19$m=1024,t=0,p=1$c29tZXNhbHRzb21lc2FsdA$a2V5a2V5a2V5a2V5",
		"$argon2id$v=19$m=1024,t=1,p=0$c29tZXNhbHRzb21lc2FsdA$a2V5a2V5a2V5a2V5",
		"$argon2id$v=18$m=1024,t=1,p=1$c29tZXNhbHRzb21lc2FsdA$a2V5a2V5a2V5a2V5",
		"$argon2id$v=x$m=1024,t=1,p=1$c29tZXNhbHRzb21lc2FsdA$a2V5a2V5a2V5a2V5",
	} {
		if ok, err := h.Verify("x", enc); ok || !errors.Is(err, errBadHash) {
			t.Errorf("%s: %v %v", enc, ok, err)
		}
	}
}

func TestArgon2NeedsRehash(t *testing.T) {
	h := &Argon2Hasher{Memory: 1024, Time: 1, Threads: 1, KeyLen: 32, SaltLen: 16}
	cur, _ := h.Hash("correct-horse-1")
	if h.NeedsRehash(cur) {
		t.Fatal("current hash flagged")
	}
	stronger := *h
	stronger.Time = 2
	if !stronger.NeedsRehash(cur) {
		t.Fatal("time change not flagged")
	}
	longer := *h
	longer.KeyLen, longer.SaltLen = 64, 32
	if !longer.NeedsRehash(cur) {
		t.Fatal("key/salt length change not flagged")
	}
	for _, enc := range []string{"garbage", "$2a$10$abc", strings.Replace(cur, "m=1024", "m=2048", 1)} {
		if !h.NeedsRehash(enc) {
			t.Errorf("%s not flagged", enc)
		}
	}
}

func TestMultiHasher(t *testing.T) {
	a := &Argon2Hasher{Memory: 1024, Time: 1, Threads: 1, KeyLen: 32, SaltLen: 16}
	m := NewMultiHasher(a)
	if NewMultiHasher(nil).argon == nil {
		t.Fatal("nil argon must default")
	}
	enc, err := m.Hash("correct-horse-1")
	if err != nil || !strings.HasPrefix(enc, "$argon2id$") || m.NeedsRehash(enc) {
		t.Fatalf("hash: %q %v", enc, err)
	}
	if ok, err := m.Verify("correct-horse-1", enc); !ok || err != nil {
		t.Fatalf("argon verify: %v %v", ok, err)
	}
	b, _ := bcrypt.GenerateFromPassword([]byte("correct-horse-1"), bcrypt.MinCost)
	for _, prefix := range []string{"$2a$", "$2b$", "$2y$"} {
		h := prefix + string(b[4:])
		if ok, err := m.Verify("correct-horse-1", h); !ok || err != nil {
			t.Errorf("%s verify: %v %v", prefix, ok, err)
		}
		if ok, err := m.Verify("wrong-horse-1", h); ok || err != nil {
			t.Errorf("%s wrong: %v %v", prefix, ok, err)
		}
		if !m.NeedsRehash(h) {
			t.Errorf("%s must need rehash", prefix)
		}
	}
	if ok, err := m.Verify("x", "$2a$10$short"); ok || !errors.Is(err, errBadHash) {
		t.Fatalf("malformed bcrypt: %v %v", ok, err)
	}
	if ok, err := m.Verify("x", "$md5$abc"); ok || !errors.Is(err, errBadHash) {
		t.Fatalf("unknown: %v %v", ok, err)
	}
}
