// Package infrastructure provides identity adapters: argon2id hashing and PostgreSQL storage.
package infrastructure

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"runtime"
	"strings"

	"golang.org/x/crypto/argon2"
)

type Argon2Hasher struct {
	Memory  uint32
	Time    uint32
	Threads uint8
	KeyLen  uint32
	SaltLen uint32
}

// NewArgon2Hasher returns OWASP-recommended argon2id parameters.
func NewArgon2Hasher() *Argon2Hasher {
	return &Argon2Hasher{Memory: 64 * 1024, Time: 3, Threads: 2, KeyLen: 32, SaltLen: 16}
}

// ErrWeakHashParams rejects argon2id parameters below the OWASP floor.
var ErrWeakHashParams = errors.New("identity: argon2id parameters below minimum (memory >= 19456 KiB, time >= 2, threads >= 1, salt/key >= 16 bytes)")

// NewArgon2HasherWithParams returns a hasher with custom parameters, refusing
// values below the OWASP argon2id minimum (m=19456 KiB, t=2, p=1).
func NewArgon2HasherWithParams(memory, time uint32, threads uint8, keyLen, saltLen uint32) (*Argon2Hasher, error) {
	if memory < 19456 || time < 2 || threads < 1 || keyLen < 16 || saltLen < 16 {
		return nil, ErrWeakHashParams
	}
	return &Argon2Hasher{Memory: memory, Time: time, Threads: threads, KeyLen: keyLen, SaltLen: saltLen}, nil
}

// hashSlots bounds concurrent argon2id computations process-wide. Each one
// holds Memory KiB (64 MiB by default), so unbounded parallel logins could
// exhaust memory; extra callers queue instead.
var hashSlots = make(chan struct{}, max(2, runtime.GOMAXPROCS(0)))

// idKey is argon2.IDKey under hashSlots.
func idKey(password, salt []byte, time, memory uint32, threads uint8, keyLen uint32) []byte {
	hashSlots <- struct{}{}
	defer func() { <-hashSlots }()
	return argon2.IDKey(password, salt, time, memory, threads, keyLen)
}

var errBadHash = errors.New("identity: malformed password hash")

func (h *Argon2Hasher) Hash(plain string) (string, error) {
	salt := make([]byte, h.SaltLen)
	// crypto/rand.Read never returns an error (it crashes the program instead).
	_, _ = rand.Read(salt)
	key := idKey([]byte(plain), salt, h.Time, h.Memory, h.Threads, h.KeyLen)
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, h.Memory, h.Time, h.Threads, b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

// argon2Params are the parameters decoded from a PHC-format argon2id hash.
type argon2Params struct {
	memory, time uint32
	threads      uint8
	salt, key    []byte
}

func decodeArgon2(encoded string) (*argon2Params, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return nil, errBadHash
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return nil, errBadHash
	}
	var p argon2Params
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.memory, &p.time, &p.threads); err != nil || p.time < 1 || p.threads < 1 {
		return nil, errBadHash
	}
	b64 := base64.RawStdEncoding
	var err error
	if p.salt, err = b64.DecodeString(parts[4]); err != nil {
		return nil, errBadHash
	}
	if p.key, err = b64.DecodeString(parts[5]); err != nil {
		return nil, errBadHash
	}
	return &p, nil
}

func (h *Argon2Hasher) Verify(plain, encoded string) (bool, error) {
	p, err := decodeArgon2(encoded)
	if err != nil {
		return false, err
	}
	got := idKey([]byte(plain), p.salt, p.time, p.memory, p.threads, uint32(len(p.key))) //nolint:gosec // key length bounded by decodeArgon2
	return subtle.ConstantTimeCompare(got, p.key) == 1, nil
}

// NeedsRehash reports whether encoded is not an argon2id hash produced with
// exactly this hasher's parameters.
func (h *Argon2Hasher) NeedsRehash(encoded string) bool {
	p, err := decodeArgon2(encoded)
	return err != nil || p.memory != h.Memory || p.time != h.Time || p.threads != h.Threads ||
		uint32(len(p.salt)) != h.SaltLen || uint32(len(p.key)) != h.KeyLen //nolint:gosec // lengths bounded by decodeArgon2
}
