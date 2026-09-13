// Package infrastructure provides identity adapters: argon2id hashing and PostgreSQL storage.
package infrastructure

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
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

var errBadHash = errors.New("identity: malformed password hash")

func (h *Argon2Hasher) Hash(plain string) (string, error) {
	salt := make([]byte, h.SaltLen)
	// crypto/rand.Read never returns an error (it crashes the program instead).
	_, _ = rand.Read(salt)
	key := argon2.IDKey([]byte(plain), salt, h.Time, h.Memory, h.Threads, h.KeyLen)
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, h.Memory, h.Time, h.Threads, b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

func (h *Argon2Hasher) Verify(plain, encoded string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, errBadHash
	}
	var memory, iterations uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &threads); err != nil {
		return false, errBadHash
	}
	b64 := base64.RawStdEncoding
	salt, err := b64.DecodeString(parts[4])
	if err != nil {
		return false, errBadHash
	}
	want, err := b64.DecodeString(parts[5])
	if err != nil {
		return false, errBadHash
	}
	got := argon2.IDKey([]byte(plain), salt, iterations, memory, threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}
