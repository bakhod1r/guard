package infrastructure

import (
	"errors"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// MultiHasher verifies legacy bcrypt ($2a$/$2b$/$2y$) and argon2id hashes but
// always hashes with argon2id. Bcrypt hashes report NeedsRehash so they are
// upgraded on the next successful login.
type MultiHasher struct {
	argon *Argon2Hasher
}

// NewMultiHasher wraps argon (nil uses NewArgon2Hasher defaults).
func NewMultiHasher(argon *Argon2Hasher) *MultiHasher {
	if argon == nil {
		argon = NewArgon2Hasher()
	}
	return &MultiHasher{argon: argon}
}

func isBcrypt(hash string) bool {
	return strings.HasPrefix(hash, "$2a$") || strings.HasPrefix(hash, "$2b$") || strings.HasPrefix(hash, "$2y$")
}

func (m *MultiHasher) Hash(plain string) (string, error) { return m.argon.Hash(plain) }

func (m *MultiHasher) Verify(plain, hash string) (bool, error) {
	if !isBcrypt(hash) {
		return m.argon.Verify(plain, hash)
	}
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain))
	if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		return false, nil
	}
	if err != nil {
		return false, errBadHash
	}
	return true, nil
}

func (m *MultiHasher) NeedsRehash(hash string) bool {
	return isBcrypt(hash) || m.argon.NeedsRehash(hash)
}
