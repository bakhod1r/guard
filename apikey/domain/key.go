// Package domain holds API key rules: issuance, scopes, expiry, revocation.
package domain

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
	"time"
)

var (
	ErrKeyNotFound  = errors.New("apikey: not found")
	ErrKeyInvalid   = errors.New("apikey: invalid, expired or revoked")
	ErrInvalidName  = errors.New("apikey: name must be 1-100 characters")
	ErrInvalidScope = errors.New("apikey: scope must be resource.action, resource.* or *")
	ErrNoScopes     = errors.New("apikey: at least one scope is required")
	ErrBadExpiry    = errors.New("apikey: expires_at must be in the future")
)

// TokenPrefix marks Guard API keys so they are recognisable in logs and secret scanners.
const TokenPrefix = "gk_"

var scopePart = regexp.MustCompile(`^[a-z0-9_\-]{1,64}$`)

// Token is the secret shown to the caller exactly once.
type Token string

// Hash is the stored form of a token.
func (t Token) Hash() string {
	sum := sha256.Sum256([]byte(t))
	return hex.EncodeToString(sum[:])
}

// LooksLikeKey reports whether a credential is an API key rather than a session token.
func LooksLikeKey(s string) bool { return strings.HasPrefix(s, TokenPrefix) }

type Key struct {
	ID         string     `json:"id"`
	UserID     string     `json:"user_id"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	Hash       string     `json:"-"`
	Scopes     []string   `json:"scopes"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

func validScope(s string) bool {
	if s == "*" {
		return true
	}
	res, act, ok := strings.Cut(s, ".")
	return ok && scopePart.MatchString(res) && (act == "*" || scopePart.MatchString(act))
}

// New issues a key. The token is returned once; only its hash is kept.
func New(id, userID, name string, scopes []string, expiresAt *time.Time, now time.Time) (*Key, Token, error) {
	name = strings.TrimSpace(name)
	if n := len([]rune(name)); n == 0 || n > 100 {
		return nil, "", ErrInvalidName
	}
	if len(scopes) == 0 {
		return nil, "", ErrNoScopes
	}
	seen := map[string]bool{}
	clean := make([]string, 0, len(scopes))
	for _, s := range scopes {
		s = strings.TrimSpace(s)
		if !validScope(s) {
			return nil, "", ErrInvalidScope
		}
		if !seen[s] {
			seen[s] = true
			clean = append(clean, s)
		}
	}
	if expiresAt != nil && !expiresAt.After(now) {
		return nil, "", ErrBadExpiry
	}
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, "", err
	}
	secret := base64.RawURLEncoding.EncodeToString(b[:])
	tok := Token(TokenPrefix + secret)
	k := &Key{ID: id, UserID: userID, Name: name, Prefix: string(tok[:len(TokenPrefix)+8]), Hash: tok.Hash(),
		Scopes: clean, ExpiresAt: expiresAt, CreatedAt: now}
	return k, tok, nil
}

// Usable reports whether the key may authenticate at now.
func (k *Key) Usable(now time.Time) error {
	if k.RevokedAt != nil || (k.ExpiresAt != nil && !now.Before(*k.ExpiresAt)) {
		return ErrKeyInvalid
	}
	return nil
}

// Allows reports whether the key's scopes cover resource.action.
// Scopes only narrow: the owner's RBAC/ABAC decision still applies.
func (k *Key) Allows(resource, action string) bool {
	for _, s := range k.Scopes {
		if s == "*" || s == resource+".*" || s == resource+"."+action {
			return true
		}
	}
	return false
}

type Repository interface {
	Create(ctx context.Context, k *Key) error
	ByHash(ctx context.Context, hash string) (*Key, error)
	ListByUser(ctx context.Context, userID string) ([]Key, error)
	Revoke(ctx context.Context, userID, id string, at time.Time) error
	RevokeAllByUser(ctx context.Context, userID string, at time.Time) error
	TouchLastUsed(ctx context.Context, id string, at time.Time) error
}
