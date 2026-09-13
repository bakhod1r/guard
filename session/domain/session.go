// Package domain holds session business rules: lifetime, idle timeout, revocation.
package domain

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"
)

var (
	ErrSessionNotFound = errors.New("session: not found")
	ErrSessionExpired  = errors.New("session: expired")
)

// Token is the opaque secret handed to the client. Only its hash is stored.
type Token string

// ID is the storage key of a session: SHA-256 of the token.
type ID string

func NewToken() (Token, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return Token(base64.RawURLEncoding.EncodeToString(b[:])), nil
}

func (t Token) ID() ID {
	sum := sha256.Sum256([]byte(t))
	return ID(hex.EncodeToString(sum[:]))
}

type Policy struct {
	// IdleTimeout expires a session not used for this long (sliding).
	IdleTimeout time.Duration
	// AbsoluteTimeout caps total session lifetime regardless of activity.
	AbsoluteTimeout time.Duration
}

func DefaultPolicy() Policy {
	return Policy{IdleTimeout: 30 * time.Minute, AbsoluteTimeout: 7 * 24 * time.Hour}
}

type Session struct {
	ID         ID                `json:"id"`
	UserID     string            `json:"user_id"`
	CreatedAt  time.Time         `json:"created_at"`
	LastSeenAt time.Time         `json:"last_seen_at"`
	ExpiresAt  time.Time         `json:"expires_at"`
	IP         string            `json:"ip,omitempty"`
	UserAgent  string            `json:"user_agent,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

func New(userID string, now time.Time, p Policy) (*Session, Token, error) {
	tok, err := NewToken()
	if err != nil {
		return nil, "", err
	}
	s := &Session{ID: tok.ID(), UserID: userID, CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(p.AbsoluteTimeout)}
	return s, tok, nil
}

// Valid reports whether the session is alive at now.
func (s *Session) Valid(now time.Time, p Policy) error {
	if !now.Before(s.ExpiresAt) || now.Sub(s.LastSeenAt) >= p.IdleTimeout {
		return ErrSessionExpired
	}
	return nil
}

// Touch slides the idle window.
func (s *Session) Touch(now time.Time) { s.LastSeenAt = now }

// TTL is how long storage should keep the session from now.
func (s *Session) TTL(now time.Time, p Policy) time.Duration {
	idle := s.LastSeenAt.Add(p.IdleTimeout)
	end := s.ExpiresAt
	if idle.Before(end) {
		end = idle
	}
	return end.Sub(now)
}

type Repository interface {
	Save(ctx context.Context, s *Session, ttl time.Duration) error
	Get(ctx context.Context, id ID) (*Session, error)
	Delete(ctx context.Context, id ID) error
	ListByUser(ctx context.Context, userID string) ([]*Session, error)
	DeleteByUser(ctx context.Context, userID string) error
}
