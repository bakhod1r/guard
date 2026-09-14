// Package domain holds session business rules: lifetime, idle timeout, revocation.
package domain

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"sort"
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

// NewToken returns a fresh 256-bit token. crypto/rand.Read never fails (it aborts the process instead).
func NewToken() Token {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return Token(base64.RawURLEncoding.EncodeToString(b[:]))
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
	// MaxPerUser caps concurrent sessions per user; Start evicts the least
	// recently used sessions beyond it. 0 means unlimited.
	MaxPerUser int
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

func New(userID string, now time.Time, p Policy) (*Session, Token) {
	tok := NewToken()
	s := &Session{ID: tok.ID(), UserID: userID, CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(p.AbsoluteTimeout)}
	return s, tok
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

// Evict returns the IDs of the least recently used sessions (by LastSeenAt,
// ties by ID) that must go so that at most limit remain. keep is never evicted
// but counts toward the limit. limit <= 0 means unlimited.
func Evict(sessions []*Session, limit int, keep ID) []ID {
	excess := len(sessions) - limit
	if limit <= 0 || excess <= 0 {
		return nil
	}
	sorted := make([]*Session, 0, len(sessions))
	for _, s := range sessions {
		if s.ID != keep {
			sorted = append(sorted, s)
		}
	}
	sort.Slice(sorted, func(i, j int) bool {
		if !sorted[i].LastSeenAt.Equal(sorted[j].LastSeenAt) {
			return sorted[i].LastSeenAt.Before(sorted[j].LastSeenAt)
		}
		return sorted[i].ID < sorted[j].ID
	})
	out := make([]ID, 0, excess)
	for _, s := range sorted[:excess] {
		out = append(out, s.ID)
	}
	return out
}

type Repository interface {
	Save(ctx context.Context, s *Session, ttl time.Duration) error
	Get(ctx context.Context, id ID) (*Session, error)
	Delete(ctx context.Context, id ID) error
	ListByUser(ctx context.Context, userID string) ([]*Session, error)
	DeleteByUser(ctx context.Context, userID string) error
}

// Toucher is an optional Repository capability: persist a slid session only
// if it still exists, so a concurrent Revoke/RevokeAll cannot be undone by an
// in-flight request. Returns ErrSessionNotFound when the session vanished.
type Toucher interface {
	Touch(ctx context.Context, s *Session, ttl time.Duration) error
}

// Taker is an optional Repository capability: atomically read and delete a
// session so only one caller can claim it (used by Rotate). Returns
// ErrSessionNotFound when the session is gone.
type Taker interface {
	Take(ctx context.Context, id ID) (*Session, error)
}

// LimitedSaver is an optional Repository capability: atomically save s and
// evict the user's least recently used sessions so at most limit remain.
type LimitedSaver interface {
	SaveLimited(ctx context.Context, s *Session, ttl time.Duration, limit int) error
}
