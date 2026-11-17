// Package token issues and verifies short-lived access tokens: compact JWTs
// signed with HMAC-SHA256 (RFC 7519, alg HS256 only). An access token is
// stateless: Verify checks the signature, the time window, the issuer and the
// audience without touching storage. Revocation (sign-out before expiry) is a
// separate, optional check, see Revocations.
//
// Only HS256 is accepted, whatever the header says, so "alg: none" and
// algorithm-confusion tokens are rejected. Keys carry an id ("kid") so a
// secret can be rotated: sign with the first key, verify with any.
package token

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	sessiondomain "github.com/bakhod1r/guard/session/domain"
)

// Errors wrap the session errors so callers that already treat an expired or
// unknown session as "credential rejected" treat a bad access token the same.
var (
	ErrInvalid = fmt.Errorf("token: invalid: %w", sessiondomain.ErrSessionNotFound)
	ErrExpired = fmt.Errorf("token: expired: %w", sessiondomain.ErrSessionExpired)
	ErrRevoked = fmt.Errorf("token: revoked: %w", sessiondomain.ErrSessionExpired)
)

// MinSecretLen is the shortest accepted HMAC secret (256 bits).
const MinSecretLen = 32

// DefaultTTL is the access token lifetime when Options.TTL is zero.
const DefaultTTL = 15 * time.Minute

// leeway tolerates clock skew between instances.
const leeway = 30 * time.Second

// Key is one HMAC secret and its id.
type Key struct {
	ID     string
	Secret []byte
}

// Options configure an Issuer.
type Options struct {
	// Keys: the first signs, every key verifies. At least one is required.
	Keys []Key
	// TTL is the token lifetime (DefaultTTL when zero).
	TTL time.Duration
	// Issuer and Audience go into iss/aud and must match on Verify.
	Issuer   string
	Audience string
}

// Claims are the verified contents of an access token.
type Claims struct {
	ID        string    // jti
	UserID    string    // sub
	SessionID string    // sid: the session the token was issued for
	Family    string    // fam: stable across rotations of that session
	IssuedAt  time.Time // iat
	ExpiresAt time.Time // exp
}

type wire struct {
	Iss string `json:"iss,omitempty"`
	Aud string `json:"aud,omitempty"`
	Sub string `json:"sub"`
	Sid string `json:"sid"`
	Fam string `json:"fam"`
	Jti string `json:"jti"`
	Iat int64  `json:"iat"`
	Ims int64  `json:"ims"` // iat in milliseconds: orders a token against a revocation in the same second
	Nbf int64  `json:"nbf"`
	Exp int64  `json:"exp"`
}

type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid,omitempty"`
}

// Issuer signs and verifies access tokens.
type Issuer struct {
	keys []Key
	ttl  time.Duration
	iss  string
	aud  string
}

// New validates the options.
func New(o Options) (*Issuer, error) {
	if len(o.Keys) == 0 {
		return nil, errors.New("token: at least one key is required")
	}
	seen := map[string]bool{}
	keys := make([]Key, len(o.Keys))
	for i, k := range o.Keys {
		if len(k.Secret) < MinSecretLen {
			return nil, fmt.Errorf("token: key %q: secret must be at least %d bytes", k.ID, MinSecretLen)
		}
		if seen[k.ID] {
			return nil, fmt.Errorf("token: duplicate key id %q", k.ID)
		}
		seen[k.ID] = true
		keys[i] = Key{ID: k.ID, Secret: append([]byte(nil), k.Secret...)}
	}
	if o.TTL < 0 {
		return nil, errors.New("token: TTL must not be negative")
	}
	ttl := o.TTL
	if ttl == 0 {
		ttl = DefaultTTL
	}
	return &Issuer{keys: keys, ttl: ttl, iss: o.Issuer, aud: o.Audience}, nil
}

// TTL is the lifetime of issued tokens.
func (i *Issuer) TTL() time.Duration { return i.ttl }

var b64 = base64.RawURLEncoding

// Issue signs a token for userID and the given session.
func (i *Issuer) Issue(userID, sessionID, family string, now time.Time) (string, Claims) {
	now = now.UTC().Truncate(time.Millisecond)
	var j [16]byte
	_, _ = rand.Read(j[:])
	c := Claims{ID: hex.EncodeToString(j[:]), UserID: userID, SessionID: sessionID, Family: family,
		IssuedAt: now, ExpiresAt: now.Add(i.ttl).Truncate(time.Second)}
	k := i.keys[0]
	h, _ := json.Marshal(header{Alg: "HS256", Typ: "JWT", Kid: k.ID})
	p, _ := json.Marshal(wire{Iss: i.iss, Aud: i.aud, Sub: c.UserID, Sid: c.SessionID, Fam: c.Family, Jti: c.ID,
		Iat: now.Unix(), Ims: now.UnixMilli(), Nbf: now.Unix(), Exp: c.ExpiresAt.Unix()})
	signing := b64.EncodeToString(h) + "." + b64.EncodeToString(p)
	return signing + "." + b64.EncodeToString(sign(k.Secret, signing)), c
}

// Verify checks signature, kid, alg, time window, issuer and audience.
func (i *Issuer) Verify(raw string, now time.Time) (Claims, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return Claims{}, ErrInvalid
	}
	hb, err1 := b64.DecodeString(parts[0])
	pb, err2 := b64.DecodeString(parts[1])
	sig, err3 := b64.DecodeString(parts[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return Claims{}, ErrInvalid
	}
	var h header
	if json.Unmarshal(hb, &h) != nil || h.Alg != "HS256" {
		return Claims{}, ErrInvalid
	}
	var key *Key
	for n := range i.keys {
		if i.keys[n].ID == h.Kid {
			key = &i.keys[n]
			break
		}
	}
	if key == nil || !hmac.Equal(sig, sign(key.Secret, parts[0]+"."+parts[1])) {
		return Claims{}, ErrInvalid
	}
	var w wire
	if json.Unmarshal(pb, &w) != nil || w.Sub == "" || w.Exp == 0 || w.Iss != i.iss || w.Aud != i.aud {
		return Claims{}, ErrInvalid
	}
	now = now.UTC()
	if now.Add(leeway).Unix() < w.Nbf {
		return Claims{}, ErrInvalid
	}
	if !now.Add(-leeway).Before(time.Unix(w.Exp, 0)) {
		return Claims{}, ErrExpired
	}
	return Claims{ID: w.Jti, UserID: w.Sub, SessionID: w.Sid, Family: w.Fam,
		IssuedAt: issuedAt(w), ExpiresAt: time.Unix(w.Exp, 0).UTC()}, nil
}

// LooksLikeJWT is a cheap shape test (three base64url parts, JSON header),
// used to route a credential before any storage lookup. Session tokens are a
// single base64url string and API keys start with "gk_", so neither matches.
func LooksLikeJWT(s string) bool {
	return strings.HasPrefix(s, "eyJ") && strings.Count(s, ".") == 2
}

func sign(secret []byte, s string) []byte {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(s))
	return m.Sum(nil)
}

func issuedAt(w wire) time.Time {
	if w.Ims/1000 == w.Iat {
		return time.UnixMilli(w.Ims).UTC()
	}
	return time.Unix(w.Iat, 0).UTC()
}
