package token

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// Revocations remembers, for one access-token lifetime, which session families
// and which users were signed out, so their still-unexpired access tokens stop
// working at once. Keys expire on their own after the TTL: by then every token
// they could match has expired anyway.
type Revocations struct {
	rdb    redis.UniversalClient
	prefix string
	ttl    time.Duration
}

// NewRevocations stores entries under prefix ("guard:" when empty) for ttl
// (the access-token TTL; keys outlive it by a minute to cover clock skew).
func NewRevocations(rdb redis.UniversalClient, prefix string, ttl time.Duration) *Revocations {
	if prefix == "" {
		prefix = "guard:"
	}
	return &Revocations{rdb: rdb, prefix: prefix + "access:revoked:", ttl: ttl + time.Minute}
}

func (r *Revocations) familyKey(f string) string { return r.prefix + "fam:" + f }
func (r *Revocations) userKey(u string) string   { return r.prefix + "user:" + u }

// RevokeFamily invalidates every access token issued for a session family.
func (r *Revocations) RevokeFamily(ctx context.Context, family string) error {
	if family == "" {
		return nil
	}
	return r.rdb.Set(ctx, r.familyKey(family), "1", r.ttl).Err()
}

// RevokeUser invalidates every access token of userID issued at or before at (millisecond precision).
func (r *Revocations) RevokeUser(ctx context.Context, userID string, at time.Time) error {
	return r.rdb.Set(ctx, r.userKey(userID), strconv.FormatInt(at.UnixMilli(), 10), r.ttl).Err()
}

// Check returns ErrRevoked for a revoked token, nil for a live one, or a
// storage error (an outage, not a verdict on the token).
func (r *Revocations) Check(ctx context.Context, c Claims) error {
	vals, err := r.rdb.MGet(ctx, r.familyKey(c.Family), r.userKey(c.UserID)).Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		return err
	}
	if len(vals) > 0 && vals[0] != nil {
		return ErrRevoked
	}
	if len(vals) > 1 && vals[1] != nil {
		if s, ok := vals[1].(string); ok {
			if at, err := strconv.ParseInt(s, 10, 64); err == nil && c.IssuedAt.UnixMilli() <= at {
				return ErrRevoked
			}
		}
	}
	return nil
}
