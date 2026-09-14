// Package infrastructure stores sessions in Redis.
package infrastructure

import (
	"context"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/bakhod1r/guard/session/domain"
)

type RedisSessions struct {
	rdb    redis.UniversalClient
	prefix string
}

func NewRedisSessions(rdb redis.UniversalClient, prefix string) *RedisSessions {
	if prefix == "" {
		prefix = "guard:"
	}
	return &RedisSessions{rdb: rdb, prefix: prefix}
}

func (r *RedisSessions) key(id domain.ID) string   { return r.prefix + "session:" + string(id) }
func (r *RedisSessions) userKey(uid string) string { return r.prefix + "user_sessions:" + uid }

func (r *RedisSessions) Save(ctx context.Context, s *domain.Session, ttl time.Duration) error {
	if ttl <= 0 {
		return r.Delete(ctx, s.ID)
	}
	b, _ := json.Marshal(s) // Session holds only strings, times and a string map: Marshal cannot fail.
	_, err := r.rdb.TxPipelined(ctx, func(p redis.Pipeliner) error {
		p.Set(ctx, r.key(s.ID), b, ttl)
		p.SAdd(ctx, r.userKey(s.UserID), string(s.ID))
		p.ExpireNX(ctx, r.userKey(s.UserID), time.Until(s.ExpiresAt))
		p.ExpireGT(ctx, r.userKey(s.UserID), time.Until(s.ExpiresAt))
		return nil
	})
	return err
}

func (r *RedisSessions) Get(ctx context.Context, id domain.ID) (*domain.Session, error) {
	b, err := r.rdb.Get(ctx, r.key(id)).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, domain.ErrSessionNotFound
	}
	if err != nil {
		return nil, err
	}
	var s domain.Session
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func (r *RedisSessions) Delete(ctx context.Context, id domain.ID) error {
	s, err := r.Get(ctx, id)
	if errors.Is(err, domain.ErrSessionNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	_, err = r.rdb.TxPipelined(ctx, func(p redis.Pipeliner) error {
		p.Del(ctx, r.key(id))
		p.SRem(ctx, r.userKey(s.UserID), string(id))
		return nil
	})
	return err
}

func (r *RedisSessions) ListByUser(ctx context.Context, userID string) ([]*domain.Session, error) {
	ids, err := r.rdb.SMembers(ctx, r.userKey(userID)).Result()
	if err != nil {
		return nil, err
	}
	out := make([]*domain.Session, 0, len(ids))
	var stale []any
	for _, id := range ids {
		s, err := r.Get(ctx, domain.ID(id))
		if errors.Is(err, domain.ErrSessionNotFound) {
			stale = append(stale, id)
			continue
		}
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	if len(stale) > 0 {
		r.rdb.SRem(ctx, r.userKey(userID), stale...)
	}
	return out, nil
}

func (r *RedisSessions) DeleteByUser(ctx context.Context, userID string) error {
	ids, err := r.rdb.SMembers(ctx, r.userKey(userID)).Result()
	if err != nil {
		return err
	}
	keys := []string{r.userKey(userID)}
	for _, id := range ids {
		keys = append(keys, r.key(domain.ID(id)))
	}
	return r.rdb.Del(ctx, keys...).Err()
}

// Touch rewrites an existing session (SET XX) so a concurrent revoke is never
// undone. Returns domain.ErrSessionNotFound when the key is gone.
func (r *RedisSessions) Touch(ctx context.Context, s *domain.Session, ttl time.Duration) error {
	if ttl <= 0 {
		return r.Delete(ctx, s.ID)
	}
	b, _ := json.Marshal(s) // cannot fail, see Save
	err := r.rdb.SetArgs(ctx, r.key(s.ID), b, redis.SetArgs{Mode: "XX", TTL: ttl}).Err()
	if errors.Is(err, redis.Nil) {
		return domain.ErrSessionNotFound
	}
	return err
}

// maxSaveRetries bounds optimistic-lock retries in SaveLimited.
const maxSaveRetries = 16

// SaveLimited saves s and evicts the user's least recently used sessions so at
// most limit remain, atomically via WATCH/MULTI on the user's session set. Stale
// ids are pruned and the set expires at the latest ExpiresAt it still covers.
func (r *RedisSessions) SaveLimited(ctx context.Context, s *domain.Session, ttl time.Duration, limit int) error {
	if ttl <= 0 {
		return r.Delete(ctx, s.ID)
	}
	b, _ := json.Marshal(s) // cannot fail, see Save
	uk := r.userKey(s.UserID)
	txf := func(tx *redis.Tx) error {
		ids, err := tx.SMembers(ctx, uk).Result()
		if err != nil {
			return err
		}
		live := []*domain.Session{s}
		var drop []any
		var corrupt []domain.ID
		if len(ids) > 0 {
			keys := make([]string, len(ids))
			for i, id := range ids {
				keys[i] = r.key(domain.ID(id))
			}
			vals, err := tx.MGet(ctx, keys...).Result()
			if err != nil {
				return err
			}
			for i, v := range vals {
				str, ok := v.(string)
				if !ok {
					drop = append(drop, ids[i])
					continue
				}
				var cur domain.Session
				if err := json.Unmarshal([]byte(str), &cur); err != nil {
					// A corrupt value must not lock the user out: drop it.
					corrupt = append(corrupt, domain.ID(ids[i]))
					drop = append(drop, ids[i])
					continue
				}
				live = append(live, &cur)
			}
		}
		evict := domain.Evict(live, limit, s.ID)
		gone := make(map[domain.ID]bool, len(evict))
		for _, id := range evict {
			gone[id] = true
			drop = append(drop, string(id))
		}
		expireAt := s.ExpiresAt
		for _, cur := range live {
			if !gone[cur.ID] && cur.ExpiresAt.After(expireAt) {
				expireAt = cur.ExpiresAt
			}
		}
		_, err = tx.TxPipelined(ctx, func(p redis.Pipeliner) error {
			p.Set(ctx, r.key(s.ID), b, ttl)
			for _, id := range append(evict, corrupt...) {
				p.Del(ctx, r.key(id))
			}
			if len(drop) > 0 {
				p.SRem(ctx, uk, drop...)
			}
			p.SAdd(ctx, uk, string(s.ID))
			p.PExpireAt(ctx, uk, expireAt)
			return nil
		})
		return err
	}
	var err error
	for i := 0; i < maxSaveRetries; i++ {
		if err = r.rdb.Watch(ctx, txf, uk); !errors.Is(err, redis.TxFailedErr) {
			return err
		}
		// Jittered backoff spreads out contending writers.
		time.Sleep(time.Duration(rand.Int64N(int64(time.Millisecond) << min(i, 5)))) //nolint:gosec // backoff jitter, not security-sensitive
	}
	return err
}

// Take atomically reads and deletes a session (GETDEL), so exactly one caller
// claims it. A corrupt value is consumed and its decode error returned.
func (r *RedisSessions) Take(ctx context.Context, id domain.ID) (*domain.Session, error) {
	b, err := r.rdb.GetDel(ctx, r.key(id)).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, domain.ErrSessionNotFound
	}
	if err != nil {
		return nil, err
	}
	var s domain.Session
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	r.rdb.SRem(ctx, r.userKey(s.UserID), string(id))
	return &s, nil
}
