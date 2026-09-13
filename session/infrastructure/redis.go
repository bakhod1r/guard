// Package infrastructure stores sessions in Redis.
package infrastructure

import (
	"context"
	"encoding/json"
	"errors"
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
