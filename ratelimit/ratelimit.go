// Package ratelimit throttles requests with a Redis sliding-window log.
package ratelimit

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// Rule allows Limit hits per Window.
type Rule struct {
	Limit  int
	Window time.Duration
}

func (r Rule) Valid() error {
	if r.Limit <= 0 || r.Window < time.Millisecond {
		return errors.New("ratelimit: limit must be > 0 and window >= 1ms")
	}
	return nil
}

type Result struct {
	Allowed    bool
	Limit      int
	Remaining  int
	RetryAfter time.Duration // zero when allowed
	ResetAfter time.Duration // until the oldest counted hit leaves the window
}

type Limiter interface {
	Allow(ctx context.Context, key string, rule Rule) (Result, error)
}

// Redis is a sliding-window log limiter: exact, atomic (one Lua call), and
// shared by every instance of the service.
type Redis struct {
	rdb    redis.UniversalClient
	prefix string
}

func NewRedis(rdb redis.UniversalClient, prefix string) *Redis {
	if prefix == "" {
		prefix = "guard:"
	}
	return &Redis{rdb: rdb, prefix: prefix + "rl:"}
}

// KEYS[1] zset; ARGV: now_ms, window_ms, limit, member
var script = redis.NewScript(`
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
redis.call('ZREMRANGEBYSCORE', key, '-inf', now - window)
local count = redis.call('ZCARD', key)
local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
local reset = 0
if oldest[2] then reset = tonumber(oldest[2]) + window - now end
if count < limit then
  redis.call('ZADD', key, now, ARGV[4])
  redis.call('PEXPIRE', key, window)
  if count == 0 then reset = window end
  return {1, limit - count - 1, 0, reset}
end
return {0, 0, reset, reset}
`)

func (r *Redis) Allow(ctx context.Context, key string, rule Rule) (Result, error) {
	if err := rule.Valid(); err != nil {
		return Result{}, err
	}
	var b [8]byte
	_, _ = rand.Read(b[:])
	now := time.Now().UnixMilli()
	member := strconv.FormatInt(now, 10) + "-" + hex.EncodeToString(b[:])
	vals, err := script.Run(ctx, r.rdb, []string{r.prefix + key},
		now, rule.Window.Milliseconds(), rule.Limit, member).Int64Slice()
	if err != nil {
		return Result{}, err
	}
	return Result{
		Allowed:    vals[0] == 1,
		Limit:      rule.Limit,
		Remaining:  int(vals[1]),
		RetryAfter: time.Duration(vals[2]) * time.Millisecond,
		ResetAfter: time.Duration(vals[3]) * time.Millisecond,
	}, nil
}
