// Package ratelimit throttles requests with a Redis sliding-window log.
//
// Redis Cluster: every Allow runs one Lua script that touches exactly one key
// (KEYS[1] = prefix + "rl:" + key), so the script never spans hash slots and
// runs unchanged on Redis Cluster. Put a hash tag in the prefix or key
// ("guard:{tenant}:") only if you need related limits on the same slot.
//
// Time comes from the calling process, not from Redis, so instances sharing a
// limiter should run NTP-synchronised clocks; skew shifts window edges by the
// skew amount.
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
	now    func() time.Time // test seam; time.Now in production
}

func NewRedis(rdb redis.UniversalClient, prefix string) *Redis {
	if prefix == "" {
		prefix = "guard:"
	}
	return &Redis{rdb: rdb, prefix: prefix + "rl:", now: time.Now}
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
	now := r.now().UnixMilli()
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
