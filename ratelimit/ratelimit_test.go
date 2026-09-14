package ratelimit

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestSlidingWindow(t *testing.T) {
	mr := miniredis.RunT(t)
	l := NewRedis(redis.NewClient(&redis.Options{Addr: mr.Addr()}), "t:")
	now := time.UnixMilli(1_700_000_000_000)
	l.now = func() time.Time { return now }
	ctx := context.Background()
	rule := Rule{Limit: 3, Window: 200 * time.Millisecond}

	for i := 0; i < 3; i++ {
		res, err := l.Allow(ctx, "ip:1", rule)
		if err != nil || !res.Allowed || res.Remaining != 2-i {
			t.Fatalf("hit %d: %+v %v", i, res, err)
		}
	}
	res, _ := l.Allow(ctx, "ip:1", rule)
	if res.Allowed || res.RetryAfter != rule.Window || res.ResetAfter != rule.Window {
		t.Fatalf("4th hit: %+v", res)
	}
	if other, _ := l.Allow(ctx, "ip:2", rule); !other.Allowed {
		t.Fatal("keys must be independent")
	}
	now = now.Add(rule.Window - time.Millisecond)
	if res, _ := l.Allow(ctx, "ip:1", rule); res.Allowed || res.RetryAfter != time.Millisecond {
		t.Fatalf("1ms before the window slides: %+v", res)
	}
	now = now.Add(time.Millisecond)
	if res, _ := l.Allow(ctx, "ip:1", rule); !res.Allowed || res.Remaining != 2 {
		t.Fatalf("window did not slide: %+v", res)
	}
}

func TestRuleValidation(t *testing.T) {
	mr := miniredis.RunT(t)
	l := NewRedis(redis.NewClient(&redis.Options{Addr: mr.Addr()}), "")
	if _, err := l.Allow(context.Background(), "k", Rule{}); err == nil {
		t.Fatal("zero rule accepted")
	}
}

func TestNewRedisUsesWallClock(t *testing.T) {
	l := NewRedis(nil, "")
	if d := time.Since(l.now()); d < 0 || d > time.Minute {
		t.Fatalf("default clock off by %v", d)
	}
}
