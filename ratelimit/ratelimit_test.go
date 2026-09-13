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
	ctx := context.Background()
	rule := Rule{Limit: 3, Window: 200 * time.Millisecond}

	for i := 0; i < 3; i++ {
		res, err := l.Allow(ctx, "ip:1", rule)
		if err != nil || !res.Allowed || res.Remaining != 2-i {
			t.Fatalf("hit %d: %+v %v", i, res, err)
		}
	}
	res, _ := l.Allow(ctx, "ip:1", rule)
	if res.Allowed || res.RetryAfter <= 0 || res.RetryAfter > rule.Window {
		t.Fatalf("4th hit: %+v", res)
	}
	if other, _ := l.Allow(ctx, "ip:2", rule); !other.Allowed {
		t.Fatal("keys must be independent")
	}
	time.Sleep(rule.Window + 20*time.Millisecond)
	if res, _ := l.Allow(ctx, "ip:1", rule); !res.Allowed {
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
