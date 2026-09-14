package ratelimit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestAllowPropagatesRedisError(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	_ = rdb.Close()
	res, err := NewRedis(rdb, "t:").Allow(context.Background(), "k", Rule{Limit: 1, Window: time.Second})
	if !errors.Is(err, redis.ErrClosed) {
		t.Fatalf("want redis.ErrClosed got %v", err)
	}
	if res != (Result{}) {
		t.Fatalf("want zero result got %+v", res)
	}
}
