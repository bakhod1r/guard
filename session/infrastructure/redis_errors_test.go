package infrastructure

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/bakhod1r/guard/session/domain"
)

var errPipe = errors.New("pipeline failed")

// failPipeline makes every MULTI/EXEC pipeline fail while single commands pass.
type failPipeline struct{}

func (failPipeline) DialHook(next redis.DialHook) redis.DialHook          { return next }
func (failPipeline) ProcessHook(next redis.ProcessHook) redis.ProcessHook { return next }
func (failPipeline) ProcessPipelineHook(redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(context.Context, []redis.Cmder) error { return errPipe }
}

func setup(t *testing.T) (*miniredis.Miniredis, *redis.Client, *RedisSessions) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return mr, rdb, NewRedisSessions(rdb, "t:")
}

func sess(uid string) *domain.Session {
	now := time.Now().UTC()
	s, _ := domain.New(uid, now, domain.DefaultPolicy())
	return s
}

func TestSaveWithNonPositiveTTLDeletesSession(t *testing.T) {
	mr, _, r := setup(t)
	ctx := context.Background()
	s := sess("u")
	if err := r.Save(ctx, s, time.Minute); err != nil {
		t.Fatal(err)
	}
	for _, ttl := range []time.Duration{0, -time.Second} {
		if err := r.Save(ctx, s, ttl); err != nil {
			t.Fatalf("ttl %v: %v", ttl, err)
		}
		if mr.Exists("t:session:" + string(s.ID)) {
			t.Fatalf("ttl %v: session still stored", ttl)
		}
	}
}

func TestDeleteMissingSessionIsNoop(t *testing.T) {
	_, _, r := setup(t)
	if err := r.Delete(context.Background(), "missing"); err != nil {
		t.Fatal(err)
	}
}

func TestGetCorruptPayloadReturnsDecodeError(t *testing.T) {
	mr, _, r := setup(t)
	_ = mr.Set("t:session:bad", "{not json")
	if _, err := r.Get(context.Background(), "bad"); err == nil || errors.Is(err, domain.ErrSessionNotFound) {
		t.Fatalf("want decode error got %v", err)
	}
}

func TestListByUserCleansStaleIDs(t *testing.T) {
	mr, _, r := setup(t)
	ctx := context.Background()
	s := sess("u")
	if err := r.Save(ctx, s, time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := mr.SAdd("t:user_sessions:u", "gone"); err != nil {
		t.Fatal(err)
	}
	list, err := r.ListByUser(ctx, "u")
	if err != nil || len(list) != 1 || list[0].ID != s.ID {
		t.Fatalf("list: %v %v", list, err)
	}
	members, _ := mr.Members("t:user_sessions:u")
	if len(members) != 1 || members[0] != string(s.ID) {
		t.Fatalf("stale id not removed: %v", members)
	}
}

func TestListByUserPropagatesDecodeError(t *testing.T) {
	mr, _, r := setup(t)
	_, _ = mr.SAdd("t:user_sessions:u", "bad")
	_ = mr.Set("t:session:bad", "{not json")
	if _, err := r.ListByUser(context.Background(), "u"); err == nil {
		t.Fatal("want decode error")
	}
}

func TestDeletePropagatesPipelineError(t *testing.T) {
	_, rdb, r := setup(t)
	ctx := context.Background()
	s := sess("u")
	if err := r.Save(ctx, s, time.Minute); err != nil {
		t.Fatal(err)
	}
	rdb.AddHook(failPipeline{})
	if err := r.Delete(ctx, s.ID); !errors.Is(err, errPipe) {
		t.Fatalf("want pipeline error got %v", err)
	}
}

func TestRedisErrorsPropagateOnClosedClient(t *testing.T) {
	_, rdb, r := setup(t)
	_ = rdb.Close()
	ctx := context.Background()
	checks := map[string]func() error{
		"Save":         func() error { return r.Save(ctx, sess("u"), time.Minute) },
		"Get":          func() error { _, err := r.Get(ctx, "x"); return err },
		"Delete":       func() error { return r.Delete(ctx, "x") },
		"ListByUser":   func() error { _, err := r.ListByUser(ctx, "u"); return err },
		"DeleteByUser": func() error { return r.DeleteByUser(ctx, "u") },
	}
	for name, fn := range checks {
		if err := fn(); !errors.Is(err, redis.ErrClosed) {
			t.Errorf("%s: want redis.ErrClosed got %v", name, err)
		}
	}
}
