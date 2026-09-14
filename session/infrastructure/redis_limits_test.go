package infrastructure

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/bakhod1r/guard/session/application"
	"github.com/bakhod1r/guard/session/domain"
)

var (
	_ domain.Toucher      = (*RedisSessions)(nil)
	_ domain.LimitedSaver = (*RedisSessions)(nil)
)

func TestTouchOnlyUpdatesExistingSession(t *testing.T) {
	mr, _, r := setup(t)
	ctx := context.Background()
	s := sess("u")
	if err := r.Touch(ctx, s, time.Minute); !errors.Is(err, domain.ErrSessionNotFound) {
		t.Fatalf("missing: %v", err)
	}
	if mr.Exists("t:session:" + string(s.ID)) {
		t.Fatal("touch created a session")
	}
	if err := r.Save(ctx, s, time.Minute); err != nil {
		t.Fatal(err)
	}
	s.LastSeenAt = s.LastSeenAt.Add(time.Second)
	if err := r.Touch(ctx, s, 2*time.Minute); err != nil {
		t.Fatal(err)
	}
	got, _ := r.Get(ctx, s.ID)
	if !got.LastSeenAt.Equal(s.LastSeenAt) || mr.TTL("t:session:"+string(s.ID)) != 2*time.Minute {
		t.Fatalf("touch: %+v ttl=%v", got, mr.TTL("t:session:"+string(s.ID)))
	}
	if err := r.Touch(ctx, s, 0); err != nil || mr.Exists("t:session:"+string(s.ID)) {
		t.Fatalf("zero ttl must delete: %v", err)
	}
}

// Revoke landing between Get and Touch must not resurrect the session.
func TestResolveRaceWithRevokeDoesNotResurrect(t *testing.T) {
	mr, rdb, r := setup(t)
	ctx := context.Background()
	svc := application.NewService(r, domain.DefaultPolicy())
	s, tok, _ := svc.Start(ctx, application.StartInput{UserID: "u"})
	rdb.AddHook(afterGetHook{fn: func() { _ = NewRedisSessions(redis.NewClient(&redis.Options{Addr: mr.Addr()}), "t:").Delete(ctx, s.ID) }})
	if _, err := svc.Resolve(ctx, tok); !errors.Is(err, domain.ErrSessionNotFound) {
		t.Fatalf("want not found got %v", err)
	}
	if mr.Exists("t:session:" + string(s.ID)) {
		t.Fatal("revoked session resurrected")
	}
}

type afterGetHook struct{ fn func() }

func (afterGetHook) DialHook(next redis.DialHook) redis.DialHook { return next }
func (h afterGetHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		err := next(ctx, cmd)
		if cmd.Name() == "get" {
			h.fn()
		}
		return err
	}
}
func (afterGetHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}

func TestSaveLimitedEvictsLRUAndPrunesStale(t *testing.T) {
	mr, _, r := setup(t)
	ctx := context.Background()
	base := time.Now().UTC()
	mk := func(i int) *domain.Session {
		s, _ := domain.New("u", base, domain.DefaultPolicy())
		s.LastSeenAt = base.Add(time.Duration(i) * time.Second)
		s.ExpiresAt = base.Add(time.Duration(i+1) * time.Hour)
		return s
	}
	a, b, c := mk(1), mk(2), mk(3)
	for _, s := range []*domain.Session{a, b} {
		if err := r.SaveLimited(ctx, s, time.Hour, 2); err != nil {
			t.Fatal(err)
		}
	}
	_, _ = mr.SAdd("t:user_sessions:u", "stale")
	c.ExpiresAt = base.Add(30 * time.Minute) // max kept ExpiresAt is b's (3h)
	if err := r.SaveLimited(ctx, c, time.Hour, 2); err != nil {
		t.Fatal(err)
	}
	if mr.Exists("t:session:" + string(a.ID)) {
		t.Fatal("oldest not evicted")
	}
	members, _ := mr.Members("t:user_sessions:u")
	if len(members) != 2 {
		t.Fatalf("members: %v", members)
	}
	ttl := mr.TTL("t:user_sessions:u")
	if ttl < 2*time.Hour || ttl > 3*time.Hour {
		t.Fatalf("user set ttl: %v", ttl)
	}
	if err := r.SaveLimited(ctx, sess("u"), 0, 2); err != nil {
		t.Fatalf("zero ttl: %v", err)
	}
}

func TestSaveLimitedErrors(t *testing.T) {
	_, rdb, r := setup(t)
	ctx := context.Background()
	rdb.AddHook(failPipeline{})
	if err := r.SaveLimited(ctx, sess("u"), time.Minute, 2); !errors.Is(err, errPipe) {
		t.Fatalf("want pipe error got %v", err)
	}

	_, rdb2, r2 := setup(t)
	_ = rdb2.Close()
	if err := r2.SaveLimited(ctx, sess("u"), time.Minute, 2); !errors.Is(err, redis.ErrClosed) {
		t.Fatalf("closed: %v", err)
	}
	if err := r2.Touch(ctx, sess("u"), time.Minute); !errors.Is(err, redis.ErrClosed) {
		t.Fatalf("closed touch: %v", err)
	}
}

// Another writer touching the user set before every EXEC exhausts retries.
func TestSaveLimitedGivesUpAfterRetries(t *testing.T) {
	mr, rdb, r := setup(t)
	other := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = other.Close() })
	h := &conflictHook{other: other, key: "t:user_sessions:u"}
	rdb.AddHook(h)
	err := r.SaveLimited(context.Background(), sess("u"), time.Minute, 2)
	if !errors.Is(err, redis.TxFailedErr) || h.n != maxSaveRetries {
		t.Fatalf("err=%v attempts=%d", err, h.n)
	}
}

type conflictHook struct {
	other *redis.Client
	key   string
	n     int
}

func (*conflictHook) DialHook(next redis.DialHook) redis.DialHook          { return next }
func (*conflictHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook { return next }
func (h *conflictHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, cmds []redis.Cmder) error {
		if cmds[len(cmds)-1].Name() != "exec" {
			return next(ctx, cmds)
		}
		h.n++
		h.other.SAdd(ctx, h.key, fmt.Sprint("x", h.n))
		return next(ctx, cmds)
	}
}

func concurrentLimit(t *testing.T, rdb redis.UniversalClient, prefix string) {
	t.Helper()
	ctx := context.Background()
	svc := application.NewService(NewRedisSessions(rdb, prefix), domain.Policy{IdleTimeout: time.Hour, AbsoluteTimeout: time.Hour, MaxPerUser: 5})
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := svc.Start(ctx, application.StartInput{UserID: "u"})
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	list, err := svc.List(ctx, "u")
	if err != nil || len(list) != 5 {
		t.Fatalf("want 5 sessions got %d (%v)", len(list), err)
	}
	if n, _ := rdb.SCard(ctx, prefix+"user_sessions:u").Result(); n != 5 {
		t.Fatalf("set size %d", n)
	}
	var cursor uint64
	keys, _, _ := rdb.Scan(ctx, cursor, prefix+"session:*", 100).Result()
	if len(keys) != 5 {
		t.Fatalf("session keys %d", len(keys))
	}
}

func TestSaveLimitedConcurrentMiniredis(t *testing.T) {
	_, rdb, _ := setup(t)
	concurrentLimit(t, rdb, "t:")
}

func TestSaveLimitedConcurrentRealRedis(t *testing.T) {
	addr := os.Getenv("GUARD_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("GUARD_TEST_REDIS_ADDR not set")
	}
	rdb := redis.NewClient(&redis.Options{Addr: addr})
	t.Cleanup(func() { _ = rdb.Close() })
	prefix := fmt.Sprintf("guard_prod_session_%d:", time.Now().UnixNano())
	t.Cleanup(func() {
		keys, _ := rdb.Keys(context.Background(), prefix+"*").Result()
		if len(keys) > 0 {
			rdb.Del(context.Background(), keys...)
		}
	})
	concurrentLimit(t, rdb, prefix)
}

type failCmdHook struct{ name string }

func (failCmdHook) DialHook(next redis.DialHook) redis.DialHook { return next }
func (h failCmdHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		if cmd.Name() == h.name {
			return errPipe
		}
		return next(ctx, cmd)
	}
}
func (failCmdHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}

func TestSaveLimitedReadErrors(t *testing.T) {
	for _, name := range []string{"smembers", "mget"} {
		_, rdb, r := setup(t)
		ctx := context.Background()
		_ = r.Save(ctx, sess("u"), time.Minute)
		rdb.AddHook(failCmdHook{name: name})
		if err := r.SaveLimited(ctx, sess("u"), time.Minute, 2); !errors.Is(err, errPipe) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}
