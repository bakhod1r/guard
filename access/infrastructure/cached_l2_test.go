package infrastructure

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func l2Redis(t *testing.T) (redis.UniversalClient, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	c := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = c.Close() })
	return c, mr
}

// The whole point under a load balancer: instance B serves a request from the
// shared Redis copy that instance A loaded, without touching PostgreSQL.
func TestL2SharedAcrossInstances(t *testing.T) {
	rdb, _ := l2Redis(t)
	o := newOrigin(t)
	ctx := context.Background()
	opts := CacheOptions{L2: true, TTL: time.Hour}
	a := NewCached(o, o, rdb, opts)
	b := NewCached(o, o, rdb, opts)

	if g, err := a.GrantsOf(ctx, "u1"); err != nil || len(g) != 1 {
		t.Fatalf("a grants %v %v", g, err)
	}
	if p, err := a.ApplicablePolicies(ctx, "post", "edit"); err != nil || len(p) != 1 {
		t.Fatalf("a policies %v %v", p, err)
	}
	if o.grantsCalls.Load() != 1 || o.policyCalls.Load() != 1 {
		t.Fatalf("origin loads %d %d", o.grantsCalls.Load(), o.policyCalls.Load())
	}

	// B has a cold in-process cache; Redis must answer for it.
	if g, err := b.GrantsOf(ctx, "u1"); err != nil || len(g) != 1 {
		t.Fatalf("b grants %v %v", g, err)
	}
	if p, err := b.ApplicablePolicies(ctx, "post", "edit"); err != nil || len(p) != 1 {
		t.Fatalf("b policies %v %v", p, err)
	}
	if o.grantsCalls.Load() != 1 || o.policyCalls.Load() != 1 {
		t.Fatalf("B bypassed L2: origin loads %d %d", o.grantsCalls.Load(), o.policyCalls.Load())
	}
	if s := b.Stats(); s.L2Hits != 2 || s.L2Misses != 0 {
		t.Fatalf("b stats %+v", s)
	}
	if s := a.Stats(); s.L2Hits != 0 || s.L2Misses != 2 {
		t.Fatalf("a stats %+v", s)
	}

	// A write anywhere moves the version: every instance must re-read the origin.
	if err := b.AssignRole(ctx, "u1", "viewer", "", nil); err != nil {
		t.Fatal(err)
	}
	if g, _ := a.GrantsOf(ctx, "u1"); len(g) != 2 {
		t.Fatalf("stale after invalidation: %v", g)
	}
	if o.grantsCalls.Load() != 2 {
		t.Fatalf("origin loads %d", o.grantsCalls.Load())
	}
	if g, _ := b.GrantsOf(ctx, "u1"); len(g) != 2 {
		t.Fatalf("b stale: %v", g)
	}
	if o.grantsCalls.Load() != 2 {
		t.Fatalf("b did not reuse A's refreshed L2 entry: %d", o.grantsCalls.Load())
	}
}

func TestL2DisabledByDefault(t *testing.T) {
	rdb, mr := l2Redis(t)
	o := newOrigin(t)
	a := NewCached(o, o, rdb, CacheOptions{TTL: time.Hour})
	b := NewCached(o, o, rdb, CacheOptions{TTL: time.Hour})
	ctx := context.Background()
	_, _ = a.GrantsOf(ctx, "u1")
	_, _ = b.GrantsOf(ctx, "u1")
	if o.grantsCalls.Load() != 2 {
		t.Fatalf("L2 must be off unless opted in, loads=%d", o.grantsCalls.Load())
	}
	if s := a.Stats(); s.L2Hits != 0 || s.L2Misses != 0 {
		t.Fatalf("stats %+v", s)
	}
	for _, k := range mr.Keys() {
		if k != "guard:access:version" {
			t.Fatalf("unexpected redis key %q", k)
		}
	}
}

func TestL2Defaults(t *testing.T) {
	rdb, _ := l2Redis(t)
	c := NewCached(NewMemory(), NewMemory(), rdb, CacheOptions{L2: true, TTL: time.Minute})
	if c.l2TTL != 2*time.Minute {
		t.Fatalf("l2TTL %v", c.l2TTL)
	}
	if c2 := NewCached(NewMemory(), NewMemory(), rdb, CacheOptions{L2: true, L2TTL: time.Hour}); c2.l2TTL != time.Hour {
		t.Fatalf("l2TTL %v", c2.l2TTL)
	}
	// Without Redis there is nothing to share: L2 stays off.
	if c3 := NewCached(NewMemory(), NewMemory(), nil, CacheOptions{L2: true}); c3.l2 {
		t.Fatal("L2 enabled without Redis")
	}
}

func TestL2CorruptValueFallsBackToOrigin(t *testing.T) {
	rdb, _ := l2Redis(t)
	o := newOrigin(t)
	var errs atomic.Int64
	c := NewCached(o, o, rdb, CacheOptions{L2: true, TTL: time.Hour, OnError: func(error) { errs.Add(1) }})
	ctx := context.Background()

	token, ok := c.l2Token(ctx)
	if !ok {
		t.Fatal("no token")
	}
	if err := rdb.Set(ctx, c.l2Key(token, l2Grants, "u1"), "{not json", time.Hour).Err(); err != nil {
		t.Fatal(err)
	}
	if g, err := c.GrantsOf(ctx, "u1"); err != nil || len(g) != 1 {
		t.Fatalf("grants %v %v", g, err)
	}
	if s := c.Stats(); s.SerializeFailures != 1 || s.L2Hits != 0 {
		t.Fatalf("stats %+v", s)
	}
	if errs.Load() != 1 {
		t.Fatalf("OnError calls %d", errs.Load())
	}
	// The corrupt value was overwritten by the origin load.
	raw, err := rdb.Get(ctx, c.l2Key(token, l2Grants, "u1")).Result()
	if err != nil || raw == "{not json" {
		t.Fatalf("corrupt value not replaced: %q %v", raw, err)
	}
}

// l2GetFailHook fails GETs of shared cache entries only, leaving the version key
// readable: the request must still be answered, by the origin.
type l2GetFailHook struct{ prefix string }

func (h *l2GetFailHook) DialHook(next redis.DialHook) redis.DialHook { return next }
func (h *l2GetFailHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}
func (h *l2GetFailHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		args := cmd.Args()
		if len(args) > 1 {
			if key, ok := args[1].(string); ok && strings.HasPrefix(key, h.prefix) {
				err := errors.New("injected l2 failure")
				cmd.SetErr(err)
				return err
			}
		}
		return next(ctx, cmd)
	}
}

func TestL2UnreachableFallsBackToOrigin(t *testing.T) {
	rdb, _ := l2Redis(t)
	o := newOrigin(t)
	var errs atomic.Int64
	c := NewCached(o, o, rdb, CacheOptions{L2: true, TTL: time.Hour, OnError: func(error) { errs.Add(1) }})
	rdb.AddHook(&l2GetFailHook{prefix: c.l2Prefix})
	ctx := context.Background()

	if g, err := c.GrantsOf(ctx, "u1"); err != nil || len(g) != 1 {
		t.Fatalf("grants %v %v", g, err)
	}
	if s := c.Stats(); s.L2Hits != 0 || s.L2Misses != 0 || s.Bypasses != 0 {
		t.Fatalf("stats %+v", s)
	}
	if errs.Load() != 1 {
		t.Fatalf("OnError calls %d", errs.Load())
	}
	if o.grantsCalls.Load() != 1 {
		t.Fatalf("origin loads %d", o.grantsCalls.Load())
	}
}

func TestL2UnserializableValueIsNotStored(t *testing.T) {
	rdb, _ := l2Redis(t)
	var errs atomic.Int64
	c := NewCached(NewMemory(), NewMemory(), rdb, CacheOptions{L2: true, OnError: func(error) { errs.Add(1) }})
	c.storeL2(context.Background(), c.l2Key("t", l2Grants, "u1"), make(chan int))
	if c.Stats().SerializeFailures != 1 || errs.Load() != 1 {
		t.Fatalf("stats %+v errs %d", c.Stats(), errs.Load())
	}
	if n, err := rdb.Exists(context.Background(), c.l2Key("t", l2Grants, "u1")).Result(); err != nil || n != 0 {
		t.Fatalf("key written: %d %v", n, err)
	}

	// A refused write is reported and otherwise ignored.
	rdb.AddHook(&l2GetFailHook{prefix: c.l2Prefix})
	c.storeL2(context.Background(), c.l2Key("t", l2Grants, "u1"), []int{1})
	if errs.Load() != 2 {
		t.Fatalf("OnError calls %d", errs.Load())
	}
}

// Without a provable version there is no key namespace to read from: the origin
// answers and nothing is cached at either level.
func TestL2WithoutVersionUsesOrigin(t *testing.T) {
	rdb, mr := l2Redis(t)
	o := newOrigin(t)
	c := NewCached(o, o, rdb, CacheOptions{L2: true, TTL: time.Hour})
	ctx := context.Background()
	mr.Close()

	if _, ok := c.l2Token(ctx); ok {
		t.Fatal("token proven while Redis is down")
	}
	if g, err := c.GrantsOf(ctx, "u1"); err != nil || len(g) != 1 {
		t.Fatalf("grants %v %v", g, err)
	}
	if s := c.Stats(); s.Bypasses != 1 || s.L2Hits != 0 || s.L2Misses != 0 {
		t.Fatalf("stats %+v", s)
	}
}

func TestL2OriginErrorIsNotStored(t *testing.T) {
	rdb, _ := l2Redis(t)
	o := newOrigin(t)
	boom := errors.New("boom")
	o.failLoad = boom
	c := NewCached(o, o, rdb, CacheOptions{L2: true, TTL: time.Hour})
	ctx := context.Background()
	if _, err := c.GrantsOf(ctx, "u1"); !errors.Is(err, boom) {
		t.Fatalf("err %v", err)
	}
	token, ok := c.l2Token(ctx)
	if !ok {
		t.Fatal("no token")
	}
	if n, err := rdb.Exists(ctx, c.l2Key(token, l2Grants, "u1")).Result(); err != nil || n != 0 {
		t.Fatalf("failed load was cached: %d %v", n, err)
	}
}

// A load can outlive the invalidation that distrusted L2, so the write side
// checks the window too rather than relying on the read side's earlier check.
func TestL2StoreSkippedWhileDistrusted(t *testing.T) {
	rdb, _ := l2Redis(t)
	c := NewCached(NewMemory(), NewMemory(), rdb, CacheOptions{L2: true, TTL: time.Hour})
	ctx := context.Background()
	c.l2DistrustUntil.Store(c.now().Add(time.Hour).UnixNano())
	c.storeL2(ctx, c.l2Key("t", l2Grants, "u1"), []int{1})
	if n, err := rdb.Exists(ctx, c.l2Key("t", l2Grants, "u1")).Result(); err != nil || n != 0 {
		t.Fatalf("wrote to a distrusted L2: %d %v", n, err)
	}
}

// A failed invalidation means the shared version may not have moved: this
// instance must stop trusting L2 for a full L2 TTL rather than re-reading a
// value that its own write just made stale.
func TestL2DistrustedAfterFailedInvalidation(t *testing.T) {
	rdb, mr := l2Redis(t)
	o := newOrigin(t)
	c := NewCached(o, o, rdb, CacheOptions{L2: true, TTL: time.Hour, L2TTL: time.Hour})
	now := time.Now()
	c.now = func() time.Time { return now }
	ctx := context.Background()
	_, _ = c.GrantsOf(ctx, "u1")

	rdb.AddHook(&failHook{cmd: "incr"})
	if err := c.AssignRole(ctx, "u1", "viewer", "", nil); err != nil {
		t.Fatal(err)
	}
	if c.Stats().InvalidationFailures != 1 {
		t.Fatal("expected a recorded invalidation failure")
	}

	before := o.grantsCalls.Load()
	if g, _ := c.GrantsOf(ctx, "u1"); len(g) != 2 {
		t.Fatalf("served a stale L2 value after a failed invalidation: %v", g)
	}
	if o.grantsCalls.Load() != before+1 {
		t.Fatal("expected an origin load while L2 is distrusted")
	}
	if c.Stats().L2Distrusted == 0 {
		t.Fatalf("stats %+v", c.Stats())
	}

	// The window is exactly the L2 TTL, so by the time L2 is trusted again every
	// entry the failed invalidation could not kill has expired on its own.
	now = now.Add(time.Hour)
	mr.FastForward(time.Hour)
	distrusted := c.Stats().L2Distrusted
	if g, _ := c.GrantsOf(ctx, "u1"); len(g) != 2 {
		t.Fatalf("stale grants after the distrust window: %v", g)
	}
	if c.Stats().L2Distrusted != distrusted {
		t.Fatal("still distrusting L2 after the window closed")
	}
	if c.Stats().L2Misses == 0 {
		t.Fatalf("expected an L2 miss on the expired entry: %+v", c.Stats())
	}
}
