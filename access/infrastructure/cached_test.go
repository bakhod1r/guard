package infrastructure

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/bakhod1r/guard/access/domain"
)

// countingOrigin counts hot-path loads and can block or fail them.
type countingOrigin struct {
	*Memory
	grantsCalls, policyCalls atomic.Int64
	gate                     chan struct{} // when non-nil, loads wait for it
	failLoad                 error
	failWrite                error
	nilResult                bool
}

func (o *countingOrigin) GrantsOf(ctx context.Context, id string) ([]domain.RoleGrant, error) {
	o.grantsCalls.Add(1)
	if o.gate != nil {
		<-o.gate
	}
	if o.failLoad != nil {
		return nil, o.failLoad
	}
	if o.nilResult {
		return nil, nil
	}
	return o.Memory.GrantsOf(ctx, id)
}

func (o *countingOrigin) ApplicablePolicies(ctx context.Context, r, a string) ([]domain.Policy, error) {
	o.policyCalls.Add(1)
	if o.failLoad != nil {
		return nil, o.failLoad
	}
	if o.nilResult {
		return nil, nil
	}
	return o.Memory.ApplicablePolicies(ctx, r, a)
}

func (o *countingOrigin) CreateRole(ctx context.Context, r *domain.Role) error {
	if o.failWrite != nil {
		return o.failWrite
	}
	return o.Memory.CreateRole(ctx, r)
}

func newOrigin(t *testing.T) *countingOrigin {
	t.Helper()
	o := &countingOrigin{Memory: NewMemory()}
	ctx := context.Background()
	role, _ := domain.NewRole("editor", "Editor", "", false)
	if err := o.Memory.CreatePermission(ctx, domain.Permission{Resource: "post", Action: "edit"}); err != nil {
		t.Fatal(err)
	}
	if err := o.Memory.CreateRole(ctx, role); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"viewer", "admin"} {
		r, _ := domain.NewRole(n, n, "", false)
		if err := o.Memory.CreateRole(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	if err := o.Memory.GrantPermission(ctx, "editor", domain.Permission{Resource: "post", Action: "edit"}, ""); err != nil {
		t.Fatal(err)
	}
	exp := time.Now().Add(time.Hour)
	if err := o.Memory.AssignRole(ctx, "u1", "editor", "", &exp); err != nil {
		t.Fatal(err)
	}
	if err := o.Memory.SavePolicy(ctx, &domain.Policy{ID: "p1", Name: "p1", Resource: "post", Action: "edit", Effect: domain.Allow, Enabled: true,
		Root: &domain.ConditionGroup{Operator: domain.And,
			Conditions: []domain.Condition{{Field: "user.id", Operator: domain.OpEq, Value: []string{"u1"}}},
			Groups:     []domain.ConditionGroup{{Operator: domain.Or}}}}); err != nil {
		t.Fatal(err)
	}
	return o
}

func uniquePrefix() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return "guard_prod_access_" + hex.EncodeToString(b) + ":"
}

type redisBackend struct {
	name string
	rdb  func(t *testing.T) redis.UniversalClient
}

func backends() []redisBackend {
	return []redisBackend{
		{"miniredis", func(t *testing.T) redis.UniversalClient {
			mr := miniredis.RunT(t)
			c := redis.NewClient(&redis.Options{Addr: mr.Addr()})
			t.Cleanup(func() { _ = c.Close() })
			return c
		}},
		{"redis", func(t *testing.T) redis.UniversalClient {
			addr := os.Getenv("GUARD_TEST_REDIS_ADDR")
			if addr == "" {
				t.Skip("GUARD_TEST_REDIS_ADDR not set")
			}
			c := redis.NewClient(&redis.Options{Addr: addr})
			t.Cleanup(func() { _ = c.Close() })
			return c
		}},
	}
}

func TestCachedCrossInstanceInvalidation(t *testing.T) {
	for _, b := range backends() {
		t.Run(b.name, func(t *testing.T) {
			rdb, ctx, prefix := b.rdb(t), context.Background(), uniquePrefix()
			t.Cleanup(func() { rdb.Del(context.Background(), prefix+"access:version") })
			o := newOrigin(t)
			a := NewCached(o, o, rdb, CacheOptions{Prefix: prefix, TTL: time.Hour})
			bb := NewCached(o, o, rdb, CacheOptions{Prefix: prefix, TTL: time.Hour})

			for i := 0; i < 3; i++ {
				if g, err := a.GrantsOf(ctx, "u1"); err != nil || len(g) != 1 {
					t.Fatalf("grants %v %v", g, err)
				}
				if p, err := a.ApplicablePolicies(ctx, "post", "edit"); err != nil || len(p) != 1 {
					t.Fatalf("policies %v %v", p, err)
				}
			}
			if o.grantsCalls.Load() != 1 || o.policyCalls.Load() != 1 {
				t.Fatalf("want 1 load each, got %d %d", o.grantsCalls.Load(), o.policyCalls.Load())
			}
			if s := a.Stats(); s.Hits != 4 || s.Misses != 2 {
				t.Fatalf("stats %+v", s)
			}

			// Write via instance B; instance A must see it on the very next read.
			if err := bb.AssignRole(ctx, "u1", "viewer", "", nil); err != nil {
				t.Fatal(err)
			}
			if g, _ := a.GrantsOf(ctx, "u1"); len(g) != 2 {
				t.Fatalf("A did not see B's grant: %v", g)
			}
			if err := bb.SavePolicy(ctx, &domain.Policy{ID: "p2", Name: "p2", Resource: "*", Action: "*", Effect: domain.Deny, Enabled: true}); err != nil {
				t.Fatal(err)
			}
			if p, _ := a.ApplicablePolicies(ctx, "post", "edit"); len(p) != 2 {
				t.Fatalf("A did not see B's policy: %v", p)
			}

			// Every write method invalidates.
			perm := domain.Permission{Resource: "post", Action: "read"}
			pols, _ := o.Memory.ListPolicies(ctx)
			writes := []func() error{
				func() error { return bb.CreatePermission(ctx, perm) },
				func() error { return bb.GrantPermission(ctx, "viewer", perm, "") },
				func() error { return bb.RevokePermission(ctx, "viewer", perm) },
				func() error { return bb.UnassignRole(ctx, "u1", "viewer") },
				func() error { r, _ := domain.NewRole("tmp", "tmp", "", false); return bb.CreateRole(ctx, r) },
				func() error { return bb.DeleteRole(ctx, "tmp") },
				func() error { return bb.DeletePolicy(ctx, pols[len(pols)-1].ID) },
			}
			for i, w := range writes {
				_, _ = a.GrantsOf(ctx, "u1")
				before := o.grantsCalls.Load()
				if err := w(); err != nil {
					t.Fatalf("write %d: %v", i, err)
				}
				_, _ = a.GrantsOf(ctx, "u1")
				if o.grantsCalls.Load() != before+1 {
					t.Fatalf("write %d did not invalidate", i)
				}
			}

			if a.Stats().InvalidationFailures+bb.Stats().InvalidationFailures != 0 {
				t.Fatalf("unexpected invalidation failures %+v %+v", a.Stats(), bb.Stats())
			}

			// A Redis flush re-seeds randomly: previously cached tags must not match.
			_, _ = a.GrantsOf(ctx, "u1")
			before := o.grantsCalls.Load()
			if err := rdb.Del(ctx, prefix+"access:version").Err(); err != nil {
				t.Fatal(err)
			}
			_, _ = a.GrantsOf(ctx, "u1")
			if o.grantsCalls.Load() != before+1 {
				t.Fatal("flushed version key reused cached entry")
			}
		})
	}
}

func TestCachedTTLExpiry(t *testing.T) {
	o := newOrigin(t)
	mr := miniredis.RunT(t)
	c := NewCached(o, o, redis.NewClient(&redis.Options{Addr: mr.Addr()}), CacheOptions{TTL: time.Minute})
	now := time.Now()
	c.now = func() time.Time { return now }
	ctx := context.Background()
	_, _ = c.GrantsOf(ctx, "u1")
	// Write that bypasses the decorator: stale until TTL.
	_ = o.Memory.AssignRole(ctx, "u1", "viewer", "", nil)
	if g, _ := c.GrantsOf(ctx, "u1"); len(g) != 1 {
		t.Fatalf("expected cached (stale) value within TTL, got %d", len(g))
	}
	now = now.Add(time.Minute)
	if g, _ := c.GrantsOf(ctx, "u1"); len(g) != 2 {
		t.Fatalf("expected fresh value after TTL, got %d", len(g))
	}
}

func TestCachedConcurrentMissesLoadOnce(t *testing.T) {
	o := newOrigin(t)
	o.gate = make(chan struct{})
	mr := miniredis.RunT(t)
	c := NewCached(o, o, redis.NewClient(&redis.Options{Addr: mr.Addr()}), CacheOptions{})
	const n = 50
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			g, err := c.GrantsOf(context.Background(), "u1")
			if err == nil && len(g) != 1 {
				err = errors.New("wrong result")
			}
			errs <- err
		}()
	}
	deadline := time.Now().Add(5 * time.Second)
	for c.Stats().Misses < n && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	close(o.gate)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := o.grantsCalls.Load(); got != 1 {
		t.Fatalf("want 1 origin load, got %d", got)
	}
}

func TestCachedWaiterContextCancelled(t *testing.T) {
	o := newOrigin(t)
	o.gate = make(chan struct{})
	c := NewCached(o, o, nil, CacheOptions{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() { _, err := c.GrantsOf(ctx, "u1"); done <- err }()
	for o.grantsCalls.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
	close(o.gate)
	// The detached load still completes and serves the next caller.
	deadline := time.Now().Add(5 * time.Second)
	for {
		g, err := c.GrantsOf(context.Background(), "u1")
		if err != nil || len(g) != 1 {
			t.Fatal(g, err)
		}
		if o.grantsCalls.Load() == 1 || time.Now().After(deadline) {
			break
		}
	}
	if o.grantsCalls.Load() != 1 {
		t.Fatalf("cancelled caller aborted shared load: %d", o.grantsCalls.Load())
	}
}

func TestCachedLoadErrorNotCached(t *testing.T) {
	o := newOrigin(t)
	boom := errors.New("boom")
	o.failLoad = boom
	c := NewCached(o, o, nil, CacheOptions{})
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if _, err := c.GrantsOf(ctx, "u1"); !errors.Is(err, boom) {
			t.Fatal(err)
		}
	}
	if o.grantsCalls.Load() != 2 {
		t.Fatal("error was cached")
	}
}

func TestCachedDeepCopies(t *testing.T) {
	o := newOrigin(t)
	c := NewCached(o, o, nil, CacheOptions{})
	ctx := context.Background()
	for i := 0; i < 2; i++ { // miss path, then hit path
		g, _ := c.GrantsOf(ctx, "u1")
		g[0].Role.Name = "hacked"
		g[0].Role.Permissions[0].Action = "hacked"
		*g[0].ExpiresAt = time.Time{}
		p, _ := c.ApplicablePolicies(ctx, "post", "edit")
		p[0].Name = "hacked"
		p[0].Root.Conditions[0].Value[0] = "hacked"
		p[0].Root.Groups[0].Operator = "hacked"
	}
	g, _ := c.GrantsOf(ctx, "u1")
	p, _ := c.ApplicablePolicies(ctx, "post", "edit")
	if g[0].Role.Name != "editor" || g[0].Role.Permissions[0].Action != "edit" || g[0].ExpiresAt.IsZero() ||
		p[0].Name != "p1" || p[0].Root.Conditions[0].Value[0] != "u1" || p[0].Root.Groups[0].Operator != domain.Or {
		t.Fatalf("cache was mutated through returned values: %+v %+v", g, p)
	}
	if o.grantsCalls.Load() != 1 {
		t.Fatal("expected hits")
	}

	// nil slices stay nil.
	if cloneGrants(nil) != nil || clonePolicies(nil) != nil || cloneSlice[string](nil) != nil {
		t.Fatal("nil clone")
	}
	if got := clonePolicies([]domain.Policy{{Name: "x"}}); got[0].Root != nil {
		t.Fatal("nil root")
	}
	if got := cloneGroup(domain.ConditionGroup{}); got.Conditions != nil || got.Groups != nil {
		t.Fatal("nil group slices")
	}
	o.nilResult = true
	c2 := NewCached(o, o, nil, CacheOptions{})
	if g, err := c2.GrantsOf(ctx, "x"); err != nil || g != nil {
		t.Fatal(g, err)
	}
}

func TestCachedWithoutRedisLocalInvalidation(t *testing.T) {
	o := newOrigin(t)
	c := NewCached(o, o, nil, CacheOptions{})
	ctx := context.Background()
	_, _ = c.GrantsOf(ctx, "u1")
	if err := c.AssignRole(ctx, "u1", "viewer", "", nil); err != nil {
		t.Fatal(err)
	}
	if g, _ := c.GrantsOf(ctx, "u1"); len(g) != 2 {
		t.Fatal("local write not visible")
	}
	// A failed write still invalidates (it may have committed).
	o.failWrite = errors.New("timeout after commit")
	r, _ := domain.NewRole("x", "x", "", false)
	if err := c.CreateRole(ctx, r); err == nil {
		t.Fatal("want error")
	}
	before := o.grantsCalls.Load()
	_, _ = c.GrantsOf(ctx, "u1")
	if o.grantsCalls.Load() != before+1 {
		t.Fatal("failed write did not invalidate")
	}
}

func TestCachedRedisDownBypasses(t *testing.T) {
	o := newOrigin(t)
	mr := miniredis.RunT(t)
	var errCount atomic.Int64
	c := NewCached(o, o, redis.NewClient(&redis.Options{Addr: mr.Addr(), MaxRetries: -1}),
		CacheOptions{OnError: func(error) { errCount.Add(1) }})
	ctx := context.Background()
	_, _ = c.GrantsOf(ctx, "u1") // cached while Redis is up
	mr.Close()
	for i := 0; i < 3; i++ {
		if g, err := c.GrantsOf(ctx, "u1"); err != nil || len(g) != 1 {
			t.Fatal(g, err)
		}
	}
	if o.grantsCalls.Load() != 4 {
		t.Fatalf("Redis down must bypass cache, loads=%d", o.grantsCalls.Load())
	}
	if err := c.AssignRole(ctx, "u1", "viewer", "", nil); err != nil {
		t.Fatal(err)
	}
	s := c.Stats()
	if s.Bypasses != 3 || s.InvalidationFailures != 1 || errCount.Load() != 4 {
		t.Fatalf("stats %+v errs %d", s, errCount.Load())
	}
}

// failHook fails the first command whose name matches.
type failHook struct{ cmd string }

func (h *failHook) DialHook(next redis.DialHook) redis.DialHook { return next }
func (h *failHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}
func (h *failHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		if strings.EqualFold(cmd.Name(), h.cmd) {
			h.cmd = ""
			err := errors.New("injected")
			cmd.SetErr(err)
			return err
		}
		return next(ctx, cmd)
	}
}

func TestCachedRedisCommandFailures(t *testing.T) {
	for _, tc := range []struct {
		cmd       string
		invalFail bool
	}{{"set", false}, {"get", false}, {"incr", true}} {
		t.Run(tc.cmd, func(t *testing.T) {
			o := newOrigin(t)
			mr := miniredis.RunT(t)
			rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
			c := NewCached(o, o, rdb, CacheOptions{})
			ctx := context.Background()
			h := &failHook{cmd: tc.cmd}
			rdb.AddHook(h)
			if tc.invalFail {
				if err := c.AssignRole(ctx, "u1", "viewer", "", nil); err != nil {
					t.Fatal(err)
				}
				if c.Stats().InvalidationFailures != 1 {
					t.Fatal("incr failure not recorded")
				}
				return
			}
			if _, err := c.GrantsOf(ctx, "u1"); err != nil {
				t.Fatal(err)
			}
			if c.Stats().Bypasses != 1 {
				t.Fatalf("stats %+v", c.Stats())
			}
		})
	}
	// SETNX failure on the write path.
	o := newOrigin(t)
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	rdb.AddHook(&failHook{cmd: "set"})
	c := NewCached(o, o, rdb, CacheOptions{})
	_ = c.AssignRole(context.Background(), "u1", "viewer", "", nil)
	if c.Stats().InvalidationFailures != 1 {
		t.Fatal("setnx failure on write not recorded")
	}
}

func TestCachedBoundedEviction(t *testing.T) {
	o := newOrigin(t)
	c := NewCached(o, o, nil, CacheOptions{MaxEntries: 2, TTL: time.Minute})
	now := time.Now()
	c.now = func() time.Time { return now }
	ctx := context.Background()
	_, _ = c.GrantsOf(ctx, "a")
	_, _ = c.GrantsOf(ctx, "b")
	_, _ = c.GrantsOf(ctx, "a") // existing key refresh never evicts
	_, _ = c.GrantsOf(ctx, "c") // full, nothing expired: clear all
	if s := c.Stats(); s.Evictions != 2 || len(c.grants.entries) != 1 {
		t.Fatalf("stats %+v entries %d", s, len(c.grants.entries))
	}
	_, _ = c.GrantsOf(ctx, "d")
	now = now.Add(2 * time.Minute)
	_, _ = c.GrantsOf(ctx, "e") // both expired: swept, not cleared
	if s := c.Stats(); s.Evictions != 4 || len(c.grants.entries) != 1 {
		t.Fatalf("stats %+v entries %d", s, len(c.grants.entries))
	}
	_, _ = c.GrantsOf(ctx, "f")
	_ = c.AssignRole(ctx, "u1", "viewer", "", nil) // old version entries are dead
	_, _ = c.ApplicablePolicies(ctx, "post", "edit")
	_, _ = c.GrantsOf(ctx, "g")
	if s := c.Stats(); s.Evictions != 6 || len(c.grants.entries) != 1 {
		t.Fatalf("stats %+v entries %d", s, len(c.grants.entries))
	}
}

func TestCachedDefaults(t *testing.T) {
	c := NewCached(NewMemory(), NewMemory(), nil, CacheOptions{})
	if c.ttl != DefaultCacheTTL || c.max != DefaultCacheMaxEntries || c.loadTimeout != DefaultCacheLoadTimeout ||
		c.versionKey != "guard:access:version" {
		t.Fatalf("%+v", c)
	}
	c.onError(errors.New("noop"))
}
