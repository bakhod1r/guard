package infrastructure

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/bakhod1r/guard/access/domain"
)

// Cache defaults.
//
// Staleness contract:
//   - A write made through any Cached instance sharing the Redis version key is
//     visible to every instance on its next read (the version is read per request).
//   - A write that bypasses Cached (raw SQL, host-table ON DELETE CASCADE, another
//     tool) or whose version INCR failed is visible after at most TTL.
//   - When Redis is unreachable every read goes to the origin: slower, never staler.
const (
	DefaultCacheTTL         = 30 * time.Second
	DefaultCacheMaxEntries  = 10_000
	DefaultCacheLoadTimeout = 5 * time.Second
	defaultCachePrefix      = "guard:"
)

// CacheOptions configures NewCached. The zero value is a safe default.
type CacheOptions struct {
	// TTL bounds staleness for writes that bypass the decorator. <= 0 means DefaultCacheTTL.
	TTL time.Duration
	// Prefix namespaces the Redis version key ("<prefix>access:version"). Empty means "guard:".
	Prefix string
	// MaxEntries bounds each in-process map (grants per user, policies per target). <= 0 means default.
	MaxEntries int
	// LoadTimeout bounds one shared origin load. The load is detached from the
	// caller's context so one cancelled request cannot fail its coalesced peers. <= 0 means default.
	LoadTimeout time.Duration
	// OnError receives Redis failures. The cache then bypasses to the origin; it never fails a request.
	OnError func(error)
	// L2 also stores the loaded values in Redis, shared by every instance behind
	// the load balancer: an in-process miss on one instance is served from the copy
	// another instance loaded instead of from the origin. Requires a non-nil Redis
	// client; ignored otherwise. Entries are namespaced by the version key, so a
	// write invalidates L1 and L2 together.
	L2 bool
	// L2TTL bounds how long a shared Redis entry survives. <= 0 means twice TTL.
	L2TTL time.Duration
}

// CacheStats are cumulative counters for hit-ratio and bypass dashboards.
type CacheStats struct {
	Hits, Misses, Bypasses, Evictions, InvalidationFailures uint64
	// L2Hits/L2Misses count shared-Redis lookups, made only on an in-process miss.
	// SerializeFailures counts unreadable or unwritable L2 payloads (the origin
	// still answers). L2Distrusted counts reads that skipped L2 because an
	// invalidation had failed.
	L2Hits, L2Misses, SerializeFailures, L2Distrusted uint64
}

type cacheEntry[T any] struct {
	version string
	expires time.Time
	value   T
}

type flight[T any] struct {
	done  chan struct{}
	value T
	err   error
}

// store is a bounded version-tagged map with request coalescing per version+key.
type store[T any] struct {
	mu       sync.Mutex
	entries  map[string]cacheEntry[T]
	inflight map[string]*flight[T]
	clone    func(T) T
}

// Cached decorates Role/Policy repositories with an in-process cache for the
// authorization hot path (GrantsOf, ApplicablePolicies). Every other read goes to
// the origin so admin screens are always fresh. Every returned value is a deep
// copy: callers may mutate it freely.
type Cached struct {
	domain.RoleRepository
	domain.PolicyRepository

	rdb         redis.UniversalClient
	versionKey  string
	l2Prefix    string
	l2          bool
	l2TTL       time.Duration
	ttl         time.Duration
	max         int
	loadTimeout time.Duration
	onError     func(error)
	now         func() time.Time
	epoch       atomic.Uint64 // local writes; keeps this instance fresh without Redis
	// l2DistrustUntil is a UnixNano deadline: a failed invalidation may have left
	// the shared version unmoved, so L2 is neither read nor written until it passes.
	l2DistrustUntil atomic.Int64

	grants   *store[[]domain.RoleGrant]
	policies *store[[]domain.Policy]

	hits, misses, bypasses, evictions, invalidationFailures atomic.Uint64
	l2Hits, l2Misses, serializeFailures, l2DistrustedReads  atomic.Uint64
}

// NewCached wraps roles and policies. rdb may be nil only for a single-instance
// deployment; with several instances pass the shared Redis so writes invalidate everywhere.
func NewCached(roles domain.RoleRepository, policies domain.PolicyRepository, rdb redis.UniversalClient, opts CacheOptions) *Cached {
	if opts.TTL <= 0 {
		opts.TTL = DefaultCacheTTL
	}
	if opts.Prefix == "" {
		opts.Prefix = defaultCachePrefix
	}
	if opts.MaxEntries <= 0 {
		opts.MaxEntries = DefaultCacheMaxEntries
	}
	if opts.LoadTimeout <= 0 {
		opts.LoadTimeout = DefaultCacheLoadTimeout
	}
	if opts.OnError == nil {
		opts.OnError = func(error) {}
	}
	if opts.L2TTL <= 0 {
		opts.L2TTL = 2 * opts.TTL
	}
	return &Cached{
		RoleRepository: roles, PolicyRepository: policies,
		rdb: rdb, versionKey: opts.Prefix + "access:version",
		l2Prefix: opts.Prefix + "access:l2:", l2: opts.L2 && rdb != nil, l2TTL: opts.L2TTL,
		ttl: opts.TTL, max: opts.MaxEntries, loadTimeout: opts.LoadTimeout, onError: opts.OnError, now: time.Now,
		grants:   &store[[]domain.RoleGrant]{entries: map[string]cacheEntry[[]domain.RoleGrant]{}, inflight: map[string]*flight[[]domain.RoleGrant]{}, clone: cloneGrants},
		policies: &store[[]domain.Policy]{entries: map[string]cacheEntry[[]domain.Policy]{}, inflight: map[string]*flight[[]domain.Policy]{}, clone: clonePolicies},
	}
}

// Stats returns cumulative counters. Hit ratio = Hits / (Hits + Misses + Bypasses).
func (c *Cached) Stats() CacheStats {
	return CacheStats{Hits: c.hits.Load(), Misses: c.misses.Load(), Bypasses: c.bypasses.Load(),
		Evictions: c.evictions.Load(), InvalidationFailures: c.invalidationFailures.Load(),
		L2Hits: c.l2Hits.Load(), L2Misses: c.l2Misses.Load(),
		SerializeFailures: c.serializeFailures.Load(), L2Distrusted: c.l2DistrustedReads.Load()}
}

// randomSeed is a random 62-bit start value. After a Redis flush the counter
// restarts from a new random seed, so it cannot reproduce a version an entry
// was tagged with before the flush (collision probability ~2^-62 per flush).
func randomSeed() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return strconv.FormatUint(binary.BigEndian.Uint64(b[:])>>2, 10)
}

// seed installs a random counter if the key is missing (cold start or flush).
func (c *Cached) seed(ctx context.Context) error {
	return c.rdb.SetNX(ctx, c.versionKey, randomSeed(), 0).Err()
}

// version returns the current cache generation. ok=false means freshness cannot
// be proven (Redis error) and the caller must bypass the cache.
func (c *Cached) version(ctx context.Context) (string, bool) {
	local := strconv.FormatUint(c.epoch.Load(), 10)
	if c.rdb == nil {
		return local, true
	}
	token, err := c.rdb.Get(ctx, c.versionKey).Result()
	if errors.Is(err, redis.Nil) {
		if err = c.seed(ctx); err == nil {
			token, err = c.rdb.Get(ctx, c.versionKey).Result()
		}
	}
	if err != nil {
		c.onError(err)
		return "", false
	}
	return local + "/" + token, true
}

// invalidate runs after every write attempt, including failed ones: an error
// returned after COMMIT reached the server (timeout, dropped connection) may
// still have changed data, so the cache never assumes a failed write did nothing.
func (c *Cached) invalidate(ctx context.Context) {
	c.epoch.Add(1)
	if c.rdb == nil {
		return
	}
	// Invalidation must happen even if the request context was just cancelled.
	ctx = context.WithoutCancel(ctx)
	err := c.seed(ctx)
	if err == nil {
		err = c.rdb.Incr(ctx, c.versionKey).Err()
	}
	if err != nil {
		c.invalidationFailures.Add(1)
		c.onError(err)
		// The shared version may not have moved, so every L2 entry this write made
		// stale would still look current. Stop trusting L2 until they expire.
		c.l2DistrustUntil.Store(c.now().Add(c.l2TTL).UnixNano())
	}
}

// l2Kind namespaces the two cached reads inside the L2 key space.
type l2Kind string

const (
	l2Grants   l2Kind = "g"
	l2Policies l2Kind = "p"
)

// l2Token is the shared half of the version: the Redis counter, without this
// instance's local epoch. Every instance behind the load balancer computes the
// same token, so they share one set of L2 keys.
func (c *Cached) l2Token(ctx context.Context) (string, bool) {
	version, ok := c.version(ctx)
	if !ok {
		return "", false
	}
	_, token, found := strings.Cut(version, "/")
	return token, found
}

func (c *Cached) l2Key(token string, kind l2Kind, key string) string {
	return c.l2Prefix + token + ":" + string(kind) + ":" + key
}

// l2Trusted reports whether a failed invalidation window is still open.
func (c *Cached) l2Trusted() bool {
	until := c.l2DistrustUntil.Load()
	return until == 0 || c.now().UnixNano() >= until
}

// l2Load wraps an origin load with the shared Redis copy. Redis never fails a
// request: any error falls through to the origin.
func l2Load[T any](c *Cached, kind l2Kind, key string, load func(context.Context) (T, error)) func(context.Context, string) (T, error) {
	return func(ctx context.Context, version string) (T, error) {
		if !c.l2 {
			return load(ctx)
		}
		if !c.l2Trusted() {
			c.l2DistrustedReads.Add(1)
			return load(ctx)
		}
		_, token, found := strings.Cut(version, "/")
		if !found {
			return load(ctx)
		}
		redisKey := c.l2Key(token, kind, key)

		raw, err := c.rdb.Get(ctx, redisKey).Bytes()
		switch {
		case err == nil:
			var value T
			if err = json.Unmarshal(raw, &value); err == nil {
				c.l2Hits.Add(1)
				return value, nil
			}
			c.serializeFailures.Add(1)
			c.onError(err)
		case errors.Is(err, redis.Nil):
			c.l2Misses.Add(1)
		default:
			c.onError(err)
			return load(ctx) // Redis is unreachable: do not try to write back.
		}

		value, err := load(ctx)
		if err != nil {
			return value, err
		}
		c.storeL2(ctx, redisKey, value)
		return value, nil
	}
}

func (c *Cached) storeL2(ctx context.Context, key string, value any) {
	if !c.l2Trusted() {
		return
	}
	raw, err := json.Marshal(value)
	if err != nil {
		c.serializeFailures.Add(1)
		c.onError(err)
		return
	}
	if err := c.rdb.Set(ctx, key, raw, c.l2TTL).Err(); err != nil {
		c.onError(err)
	}
}

func cachedLoad[T any](ctx context.Context, c *Cached, s *store[T], key string, load func(context.Context, string) (T, error)) (T, error) {
	var zero T
	// The version is read BEFORE loading: a write racing the load bumps it, so
	// the (possibly stale) result is stored under an already-dead tag.
	version, ok := c.version(ctx)
	if !ok {
		c.bypasses.Add(1)
		return load(ctx, "")
	}
	now := c.now()
	s.mu.Lock()
	if e, hit := s.entries[key]; hit && e.version == version && now.Before(e.expires) {
		s.mu.Unlock()
		c.hits.Add(1)
		return s.clone(e.value), nil
	}
	c.misses.Add(1)
	fk := version + "\x00" + key
	f := s.inflight[fk]
	if f == nil {
		f = &flight[T]{done: make(chan struct{})}
		s.inflight[fk] = f
		go runFlight(ctx, c, s, f, fk, key, version, now, load)
	}
	s.mu.Unlock()
	select {
	case <-f.done:
		if f.err != nil {
			return zero, f.err
		}
		return s.clone(f.value), nil
	case <-ctx.Done():
		return zero, ctx.Err()
	}
}

// runFlight performs one coalesced origin load detached from any single caller.
func runFlight[T any](ctx context.Context, c *Cached, s *store[T], f *flight[T], fk, key, version string, now time.Time, load func(context.Context, string) (T, error)) {
	lctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), c.loadTimeout)
	defer cancel()
	f.value, f.err = load(lctx, version)

	s.mu.Lock()
	delete(s.inflight, fk)
	if f.err == nil {
		if _, exists := s.entries[key]; !exists && len(s.entries) >= c.max {
			c.evictions.Add(uint64(s.sweep(now, version, c.max))) //nolint:gosec // sweep count is non-negative
		}
		s.entries[key] = cacheEntry[T]{version: version, expires: now.Add(c.ttl), value: f.value}
	}
	s.mu.Unlock()
	close(f.done)
}

// sweep drops expired and dead-version entries; if still full it drops everything
// (simple, O(n) once per overflow, bounded memory). Caller holds s.mu.
func (s *store[T]) sweep(now time.Time, version string, limit int) int {
	n := 0
	for k, e := range s.entries {
		if e.version != version || !now.Before(e.expires) {
			delete(s.entries, k)
			n++
		}
	}
	if len(s.entries) >= limit {
		n += len(s.entries)
		clear(s.entries)
	}
	return n
}

func cloneGrants(in []domain.RoleGrant) []domain.RoleGrant {
	if in == nil {
		return nil
	}
	out := make([]domain.RoleGrant, len(in))
	for i, g := range in {
		out[i] = g
		out[i].Role.Permissions = cloneSlice(g.Role.Permissions)
		if g.ExpiresAt != nil {
			t := *g.ExpiresAt
			out[i].ExpiresAt = &t
		}
	}
	return out
}

func clonePolicies(in []domain.Policy) []domain.Policy {
	if in == nil {
		return nil
	}
	out := make([]domain.Policy, len(in))
	for i, p := range in {
		out[i] = p
		if p.Root != nil {
			root := cloneGroup(*p.Root)
			out[i].Root = &root
		}
	}
	return out
}

func cloneGroup(g domain.ConditionGroup) domain.ConditionGroup {
	out := g
	if g.Conditions != nil {
		out.Conditions = make([]domain.Condition, len(g.Conditions))
		for i, cond := range g.Conditions {
			out.Conditions[i] = cond
			out.Conditions[i].Value = cloneSlice(cond.Value)
		}
	}
	if g.Groups != nil {
		out.Groups = make([]domain.ConditionGroup, len(g.Groups))
		for i, child := range g.Groups {
			out.Groups[i] = cloneGroup(child)
		}
	}
	return out
}

func cloneSlice[T any](in []T) []T {
	if in == nil {
		return nil
	}
	return append(make([]T, 0, len(in)), in...)
}

// ---------- cached reads ----------

func (c *Cached) GrantsOf(ctx context.Context, userID string) ([]domain.RoleGrant, error) {
	return cachedLoad(ctx, c, c.grants, userID, l2Load(c, l2Grants, userID,
		func(ctx context.Context) ([]domain.RoleGrant, error) {
			return c.RoleRepository.GrantsOf(ctx, userID)
		}))
}

func (c *Cached) ApplicablePolicies(ctx context.Context, resource, action string) ([]domain.Policy, error) {
	key := resource + "\x00" + action
	return cachedLoad(ctx, c, c.policies, key, l2Load(c, l2Policies, resource+":"+action,
		func(ctx context.Context) ([]domain.Policy, error) {
			return c.PolicyRepository.ApplicablePolicies(ctx, resource, action)
		}))
}

// ---------- writes: origin first, then invalidate ----------

func (c *Cached) CreateRole(ctx context.Context, r *domain.Role) error {
	err := c.RoleRepository.CreateRole(ctx, r)
	c.invalidate(ctx)
	return err
}

func (c *Cached) DeleteRole(ctx context.Context, name string) error {
	err := c.RoleRepository.DeleteRole(ctx, name)
	c.invalidate(ctx)
	return err
}

func (c *Cached) CreatePermission(ctx context.Context, p domain.Permission) error {
	err := c.RoleRepository.CreatePermission(ctx, p)
	c.invalidate(ctx)
	return err
}

func (c *Cached) GrantPermission(ctx context.Context, role string, p domain.Permission, grantedBy string) error {
	err := c.RoleRepository.GrantPermission(ctx, role, p, grantedBy)
	c.invalidate(ctx)
	return err
}

func (c *Cached) RevokePermission(ctx context.Context, role string, p domain.Permission) error {
	err := c.RoleRepository.RevokePermission(ctx, role, p)
	c.invalidate(ctx)
	return err
}

func (c *Cached) AssignRole(ctx context.Context, userID, role, grantedBy string, expiresAt *time.Time) error {
	err := c.RoleRepository.AssignRole(ctx, userID, role, grantedBy, expiresAt)
	c.invalidate(ctx)
	return err
}

func (c *Cached) UnassignRole(ctx context.Context, userID, role string) error {
	err := c.RoleRepository.UnassignRole(ctx, userID, role)
	c.invalidate(ctx)
	return err
}

func (c *Cached) SavePolicy(ctx context.Context, p *domain.Policy) error {
	err := c.PolicyRepository.SavePolicy(ctx, p)
	c.invalidate(ctx)
	return err
}

func (c *Cached) DeletePolicy(ctx context.Context, id string) error {
	err := c.PolicyRepository.DeletePolicy(ctx, id)
	c.invalidate(ctx)
	return err
}

var (
	_ domain.RoleRepository   = (*Cached)(nil)
	_ domain.PolicyRepository = (*Cached)(nil)
)

// RoleHolders reads the origin (admin path, never cached).
func (c *Cached) RoleHolders(ctx context.Context, role string) ([]string, error) {
	h, ok := c.RoleRepository.(domain.RoleHolderRepository)
	if !ok {
		return nil, domain.ErrHoldersUnsupported
	}
	return h.RoleHolders(ctx, role)
}

// UnassignRoleChecked delegates to the origin, then invalidates.
func (c *Cached) UnassignRoleChecked(ctx context.Context, userID, role string, check func([]string) error) error {
	h, ok := c.RoleRepository.(domain.RoleHolderRepository)
	if !ok {
		return domain.ErrHoldersUnsupported
	}
	err := h.UnassignRoleChecked(ctx, userID, role, check)
	c.invalidate(ctx)
	return err
}
