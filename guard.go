// Package guard wires identity, sessions, RBAC/ABAC and audit into one entry point.
//
//	g, _ := guard.New(guard.Config{DB: pool, Redis: rdb, UserTable: "users", UserIDColumn: "id"})
//	_, _ = g.WriteMigrations(ctx, "./migrations/guard") // detects users.id type, renders SQL
//	_ = g.Migrate(ctx, "./migrations/guard")
//	ginguard.Mount(router.Group("/api"), g, ginguard.Options{})
package guard

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	accessapp "github.com/bakhod1r/guard/access/application"
	accessdomain "github.com/bakhod1r/guard/access/domain"
	accessinfra "github.com/bakhod1r/guard/access/infrastructure"
	apikeyapp "github.com/bakhod1r/guard/apikey/application"
	apikeydomain "github.com/bakhod1r/guard/apikey/domain"
	apikeyinfra "github.com/bakhod1r/guard/apikey/infrastructure"
	"github.com/bakhod1r/guard/audit"
	identityapp "github.com/bakhod1r/guard/identity/application"
	identitydomain "github.com/bakhod1r/guard/identity/domain"
	identityinfra "github.com/bakhod1r/guard/identity/infrastructure"
	"github.com/bakhod1r/guard/kernel/migrations"
	"github.com/bakhod1r/guard/ratelimit"
	sessionapp "github.com/bakhod1r/guard/session/application"
	sessiondomain "github.com/bakhod1r/guard/session/domain"
	sessioninfra "github.com/bakhod1r/guard/session/infrastructure"
)

// Re-exported domain types so host apps need a single import.
type (
	User          = identitydomain.User
	Status        = identitydomain.Status
	Lockout       = identitydomain.Lockout
	Session       = sessiondomain.Session
	SessionToken  = sessiondomain.Token
	SessionPolicy = sessiondomain.Policy
	Role          = accessdomain.Role
	RoleGrant     = accessdomain.RoleGrant
	Permission    = accessdomain.Permission
	Policy        = accessdomain.Policy
	Resource      = accessdomain.Resource
	Decision      = accessdomain.Decision
	AuditEvent    = audit.Event
	APIKey        = apikeydomain.Key
	APIKeyToken   = apikeydomain.Token
	// AccessCacheOptions configures Config.AccessCache.
	AccessCacheOptions = accessinfra.CacheOptions
	AccessCacheStats   = accessinfra.CacheStats
)

var ErrSessionRequired = errors.New("guard: this operation requires a session, not an API key")

type Config struct {
	DB    *pgxpool.Pool
	Redis redis.UniversalClient
	// RedisPrefix namespaces session keys. Default "guard:".
	RedisPrefix string
	// Session lifetime. Each zero field uses its default (30m idle / 7d absolute).
	Session SessionPolicy
	// Lockout for password guessing. Each zero field uses its default (5 attempts / 15m).
	Lockout Lockout
	// DefaultRole is assigned on CreateAccount. Default "user"; "-" disables.
	DefaultRole string
	// UserTable is the host application's existing user table ("users" or
	// "schema.users"). Guard never creates it; its tables reference it. Default "users".
	UserTable string
	// UserIDColumn is the primary key (or unique) column of UserTable. Default "id".
	UserIDColumn string
	// Logger receives operational events (audit write failures at Warn, failed
	// logins at Info). Raw emails, passwords and tokens are never logged.
	// Default slog.Default().
	Logger *slog.Logger
	// AsyncAudit > 0 writes audit events through a non-blocking buffer of this
	// size; overflow is dropped and counted. 0 (default) writes synchronously.
	// Call Guard.Close on shutdown to flush.
	AsyncAudit int
	// AuditBuffer queues audit events in Redis and batch-writes them to
	// PostgreSQL. When Enabled, AsyncAudit is ignored.
	AuditBuffer AuditBuffer
	// AccessCache enables the in-process role/policy cache for authorization
	// (invalidated cluster-wide through Redis). nil (default) disables it.
	// Empty Prefix uses RedisPrefix; nil OnError logs at Warn.
	AccessCache *accessinfra.CacheOptions
	// PasswordHashParams overrides argon2id parameters; values below the OWASP
	// floor make New fail. nil uses secure defaults. Legacy bcrypt hashes are
	// always verified and upgraded on login.
	PasswordHashParams *PasswordHashParams
	// AuditEmailKey (>= 32 random bytes, keep secret) makes login audit events
	// store "email_hmac" (hex HMAC-SHA256, first 16 bytes) instead of the
	// unkeyed "email_sha256" fingerprint, which is brute-forceable from a list
	// of known addresses. Raw emails are never stored in audit metadata.
	AuditEmailKey []byte
}

// minAuditEmailKeyLen is the HMAC-SHA256 key floor for Config.AuditEmailKey.
const minAuditEmailKeyLen = 32

// PasswordHashParams are argon2id parameters (Memory in KiB).
type PasswordHashParams struct {
	Memory, Time    uint32
	Threads         uint8
	KeyLen, SaltLen uint32
}

func passwordHasher(p *PasswordHashParams) (*identityinfra.MultiHasher, error) {
	if p == nil {
		return identityinfra.NewMultiHasher(nil), nil
	}
	a, err := identityinfra.NewArgon2HasherWithParams(p.Memory, p.Time, p.Threads, p.KeyLen, p.SaltLen)
	if err != nil {
		return nil, err
	}
	return identityinfra.NewMultiHasher(a), nil
}

func accessCacheOptions(o accessinfra.CacheOptions, prefix string, logger *slog.Logger) accessinfra.CacheOptions {
	if o.Prefix == "" {
		o.Prefix = prefix
	}
	if o.OnError == nil {
		o.OnError = func(err error) {
			logger.Warn("guard: access cache redis failure, bypassing cache", "error", err.Error())
		}
	}
	return o
}

// AuditBuffer configures the Redis-backed audit queue. Events are pushed to the
// Redis list <RedisPrefix>audit:queue and flushed every Interval (default 1s)
// in batches of BatchSize (default 500). The queue survives process restarts
// and is shared by every instance. When Redis is unavailable events fall back
// to direct PostgreSQL writes. Call Guard.Close on shutdown to drain it.
type AuditBuffer struct {
	Enabled   bool
	BatchSize int
	Interval  time.Duration
}

type Guard struct {
	Identity *identityapp.Service
	Sessions *sessionapp.Service
	Access   *accessapp.Service
	APIKeys  *apikeyapp.Service
	Audit    audit.Log
	// Limiter is nil when no Redis-backed limiter was configured.
	Limiter ratelimit.Limiter

	db          *pgxpool.Pool
	redis       redis.UniversalClient
	logger      *slog.Logger
	asyncAudit  *audit.Async
	auditBuffer *audit.RedisBuffer
	defaultRole string
	accessCache *accessinfra.Cached
	cachePrefix string
	userTable   string
	userColumn  string
	// auditEmailKey is a private copy of Config.AuditEmailKey.
	auditEmailKey []byte
}

func New(cfg Config) (*Guard, error) {
	if cfg.DB == nil || cfg.Redis == nil {
		return nil, errors.New("guard: Config.DB and Config.Redis are required")
	}
	if len(cfg.AuditEmailKey) > 0 && len(cfg.AuditEmailKey) < minAuditEmailKeyLen {
		return nil, fmt.Errorf("guard: Config.AuditEmailKey must be at least %d bytes", minAuditEmailKeyLen)
	}
	hasher, err := passwordHasher(cfg.PasswordHashParams)
	if err != nil {
		return nil, err
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	pg := accessinfra.NewPostgres(cfg.DB)
	var roles accessdomain.RoleRepository = pg
	var policies accessdomain.PolicyRepository = pg
	var cached *accessinfra.Cached
	var cachePrefix string
	if cfg.AccessCache != nil {
		opts := accessCacheOptions(*cfg.AccessCache, cfg.RedisPrefix, logger)
		cached = accessinfra.NewCached(pg, pg, cfg.Redis, opts)
		roles, policies, cachePrefix = cached, cached, opts.Prefix
		if cachePrefix == "" {
			cachePrefix = "guard:"
		}
	}
	var auditLog audit.Log = audit.NewPostgres(cfg.DB)
	var buffer *audit.RedisBuffer
	if cfg.AuditBuffer.Enabled {
		buffer = audit.NewRedisBuffer(cfg.Redis, auditLog, audit.RedisBufferConfig{
			Prefix: cfg.RedisPrefix, BatchSize: cfg.AuditBuffer.BatchSize,
			Interval: cfg.AuditBuffer.Interval, Logger: logger,
		})
		auditLog = buffer
		cfg.AsyncAudit = 0
	}
	g := Build(Repositories{
		Users:    identityinfra.NewPostgresUsers(cfg.DB),
		Hasher:   hasher,
		Sessions: sessioninfra.NewRedisSessions(cfg.Redis, cfg.RedisPrefix),
		Roles:    roles,
		Policies: policies,
		Audit:    auditLog,
		APIKeys:  apikeyinfra.NewPostgres(cfg.DB),
		Limiter:  ratelimit.NewRedis(cfg.Redis, cfg.RedisPrefix),
	}, cfg)
	g.db, g.redis, g.auditBuffer = cfg.DB, cfg.Redis, buffer
	g.accessCache, g.cachePrefix = cached, cachePrefix
	return g, nil
}

// Repositories lets callers swap storage (tests, other databases).
type Repositories struct {
	Users    identitydomain.UserRepository
	Hasher   identitydomain.PasswordHasher
	Sessions sessiondomain.Repository
	Roles    accessdomain.RoleRepository
	Policies accessdomain.PolicyRepository
	Audit    audit.Log
	APIKeys  apikeydomain.Repository
	Limiter  ratelimit.Limiter
}

func Build(r Repositories, cfg Config) *Guard {
	cfg.Session = sessionPolicy(cfg.Session)
	cfg.Lockout = lockoutPolicy(cfg.Lockout)
	switch cfg.DefaultRole {
	case "":
		cfg.DefaultRole = "user"
	case "-":
		cfg.DefaultRole = ""
	}
	if cfg.UserTable == "" {
		cfg.UserTable = "users"
	}
	if cfg.UserIDColumn == "" {
		cfg.UserIDColumn = "id"
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	var asyncAudit *audit.Async
	if cfg.AsyncAudit > 0 && r.Audit != nil {
		asyncAudit = audit.NewAsync(r.Audit, cfg.AsyncAudit, cfg.Logger)
		r.Audit = asyncAudit
	}
	g := &Guard{
		logger:        cfg.Logger,
		asyncAudit:    asyncAudit,
		userTable:     cfg.UserTable,
		userColumn:    cfg.UserIDColumn,
		auditEmailKey: append([]byte(nil), cfg.AuditEmailKey...),
		Identity:      identityapp.NewService(r.Users, r.Hasher, cfg.Lockout),
		Sessions:      sessionapp.NewService(r.Sessions, cfg.Session),
		Access:        accessapp.NewService(r.Roles, r.Policies),
		APIKeys:       apikeyapp.NewService(r.APIKeys),
		Audit:         r.Audit,
		Limiter:       r.Limiter,
		defaultRole:   cfg.DefaultRole,
	}
	g.Access.SetSuperAdminBlocked(g.superAdminBlocked)
	return g
}

// sessionPolicy fills each zero field separately: a policy that only sets
// MaxPerUser must not get zero timeouts (sessions would expire immediately).
func sessionPolicy(p SessionPolicy) SessionPolicy {
	def := sessiondomain.DefaultPolicy()
	if p.IdleTimeout == 0 {
		p.IdleTimeout = def.IdleTimeout
	}
	if p.AbsoluteTimeout == 0 {
		p.AbsoluteTimeout = def.AbsoluteTimeout
	}
	return p
}

func lockoutPolicy(l Lockout) Lockout {
	def := identitydomain.DefaultLockout()
	if l.MaxAttempts == 0 {
		l.MaxAttempts = def.MaxAttempts
	}
	if l.Duration == 0 {
		l.Duration = def.Duration
	}
	return l
}

// AccessStats returns access cache counters; ok is false when Config.AccessCache is nil.
func (g *Guard) AccessStats() (stats accessinfra.CacheStats, ok bool) {
	if g.accessCache == nil {
		return stats, false
	}
	return g.accessCache.Stats(), true
}

// InvalidateAccess drops cached role grants and policies on every instance.
// Call it after changes that bypass Guard, e.g. deleting a host user (ON
// DELETE CASCADE). No-op without Config.AccessCache.
func (g *Guard) InvalidateAccess(ctx context.Context) error {
	if g.accessCache == nil {
		return nil
	}
	key := g.cachePrefix + "access:version"
	ctx = context.WithoutCancel(ctx)
	// Same protocol as accessinfra.Cached: seed a random base so a flushed key
	// never reuses an old generation, then INCR.
	err := g.redis.SetNX(ctx, key, strconv.FormatUint(rand.Uint64()>>2, 10), 0).Err() //nolint:gosec // cache generation seed, not security-sensitive
	if err == nil {
		err = g.redis.Incr(ctx, key).Err()
	}
	if err != nil {
		return fmt.Errorf("guard: invalidate access cache: %w", err)
	}
	return nil
}

// RotateSession replaces a session token (call after login or privilege
// change) and records session.rotate. The old token stops working.
func (g *Guard) RotateSession(ctx context.Context, token SessionToken) (*Session, SessionToken, error) {
	s, tok, err := g.Sessions.Rotate(ctx, token)
	if err != nil {
		return nil, "", err
	}
	g.record(ctx, audit.Event{ActorID: s.UserID, Action: "session.rotate", Target: s.UserID, Success: true})
	return s, tok, nil
}

// UserRef inspects the database and resolves the host user table and its id column type.
func (g *Guard) UserRef(ctx context.Context) (migrations.UserRef, error) {
	if g.db == nil {
		return migrations.UserRef{}, errors.New("guard: needs a PostgreSQL-backed Guard")
	}
	return migrations.Detect(ctx, g.db, g.userTable, g.userColumn)
}

// WriteMigrations detects the host user table, renders Guard's SQL migrations
// for it and writes them into dir. Existing files are never overwritten.
func (g *Guard) WriteMigrations(ctx context.Context, dir string) ([]string, error) {
	ref, err := g.UserRef(ctx)
	if err != nil {
		return nil, err
	}
	return migrations.Write(dir, ref)
}

// Migrate applies migrations from dir. dir == "" renders the embedded
// templates against the detected user table instead.
func (g *Guard) Migrate(ctx context.Context, dir string) error {
	ref, err := g.UserRef(ctx)
	if err != nil {
		return err
	}
	return migrations.Up(ctx, g.db, dir, ref)
}

// RequestMeta describes the HTTP caller for sessions and audit.
type RequestMeta struct {
	IP        string
	UserAgent string
}

func (g *Guard) record(ctx context.Context, e audit.Event) {
	if g.Audit != nil {
		if err := g.Audit.Record(ctx, e); err != nil {
			g.logger.WarnContext(ctx, "guard: audit write failed", "action", e.Action, "target", e.Target, "error", err.Error())
		}
	}
}

// healthTimeout bounds each backend ping in Health.
const healthTimeout = 2 * time.Second

// Health pings PostgreSQL and Redis, each with a 2s timeout. It returns an
// error naming every unhealthy backend, or when none is configured.
func (g *Guard) Health(ctx context.Context) error {
	if g.db == nil && g.redis == nil {
		return errors.New("guard: no backends configured")
	}
	var errs []error
	if g.db != nil {
		c, cancel := context.WithTimeout(ctx, healthTimeout)
		if err := g.db.Ping(c); err != nil {
			errs = append(errs, fmt.Errorf("guard: postgres: %w", err))
		}
		cancel()
	}
	if g.redis != nil {
		c, cancel := context.WithTimeout(ctx, healthTimeout)
		if err := g.redis.Ping(c).Err(); err != nil {
			errs = append(errs, fmt.Errorf("guard: redis: %w", err))
		}
		cancel()
	}
	return errors.Join(errs...)
}

// Close flushes buffered audit events (Config.AsyncAudit, Config.AuditBuffer)
// until done or ctx expires. It never closes the caller's database pool or
// Redis client.
func (g *Guard) Close(ctx context.Context) error {
	var errs []error
	if g.asyncAudit != nil {
		errs = append(errs, g.asyncAudit.Close(ctx))
	}
	if g.auditBuffer != nil {
		errs = append(errs, g.auditBuffer.Close(ctx))
	}
	return errors.Join(errs...)
}

// emailFingerprint lets operators correlate failed logins without storing the address.
func emailFingerprint(email string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(email))))
	return hex.EncodeToString(sum[:])[:16]
}

// auditEmail adds a non-reversible email identifier to login audit metadata:
// keyed "email_hmac" when Config.AuditEmailKey is set, else "email_sha256".
func (g *Guard) auditEmail(email string, md map[string]any) map[string]any {
	if len(g.auditEmailKey) == 0 {
		md["email_sha256"] = emailFingerprint(email)
		return md
	}
	mac := hmac.New(sha256.New, g.auditEmailKey)
	mac.Write([]byte(strings.ToLower(strings.TrimSpace(email))))
	md["email_hmac"] = hex.EncodeToString(mac.Sum(nil)[:16])
	return md
}

// CreateAccount gives an existing host user (userID from UserTable) login
// credentials, assigns DefaultRole and records an audit event.
func (g *Guard) CreateAccount(ctx context.Context, userID, email, password string, attrs map[string]any, meta RequestMeta) (*User, error) {
	u, err := g.Identity.CreateAccount(ctx, identityapp.CreateAccountInput{UserID: userID, Email: email, Password: password, Attributes: attrs})
	if err != nil {
		return nil, err
	}
	if g.defaultRole != "" {
		if err := g.Access.AssignRole(ctx, string(u.ID), g.defaultRole, "", nil); err != nil && !errors.Is(err, accessdomain.ErrRoleNotFound) {
			return nil, err
		}
	}
	g.record(ctx, audit.Event{ActorID: string(u.ID), Action: "account.create", Target: string(u.ID), Success: true, IP: meta.IP, UserAgent: meta.UserAgent})
	return u, nil
}

// ResetPassword sets a new password (admin action) and signs the user out everywhere.
func (g *Guard) ResetPassword(ctx context.Context, actorID, userID, password string) error {
	if err := g.Identity.SetPassword(ctx, identitydomain.UserID(userID), password); err != nil {
		return err
	}
	if err := g.Sessions.RevokeAll(ctx, userID); err != nil {
		return err
	}
	g.record(ctx, audit.Event{ActorID: actorID, Action: "account.password_reset", Target: userID, Success: true})
	return nil
}

type LoginResult struct {
	User    *User
	Session *Session
	Token   SessionToken
}

func (g *Guard) Login(ctx context.Context, email, password string, meta RequestMeta) (*LoginResult, error) {
	u, err := g.Identity.Authenticate(ctx, email, password)
	if err != nil {
		g.record(ctx, audit.Event{Action: "auth.login", Success: false, IP: meta.IP, UserAgent: meta.UserAgent,
			Metadata: g.auditEmail(email, map[string]any{"error": err.Error()})})
		g.logger.InfoContext(ctx, "guard: login failed", "email_sha256", emailFingerprint(email), "ip", meta.IP, "error", err.Error())
		return nil, err
	}
	s, tok, err := g.Sessions.Start(ctx, sessionapp.StartInput{UserID: string(u.ID), IP: meta.IP, UserAgent: meta.UserAgent})
	if err != nil {
		return nil, err
	}
	g.record(ctx, audit.Event{ActorID: string(u.ID), Action: "auth.login", Target: string(u.ID), Success: true, IP: meta.IP, UserAgent: meta.UserAgent,
		Metadata: g.auditEmail(email, map[string]any{})})
	return &LoginResult{User: u, Session: s, Token: tok}, nil
}

func (g *Guard) Logout(ctx context.Context, p *Principal, meta RequestMeta) error {
	if p.Session == nil {
		return ErrSessionRequired
	}
	if err := g.Sessions.Revoke(ctx, p.Session.ID); err != nil {
		return err
	}
	g.record(ctx, audit.Event{ActorID: string(p.User.ID), Action: "auth.logout", Success: true, IP: meta.IP, UserAgent: meta.UserAgent})
	return nil
}

// Principal is the authenticated caller of a request. Exactly one of
// Session and APIKey is set.
type Principal struct {
	User    *User
	Session *Session
	APIKey  *APIKey
	Roles   []Role
}

// Authenticate resolves a session token or an API key ("gk_...") into a
// principal. The user row is re-read on every call so bans and role changes
// apply immediately.
func (g *Guard) Authenticate(ctx context.Context, credential string) (*Principal, error) {
	if apikeydomain.LooksLikeKey(credential) {
		k, err := g.APIKeys.Resolve(ctx, apikeydomain.Token(credential))
		if err != nil {
			return nil, err
		}
		return g.principal(ctx, k.UserID, &Principal{APIKey: k}, func() {})
	}
	s, err := g.Sessions.Resolve(ctx, SessionToken(credential))
	if err != nil {
		return nil, err
	}
	return g.principal(ctx, s.UserID, &Principal{Session: s}, func() { _ = g.Sessions.Revoke(ctx, s.ID) })
}

func (g *Guard) principal(ctx context.Context, userID string, p *Principal, onMissingUser func()) (*Principal, error) {
	u, err := g.Identity.User(ctx, identitydomain.UserID(userID))
	if errors.Is(err, identitydomain.ErrUserNotFound) {
		onMissingUser()
		return nil, sessiondomain.ErrSessionNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := u.CanLogin(); err != nil {
		if p.Session != nil {
			_ = g.Sessions.RevokeAll(ctx, userID)
		}
		return nil, err
	}
	roles, err := g.Access.ActiveRoles(ctx, userID)
	if err != nil {
		return nil, err
	}
	p.User, p.Roles = u, roles
	return p, nil
}

// Authorize decides whether p may perform action on resource.
func (g *Guard) Authorize(ctx context.Context, p *Principal, action string, res Resource, env map[string]any) (Decision, error) {
	if p.APIKey != nil && !p.APIKey.Allows(res.Type, action) {
		return Decision{Allowed: false, Reason: "api key scope does not cover " + res.Type + "." + action}, nil
	}
	attrs := map[string]any{}
	for k, v := range p.User.Attributes {
		attrs[k] = v
	}
	attrs["email"] = string(p.User.Email)
	attrs["status"] = string(p.User.Status)
	roles := p.Roles
	if roles == nil {
		roles = []Role{}
	}
	return g.Access.Authorize(ctx, accessdomain.Request{
		Subject:     accessdomain.Subject{ID: string(p.User.ID), Roles: roles, Attributes: attrs},
		Action:      action,
		Resource:    res,
		Environment: env,
	})
}

// SetUserStatus changes account status; blocking also revokes every session.
func (g *Guard) SetUserStatus(ctx context.Context, actorID, userID string, status Status) error {
	if err := g.changeStatus(ctx, userID, status); err != nil {
		return err
	}
	if status == identitydomain.StatusBanned || status == identitydomain.StatusSuspended {
		if err := g.Sessions.RevokeAll(ctx, userID); err != nil {
			return err
		}
	}
	g.record(ctx, audit.Event{ActorID: actorID, Action: "user.status", Target: userID, Success: true, Metadata: map[string]any{"status": string(status)}})
	return nil
}

// IssueAPIKey creates a key for p's user. Only session principals may issue
// keys, so a leaked key cannot mint more keys.
func (g *Guard) IssueAPIKey(ctx context.Context, p *Principal, name string, scopes []string, expiresAt *time.Time, meta RequestMeta) (*APIKey, APIKeyToken, error) {
	if p.Session == nil {
		return nil, "", ErrSessionRequired
	}
	k, tok, err := g.APIKeys.Issue(ctx, string(p.User.ID), name, scopes, expiresAt)
	if err != nil {
		return nil, "", err
	}
	g.record(ctx, audit.Event{ActorID: string(p.User.ID), Action: "apikey.issue", Target: k.ID, Success: true,
		IP: meta.IP, UserAgent: meta.UserAgent, Metadata: map[string]any{"name": k.Name, "scopes": k.Scopes}})
	return k, tok, nil
}

// EnsureAdmin gives the existing host user userID an account (if missing)
// and the admin role. Intended for bootstrap at startup.
func (g *Guard) EnsureAdmin(ctx context.Context, userID, email, password string) (*User, error) {
	u, err := g.Identity.CreateAccount(ctx, identityapp.CreateAccountInput{UserID: userID, Email: email, Password: password})
	if errors.Is(err, identitydomain.ErrAccountExists) {
		u, err = g.Identity.User(ctx, identitydomain.UserID(userID))
	}
	if err != nil {
		return nil, err
	}
	if err := g.Access.AssignRole(ctx, string(u.ID), "admin", "", nil); err != nil {
		return nil, err
	}
	return u, nil
}
