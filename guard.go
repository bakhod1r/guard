// Package guard wires identity, sessions, RBAC/ABAC and audit into one entry point.
//
//	g, _ := guard.New(guard.Config{DB: pool, Redis: rdb})
//	_ = guard.WriteMigrations("./migrations/guard")
//	_ = g.Migrate(ctx, "./migrations/guard")
//	ginguard.Mount(router.Group("/api"), g, ginguard.Options{})
package guard

import (
	"context"
	"errors"
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
)

var ErrSessionRequired = errors.New("guard: this operation requires a session, not an API key")

type Config struct {
	DB    *pgxpool.Pool
	Redis redis.UniversalClient
	// RedisPrefix namespaces session keys. Default "guard:".
	RedisPrefix string
	// Session lifetime. Zero value uses 30m idle / 7d absolute.
	Session SessionPolicy
	// Lockout for password guessing. Zero value uses 5 attempts / 15m.
	Lockout Lockout
	// DefaultRole is assigned on Register. Default "user"; "-" disables.
	DefaultRole string
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
	defaultRole string
}

func New(cfg Config) (*Guard, error) {
	if cfg.DB == nil || cfg.Redis == nil {
		return nil, errors.New("guard: Config.DB and Config.Redis are required")
	}
	store := accessinfra.NewPostgres(cfg.DB)
	g := Build(Repositories{
		Users:    identityinfra.NewPostgresUsers(cfg.DB),
		Hasher:   identityinfra.NewArgon2Hasher(),
		Sessions: sessioninfra.NewRedisSessions(cfg.Redis, cfg.RedisPrefix),
		Roles:    store,
		Policies: store,
		Audit:    audit.NewPostgres(cfg.DB),
		APIKeys:  apikeyinfra.NewPostgres(cfg.DB),
		Limiter:  ratelimit.NewRedis(cfg.Redis, cfg.RedisPrefix),
	}, cfg)
	g.db = cfg.DB
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
	if cfg.Session == (SessionPolicy{}) {
		cfg.Session = sessiondomain.DefaultPolicy()
	}
	if cfg.Lockout == (Lockout{}) {
		cfg.Lockout = identitydomain.DefaultLockout()
	}
	switch cfg.DefaultRole {
	case "":
		cfg.DefaultRole = "user"
	case "-":
		cfg.DefaultRole = ""
	}
	return &Guard{
		Identity:    identityapp.NewService(r.Users, r.Hasher, cfg.Lockout),
		Sessions:    sessionapp.NewService(r.Sessions, cfg.Session),
		Access:      accessapp.NewService(r.Roles, r.Policies),
		APIKeys:     apikeyapp.NewService(r.APIKeys),
		Audit:       r.Audit,
		Limiter:     r.Limiter,
		defaultRole: cfg.DefaultRole,
	}
}

// WriteMigrations copies Guard's SQL migrations into dir without overwriting existing files.
func WriteMigrations(dir string) ([]string, error) { return migrations.Write(dir) }

// Migrate applies migrations from dir ("" = embedded copies).
func (g *Guard) Migrate(ctx context.Context, dir string) error {
	if g.db == nil {
		return errors.New("guard: Migrate needs a PostgreSQL-backed Guard")
	}
	return migrations.Up(ctx, g.db, dir)
}

// RequestMeta describes the HTTP caller for sessions and audit.
type RequestMeta struct {
	IP        string
	UserAgent string
}

func (g *Guard) record(ctx context.Context, e audit.Event) {
	if g.Audit != nil {
		_ = g.Audit.Record(ctx, e)
	}
}

func (g *Guard) Register(ctx context.Context, email, password string, attrs map[string]any, meta RequestMeta) (*User, error) {
	u, err := g.Identity.Register(ctx, identityapp.RegisterInput{Email: email, Password: password, Attributes: attrs})
	if err != nil {
		return nil, err
	}
	if g.defaultRole != "" {
		if err := g.Access.AssignRole(ctx, string(u.ID), g.defaultRole, "", nil); err != nil && !errors.Is(err, accessdomain.ErrRoleNotFound) {
			return nil, err
		}
	}
	g.record(ctx, audit.Event{ActorID: string(u.ID), Action: "user.register", Target: string(u.ID), Success: true, IP: meta.IP, UserAgent: meta.UserAgent})
	return u, nil
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
			Metadata: map[string]any{"email": email, "error": err.Error()}})
		return nil, err
	}
	s, tok, err := g.Sessions.Start(ctx, sessionapp.StartInput{UserID: string(u.ID), IP: meta.IP, UserAgent: meta.UserAgent})
	if err != nil {
		return nil, err
	}
	g.record(ctx, audit.Event{ActorID: string(u.ID), Action: "auth.login", Target: string(u.ID), Success: true, IP: meta.IP, UserAgent: meta.UserAgent})
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
	if err := g.Identity.SetStatus(ctx, identitydomain.UserID(userID), status); err != nil {
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

// EnsureAdmin creates the account if missing and grants it the admin role.
// Intended for bootstrap at startup from environment configuration.
func (g *Guard) EnsureAdmin(ctx context.Context, email, password string) (*User, error) {
	u, err := g.Identity.Register(ctx, identityapp.RegisterInput{Email: email, Password: password})
	if errors.Is(err, identitydomain.ErrEmailTaken) {
		u, err = g.Identity.UserByEmail(ctx, email)
	}
	if err != nil {
		return nil, err
	}
	if err := g.Access.AssignRole(ctx, string(u.ID), "admin", "", nil); err != nil {
		return nil, err
	}
	return u, nil
}
