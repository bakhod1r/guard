// Package config loads a guard.yaml file and wires Guard from it.
//
//	f, err := config.Load("guard.yaml")
//	g, err := f.Open(ctx)
//	ginguard.Mount(r.Group("/api"), g, f.HTTPOptions())
//
// ${VAR} references are expanded from the environment before decoding. Keep
// secrets (database password, redis password) in the environment, not in the
// file: the file is typically committed, the environment is not.
package config

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"regexp"
	"time"

	"github.com/goccy/go-yaml"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/bakhod1r/guard"
	"github.com/bakhod1r/guard/ginguard"
	"github.com/bakhod1r/guard/ratelimit"
)

// Duration decodes Go duration strings ("30m", "168h").
type Duration time.Duration

func (d *Duration) UnmarshalYAML(b []byte) error {
	var s string
	if err := yaml.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("duration must be a string like \"30m\": %w", err)
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

type File struct {
	Database struct {
		URL string `yaml:"url"`
	} `yaml:"database"`
	Redis struct {
		Addr     string `yaml:"addr"`
		Password string `yaml:"password"`
		DB       int    `yaml:"db"`
		Prefix   string `yaml:"prefix"`
	} `yaml:"redis"`
	UserTable    string `yaml:"user_table"`
	UserIDColumn string `yaml:"user_id_column"`
	DefaultRole  string `yaml:"default_role"`
	Session      struct {
		Idle       Duration `yaml:"idle"`
		Absolute   Duration `yaml:"absolute"`
		MaxPerUser int      `yaml:"max_per_user"`
	} `yaml:"session"`
	Lockout struct {
		Attempts int      `yaml:"attempts"`
		Window   Duration `yaml:"window"`
	} `yaml:"lockout"`
	Audit struct {
		AsyncBuffer int `yaml:"async_buffer"`
		// EmailKey is a base64 (std) key of >= 32 bytes, e.g. "${GUARD_AUDIT_EMAIL_KEY}".
		// Set: login audit stores keyed "email_hmac"; empty: "email_sha256".
		EmailKey string `yaml:"email_key"`
		// RedisBuffer queues events in Redis and batch-writes them; overrides async_buffer.
		RedisBuffer struct {
			Enabled   bool     `yaml:"enabled"`
			BatchSize int      `yaml:"batch_size"`
			Interval  Duration `yaml:"interval"`
		} `yaml:"redis_buffer"`
	} `yaml:"audit"`
	// AccessCache enables the role/policy authorization cache (off by default).
	AccessCache struct {
		Enabled    bool     `yaml:"enabled"`
		TTL        Duration `yaml:"ttl"`
		MaxEntries int      `yaml:"max_entries"`
		// Shared enables the Redis-backed second level, shared by every instance
		// behind a load balancer.
		Shared    bool     `yaml:"shared"`
		SharedTTL Duration `yaml:"shared_ttl"`
	} `yaml:"access_cache"`
	Migrations struct {
		Dir       string `yaml:"dir"`
		AutoApply bool   `yaml:"auto_apply"`
	} `yaml:"migrations"`
	HTTP struct {
		CookieName     string   `yaml:"cookie_name"`
		InsecureCookie bool     `yaml:"insecure_cookie"`
		CookieDomain   string   `yaml:"cookie_domain"`
		AuthPath       string   `yaml:"auth_path"`
		AdminPath      string   `yaml:"admin_path"`
		TrustedOrigins []string `yaml:"trusted_origins"`
		MaxBodyBytes   int64    `yaml:"max_body_bytes"`
		HSTS           bool     `yaml:"hsts"`
		AuthRateLimit  struct {
			// Limit -1 disables auth rate limiting; 0 uses the default.
			Limit  int      `yaml:"limit"`
			Window Duration `yaml:"window"`
		} `yaml:"auth_rate_limit"`
	} `yaml:"http"`
	Autoseed struct {
		Enabled   bool     `yaml:"enabled"`
		Prefix    string   `yaml:"prefix"`
		SuperRole string   `yaml:"super_role"`
		Exclude   []string `yaml:"exclude"`
	} `yaml:"autoseed"`
}

// Load reads path, expands ${VAR} from the environment, decodes strictly and validates.
func Load(path string) (*File, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path comes from operator configuration
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return Parse(data)
}

// Parse expands ${VAR}, decodes strictly (unknown keys are errors) and validates.
func Parse(data []byte) (*File, error) {
	var f File
	dec := yaml.NewDecoder(bytes.NewReader([]byte(os.ExpandEnv(string(data)))), yaml.DisallowUnknownField())
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if err := f.Validate(); err != nil {
		return nil, err
	}
	return &f, nil
}

var identRe = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*(\.[a-zA-Z_][a-zA-Z0-9_]*)?$`)

// Validate checks required fields, SQL identifiers and rejects negative numbers.
// Empty user_table / user_id_column fall back to Guard's defaults.
func (f *File) Validate() error {
	switch {
	case f.Database.URL == "":
		return fmt.Errorf("config: database.url is required")
	case f.Redis.Addr == "":
		return fmt.Errorf("config: redis.addr is required")
	case f.UserTable != "" && !identRe.MatchString(f.UserTable):
		return fmt.Errorf("config: user_table %q is not a valid identifier", f.UserTable)
	case f.UserIDColumn != "" && !identRe.MatchString(f.UserIDColumn):
		return fmt.Errorf("config: user_id_column %q is not a valid identifier", f.UserIDColumn)
	case f.Migrations.AutoApply && f.Migrations.Dir == "":
		return fmt.Errorf("config: migrations.dir is required when migrations.auto_apply is true")
	case f.HTTP.AuthRateLimit.Limit < -1:
		return fmt.Errorf("config: http.auth_rate_limit.limit must be >= -1")
	}
	if _, err := f.auditEmailKey(); err != nil {
		return err
	}
	nonNeg := []struct {
		name string
		v    int64
	}{
		{"redis.db", int64(f.Redis.DB)},
		{"session.idle", int64(f.Session.Idle)},
		{"session.absolute", int64(f.Session.Absolute)},
		{"session.max_per_user", int64(f.Session.MaxPerUser)},
		{"lockout.attempts", int64(f.Lockout.Attempts)},
		{"lockout.window", int64(f.Lockout.Window)},
		{"audit.async_buffer", int64(f.Audit.AsyncBuffer)},
		{"audit.redis_buffer.batch_size", int64(f.Audit.RedisBuffer.BatchSize)},
		{"audit.redis_buffer.interval", int64(f.Audit.RedisBuffer.Interval)},
		{"access_cache.ttl", int64(f.AccessCache.TTL)},
		{"access_cache.max_entries", int64(f.AccessCache.MaxEntries)},
		{"access_cache.shared_ttl", int64(f.AccessCache.SharedTTL)},
		{"http.max_body_bytes", f.HTTP.MaxBodyBytes},
		{"http.auth_rate_limit.window", int64(f.HTTP.AuthRateLimit.Window)},
	}
	for _, n := range nonNeg {
		if n.v < 0 {
			return fmt.Errorf("config: %s must not be negative", n.name)
		}
	}
	return nil
}

// auditEmailKey decodes audit.email_key; empty means no key.
func (f *File) auditEmailKey() ([]byte, error) {
	if f.Audit.EmailKey == "" {
		return nil, nil
	}
	k, err := base64.StdEncoding.DecodeString(f.Audit.EmailKey)
	if err != nil {
		return nil, fmt.Errorf("config: audit.email_key must be base64: %w", err)
	}
	if len(k) < 32 {
		return nil, fmt.Errorf("config: audit.email_key must decode to at least 32 bytes, got %d", len(k))
	}
	return k, nil
}

func (f *File) guardConfig() guard.Config {
	c := guard.Config{
		RedisPrefix: f.Redis.Prefix,
		Session: guard.SessionPolicy{
			IdleTimeout:     time.Duration(f.Session.Idle),
			AbsoluteTimeout: time.Duration(f.Session.Absolute),
			MaxPerUser:      f.Session.MaxPerUser,
		},
		Lockout:      guard.Lockout{MaxAttempts: f.Lockout.Attempts, Duration: time.Duration(f.Lockout.Window)},
		DefaultRole:  f.DefaultRole,
		UserTable:    f.UserTable,
		UserIDColumn: f.UserIDColumn,
		AsyncAudit:   f.Audit.AsyncBuffer,
		AuditBuffer: guard.AuditBuffer{Enabled: f.Audit.RedisBuffer.Enabled, BatchSize: f.Audit.RedisBuffer.BatchSize,
			Interval: time.Duration(f.Audit.RedisBuffer.Interval)},
	}
	c.AuditEmailKey, _ = f.auditEmailKey() // validated in Parse
	if f.AccessCache.Enabled {
		c.AccessCache = &guard.AccessCacheOptions{TTL: time.Duration(f.AccessCache.TTL), MaxEntries: f.AccessCache.MaxEntries,
			L2: f.AccessCache.Shared, L2TTL: time.Duration(f.AccessCache.SharedTTL)}
	}
	return c
}

// Seams for failure-path tests.
var (
	newGuard        = guard.New
	writeMigrations = func(ctx context.Context, g *guard.Guard, dir string) error {
		_, err := g.WriteMigrations(ctx, dir)
		return err
	}
	migrate = func(ctx context.Context, g *guard.Guard, dir string) error { return g.Migrate(ctx, dir) }
)

// Open connects PostgreSQL and Redis, builds Guard and, when
// migrations.auto_apply is set, writes then applies migrations. Connections
// are closed on any failure. On success they live for the process; Guard
// does not expose them for closing.
func (f *File) Open(ctx context.Context) (*guard.Guard, error) {
	pool, err := pgxpool.New(ctx, f.Database.URL)
	if err != nil {
		return nil, fmt.Errorf("config: database: %w", err)
	}
	rdb := redis.NewClient(&redis.Options{Addr: f.Redis.Addr, Password: f.Redis.Password, DB: f.Redis.DB})
	fail := func(err error) (*guard.Guard, error) {
		_ = rdb.Close()
		pool.Close()
		return nil, err
	}
	cfg := f.guardConfig()
	cfg.DB, cfg.Redis = pool, rdb
	g, err := newGuard(cfg)
	if err != nil {
		return fail(fmt.Errorf("config: %w", err))
	}
	if f.Migrations.AutoApply {
		if err := writeMigrations(ctx, g, f.Migrations.Dir); err != nil {
			return fail(fmt.Errorf("config: write migrations: %w", err))
		}
		if err := migrate(ctx, g, f.Migrations.Dir); err != nil {
			return fail(fmt.Errorf("config: migrate: %w", err))
		}
	}
	return g, nil
}

func (f *File) HTTPOptions() ginguard.Options {
	return ginguard.Options{
		CookieName:     f.HTTP.CookieName,
		InsecureCookie: f.HTTP.InsecureCookie,
		CookieDomain:   f.HTTP.CookieDomain,
		AuthPath:       f.HTTP.AuthPath,
		AdminPath:      f.HTTP.AdminPath,
		AuthRateLimit:  ratelimit.Rule{Limit: f.HTTP.AuthRateLimit.Limit, Window: time.Duration(f.HTTP.AuthRateLimit.Window)},
		TrustedOrigins: f.HTTP.TrustedOrigins,
		MaxBodyBytes:   f.HTTP.MaxBodyBytes,
		HSTS:           f.HTTP.HSTS,
	}
}

// AutoseedOptions returns the autoseed settings and whether autoseed is enabled.
func (f *File) AutoseedOptions() (ginguard.AutoseedOptions, bool) {
	return ginguard.AutoseedOptions{
		Prefix:    f.Autoseed.Prefix,
		SuperRole: f.Autoseed.SuperRole,
		Exclude:   f.Autoseed.Exclude,
	}, f.Autoseed.Enabled
}
