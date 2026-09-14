package guard

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	accessdomain "github.com/bakhod1r/guard/access/domain"
	accessinfra "github.com/bakhod1r/guard/access/infrastructure"
	apikeydomain "github.com/bakhod1r/guard/apikey/domain"
	apikeyinfra "github.com/bakhod1r/guard/apikey/infrastructure"
	"github.com/bakhod1r/guard/audit"
	identitydomain "github.com/bakhod1r/guard/identity/domain"
	identityinfra "github.com/bakhod1r/guard/identity/infrastructure"
	"github.com/bakhod1r/guard/kernel/migrations"
	sessiondomain "github.com/bakhod1r/guard/session/domain"
	sessioninfra "github.com/bakhod1r/guard/session/infrastructure"
)

var errBoom = errors.New("storage boom")

// Failing fakes: wrap a working repository and fail selected methods.

type users struct {
	identitydomain.UserRepository
	byIDErr, updateErr error
}

func (u *users) ByID(ctx context.Context, id identitydomain.UserID) (*identitydomain.User, error) {
	if u.byIDErr != nil {
		return nil, u.byIDErr
	}
	return u.UserRepository.ByID(ctx, id)
}

func (u *users) Update(ctx context.Context, x *identitydomain.User) error {
	if u.updateErr != nil {
		return u.updateErr
	}
	return u.UserRepository.Update(ctx, x)
}

type roles struct {
	accessdomain.RoleRepository
	assignErr, grantsErr error
}

func (r *roles) AssignRole(ctx context.Context, userID, role, by string, exp *time.Time) error {
	if r.assignErr != nil {
		return r.assignErr
	}
	return r.RoleRepository.AssignRole(ctx, userID, role, by, exp)
}

func (r *roles) GrantsOf(ctx context.Context, userID string) ([]accessdomain.RoleGrant, error) {
	if r.grantsErr != nil {
		return nil, r.grantsErr
	}
	return r.RoleRepository.GrantsOf(ctx, userID)
}

type sessions struct {
	sessiondomain.Repository
	saveErr, getErr, deleteErr, deleteByUserErr error
	deleted, deletedByUser                      int
}

func (s *sessions) Save(ctx context.Context, x *sessiondomain.Session, ttl time.Duration) error {
	if s.saveErr != nil {
		return s.saveErr
	}
	return s.Repository.Save(ctx, x, ttl)
}

func (s *sessions) Get(ctx context.Context, id sessiondomain.ID) (*sessiondomain.Session, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	return s.Repository.Get(ctx, id)
}

func (s *sessions) Delete(ctx context.Context, id sessiondomain.ID) error {
	s.deleted++
	if s.deleteErr != nil {
		return s.deleteErr
	}
	return s.Repository.Delete(ctx, id)
}

func (s *sessions) DeleteByUser(ctx context.Context, userID string) error {
	s.deletedByUser++
	if s.deleteByUserErr != nil {
		return s.deleteByUserErr
	}
	return s.Repository.DeleteByUser(ctx, userID)
}

type keys struct {
	apikeydomain.Repository
	createErr, byHashErr error
}

func (k *keys) Create(ctx context.Context, x *apikeydomain.Key) error {
	if k.createErr != nil {
		return k.createErr
	}
	return k.Repository.Create(ctx, x)
}

func (k *keys) ByHash(ctx context.Context, h string) (*apikeydomain.Key, error) {
	if k.byHashErr != nil {
		return nil, k.byHashErr
	}
	return k.Repository.ByHash(ctx, h)
}

type fixture struct {
	g        *Guard
	users    *users
	roles    *roles
	sessions *sessions
	keys     *keys
	audit    *audit.Memory
	store    *accessinfra.Memory
}

func newFixture(t *testing.T, cfg Config) *fixture {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	store := accessinfra.NewMemory()
	ctx := context.Background()
	for _, name := range []string{"admin", "user"} {
		if err := store.CreateRole(ctx, &accessdomain.Role{Name: name, Title: name, IsSystem: true, Wildcard: name == "admin"}); err != nil {
			t.Fatal(err)
		}
	}
	f := &fixture{
		users:    &users{UserRepository: identityinfra.NewMemoryUsers()},
		roles:    &roles{RoleRepository: store},
		sessions: &sessions{Repository: sessioninfra.NewRedisSessions(rdb, "guard-unit:")},
		keys:     &keys{Repository: apikeyinfra.NewMemory()},
		audit:    &audit.Memory{},
		store:    store,
	}
	f.g = Build(Repositories{
		Users:    f.users,
		Hasher:   &identityinfra.Argon2Hasher{Memory: 1024, Time: 1, Threads: 1, KeyLen: 32, SaltLen: 16},
		Sessions: f.sessions,
		Roles:    f.roles,
		Policies: store,
		Audit:    f.audit,
		APIKeys:  f.keys,
	}, cfg)
	return f
}

const pw = "correct horse battery"

func (f *fixture) account(t *testing.T, id string) *User {
	t.Helper()
	u, err := f.g.CreateAccount(context.Background(), id, id+"@example.com", pw, nil, RequestMeta{})
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func (f *fixture) login(t *testing.T, id string) *LoginResult {
	t.Helper()
	r, err := f.g.Login(context.Background(), id+"@example.com", pw, RequestMeta{IP: "1.2.3.4"})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestNewRequiresDBAndRedis(t *testing.T) {
	rdb := redis.NewClient(&redis.Options{Addr: "localhost:1"})
	defer rdb.Close()
	for name, cfg := range map[string]Config{"nil db": {Redis: rdb}, "nil redis": {DB: &pgxpool.Pool{}}, "both nil": {}} {
		t.Run(name, func(t *testing.T) {
			if g, err := New(cfg); err == nil || g != nil {
				t.Fatalf("New = %v, %v; want error", g, err)
			}
		})
	}
}

func TestBuildAppliesDefaults(t *testing.T) {
	g := Build(Repositories{}, Config{})
	if g.defaultRole != "user" || g.userTable != "users" || g.userColumn != "id" {
		t.Fatalf("defaults: role=%q table=%q col=%q", g.defaultRole, g.userTable, g.userColumn)
	}
	g = Build(Repositories{}, Config{DefaultRole: "-", UserTable: "auth.people", UserIDColumn: "uid",
		Session: SessionPolicy{IdleTimeout: time.Minute, AbsoluteTimeout: time.Hour}, Lockout: Lockout{MaxAttempts: 1, Duration: time.Second}})
	if g.defaultRole != "" || g.userTable != "auth.people" || g.userColumn != "uid" {
		t.Fatalf("overrides: role=%q table=%q col=%q", g.defaultRole, g.userTable, g.userColumn)
	}
	if g = Build(Repositories{}, Config{DefaultRole: "editor"}); g.defaultRole != "editor" {
		t.Fatalf("custom role = %q", g.defaultRole)
	}
}

func TestDatabaseOperationsNeedPostgres(t *testing.T) {
	g := Build(Repositories{}, Config{})
	ctx := context.Background()
	if _, err := g.UserRef(ctx); err == nil {
		t.Fatal("UserRef: want error")
	}
	if _, err := g.WriteMigrations(ctx, t.TempDir()); err == nil {
		t.Fatal("WriteMigrations: want error")
	}
	if err := g.Migrate(ctx, ""); err == nil {
		t.Fatal("Migrate: want error")
	}
}

func TestRecordWithoutAuditLogIsNoop(t *testing.T) {
	f := newFixture(t, Config{})
	f.g.Audit = nil
	f.account(t, "1") // would panic if record dereferenced a nil log
}

func TestCreateAccount(t *testing.T) {
	ctx := context.Background()
	t.Run("assigns default role and audits", func(t *testing.T) {
		f := newFixture(t, Config{})
		u := f.account(t, "1")
		grants, _ := f.store.GrantsOf(ctx, string(u.ID))
		if len(grants) != 1 || grants[0].Role.Name != "user" {
			t.Fatalf("grants = %+v", grants)
		}
		if len(f.audit.Events) != 1 || f.audit.Events[0].Action != "account.create" {
			t.Fatalf("audit = %+v", f.audit.Events)
		}
	})
	t.Run("missing default role is ignored", func(t *testing.T) {
		f := newFixture(t, Config{DefaultRole: "ghost"})
		f.account(t, "1")
	})
	t.Run("disabled default role assigns nothing", func(t *testing.T) {
		f := newFixture(t, Config{DefaultRole: "-"})
		f.roles.assignErr = errBoom
		f.account(t, "1")
	})
	t.Run("assign error propagates", func(t *testing.T) {
		f := newFixture(t, Config{})
		f.roles.assignErr = errBoom
		if _, err := f.g.CreateAccount(ctx, "1", "a@example.com", pw, nil, RequestMeta{}); !errors.Is(err, errBoom) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("identity error propagates", func(t *testing.T) {
		f := newFixture(t, Config{})
		if _, err := f.g.CreateAccount(ctx, "1", "a@example.com", "short", nil, RequestMeta{}); !errors.Is(err, identitydomain.ErrWeakPassword) {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestResetPassword(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, Config{})
	f.account(t, "1")
	if err := f.g.ResetPassword(ctx, "admin", "1", "short"); !errors.Is(err, identitydomain.ErrWeakPassword) {
		t.Fatalf("weak: %v", err)
	}
	if err := f.g.ResetPassword(ctx, "admin", "nope", pw); !errors.Is(err, identitydomain.ErrUserNotFound) {
		t.Fatalf("missing: %v", err)
	}
	f.sessions.deleteByUserErr = errBoom
	if err := f.g.ResetPassword(ctx, "admin", "1", pw+"2"); !errors.Is(err, errBoom) {
		t.Fatalf("revoke: %v", err)
	}
	f.sessions.deleteByUserErr = nil
	if err := f.g.ResetPassword(ctx, "admin", "1", pw); err != nil {
		t.Fatal(err)
	}
	if last := f.audit.Events[len(f.audit.Events)-1]; last.Action != "account.password_reset" || last.ActorID != "admin" {
		t.Fatalf("audit = %+v", last)
	}
}

func TestLogin(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, Config{})
	f.account(t, "1")
	t.Run("failure is audited", func(t *testing.T) {
		if _, err := f.g.Login(ctx, "1@example.com", "wrong password", RequestMeta{IP: "9.9.9.9"}); !errors.Is(err, identitydomain.ErrInvalidCredentials) {
			t.Fatalf("err = %v", err)
		}
		last := f.audit.Events[len(f.audit.Events)-1]
		if last.Success || last.Action != "auth.login" || last.IP != "9.9.9.9" || last.Metadata["email"] != "1@example.com" {
			t.Fatalf("audit = %+v", last)
		}
	})
	t.Run("session store error", func(t *testing.T) {
		f.sessions.saveErr = errBoom
		defer func() { f.sessions.saveErr = nil }()
		if _, err := f.g.Login(ctx, "1@example.com", pw, RequestMeta{}); !errors.Is(err, errBoom) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("success", func(t *testing.T) {
		r := f.login(t, "1")
		if r.User.ID != "1" || r.Session == nil || r.Token == "" {
			t.Fatalf("result = %+v", r)
		}
	})
}

func TestLogout(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, Config{})
	u := f.account(t, "1")
	if err := f.g.Logout(ctx, &Principal{User: u, APIKey: &APIKey{}}, RequestMeta{}); !errors.Is(err, ErrSessionRequired) {
		t.Fatalf("api key logout: %v", err)
	}
	r := f.login(t, "1")
	p := &Principal{User: u, Session: r.Session}
	f.sessions.deleteErr = errBoom
	if err := f.g.Logout(ctx, p, RequestMeta{}); !errors.Is(err, errBoom) {
		t.Fatalf("revoke error: %v", err)
	}
	f.sessions.deleteErr = nil
	if err := f.g.Logout(ctx, p, RequestMeta{}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.g.Authenticate(ctx, string(r.Token)); !errors.Is(err, sessiondomain.ErrSessionNotFound) {
		t.Fatalf("token after logout: %v", err)
	}
}

func TestAuthenticate(t *testing.T) {
	ctx := context.Background()

	t.Run("session token", func(t *testing.T) {
		f := newFixture(t, Config{})
		f.account(t, "1")
		p, err := f.g.Authenticate(ctx, string(f.login(t, "1").Token))
		if err != nil || p.Session == nil || p.APIKey != nil || p.User.ID != "1" || len(p.Roles) != 1 {
			t.Fatalf("p = %+v, err = %v", p, err)
		}
	})
	t.Run("api key", func(t *testing.T) {
		f := newFixture(t, Config{})
		u := f.account(t, "1")
		_, tok, err := f.g.IssueAPIKey(ctx, &Principal{User: u, Session: &Session{}}, "ci", []string{"user.read"}, nil, RequestMeta{})
		if err != nil {
			t.Fatal(err)
		}
		p, err := f.g.Authenticate(ctx, string(tok))
		if err != nil || p.APIKey == nil || p.Session != nil || p.User.ID != "1" {
			t.Fatalf("p = %+v, err = %v", p, err)
		}
	})
	t.Run("invalid api key", func(t *testing.T) {
		f := newFixture(t, Config{})
		if _, err := f.g.Authenticate(ctx, "gk_"+hex.EncodeToString(make([]byte, 32))); err == nil {
			t.Fatal("want error")
		}
	})
	t.Run("api key repository error", func(t *testing.T) {
		f := newFixture(t, Config{})
		u := f.account(t, "1")
		_, tok, _ := f.g.IssueAPIKey(ctx, &Principal{User: u, Session: &Session{}}, "ci", []string{"*"}, nil, RequestMeta{})
		f.keys.byHashErr = errBoom
		if _, err := f.g.Authenticate(ctx, string(tok)); !errors.Is(err, errBoom) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("session repository error", func(t *testing.T) {
		f := newFixture(t, Config{})
		f.sessions.getErr = errBoom
		if _, err := f.g.Authenticate(ctx, "whatever"); !errors.Is(err, errBoom) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("missing user revokes session", func(t *testing.T) {
		f := newFixture(t, Config{})
		f.account(t, "1")
		tok := f.login(t, "1").Token
		f.users.byIDErr = identitydomain.ErrUserNotFound
		if _, err := f.g.Authenticate(ctx, string(tok)); !errors.Is(err, sessiondomain.ErrSessionNotFound) {
			t.Fatalf("err = %v", err)
		}
		if f.sessions.deleted != 1 {
			t.Fatalf("deleted = %d", f.sessions.deleted)
		}
	})
	t.Run("missing api key owner", func(t *testing.T) {
		f := newFixture(t, Config{})
		u := f.account(t, "1")
		_, tok, _ := f.g.IssueAPIKey(ctx, &Principal{User: u, Session: &Session{}}, "ci", []string{"*"}, nil, RequestMeta{})
		f.users.byIDErr = identitydomain.ErrUserNotFound
		if _, err := f.g.Authenticate(ctx, string(tok)); !errors.Is(err, sessiondomain.ErrSessionNotFound) || f.sessions.deleted != 0 {
			t.Fatalf("err = %v, deleted = %d", err, f.sessions.deleted)
		}
	})
	t.Run("user repository error", func(t *testing.T) {
		f := newFixture(t, Config{})
		f.account(t, "1")
		tok := f.login(t, "1").Token
		f.users.byIDErr = errBoom
		if _, err := f.g.Authenticate(ctx, string(tok)); !errors.Is(err, errBoom) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("blocked user revokes all sessions", func(t *testing.T) {
		f := newFixture(t, Config{})
		f.account(t, "1")
		tok := f.login(t, "1").Token
		u, _ := f.users.ByID(ctx, "1")
		u.Status = identitydomain.StatusBanned
		_ = f.users.Update(ctx, u)
		if _, err := f.g.Authenticate(ctx, string(tok)); !errors.Is(err, identitydomain.ErrUserBlocked) {
			t.Fatalf("err = %v", err)
		}
		if f.sessions.deletedByUser != 1 {
			t.Fatalf("deletedByUser = %d", f.sessions.deletedByUser)
		}
	})
	t.Run("blocked api key owner leaves sessions", func(t *testing.T) {
		f := newFixture(t, Config{})
		u := f.account(t, "1")
		_, tok, _ := f.g.IssueAPIKey(ctx, &Principal{User: u, Session: &Session{}}, "ci", []string{"*"}, nil, RequestMeta{})
		u.Status = identitydomain.StatusSuspended
		_ = f.users.Update(ctx, u)
		if _, err := f.g.Authenticate(ctx, string(tok)); !errors.Is(err, identitydomain.ErrUserBlocked) || f.sessions.deletedByUser != 0 {
			t.Fatalf("err = %v, deletedByUser = %d", err, f.sessions.deletedByUser)
		}
	})
	t.Run("role repository error", func(t *testing.T) {
		f := newFixture(t, Config{})
		f.account(t, "1")
		tok := f.login(t, "1").Token
		f.roles.grantsErr = errBoom
		if _, err := f.g.Authenticate(ctx, string(tok)); !errors.Is(err, errBoom) {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestAuthorize(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, Config{})
	u := f.account(t, "1")
	u.Attributes = map[string]any{"dept": "eng"}

	t.Run("api key scope denies", func(t *testing.T) {
		p := &Principal{User: u, APIKey: &APIKey{Scopes: []string{"user.read"}}}
		d, err := f.g.Authorize(ctx, p, "write", Resource{Type: "user"}, nil)
		if err != nil || d.Allowed || d.Reason != "api key scope does not cover user.write" {
			t.Fatalf("d = %+v, err = %v", d, err)
		}
	})
	t.Run("nil roles are not reloaded", func(t *testing.T) {
		f.roles.grantsErr = errBoom // would surface if Access reloaded roles
		defer func() { f.roles.grantsErr = nil }()
		d, err := f.g.Authorize(ctx, &Principal{User: u}, "write", Resource{Type: "user"}, nil)
		if err != nil || d.Allowed {
			t.Fatalf("d = %+v, err = %v", d, err)
		}
	})
	t.Run("wildcard role allows within key scope", func(t *testing.T) {
		p := &Principal{User: u, APIKey: &APIKey{Scopes: []string{"*"}}, Roles: []Role{{Name: "admin", Wildcard: true}}}
		d, err := f.g.Authorize(ctx, p, "write", Resource{Type: "user"}, map[string]any{"ip": "1.1.1.1"})
		if err != nil || !d.Allowed {
			t.Fatalf("d = %+v, err = %v", d, err)
		}
	})
}

func TestSetUserStatus(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		status     Status
		revokesAll bool
	}{
		{identitydomain.StatusBanned, true},
		{identitydomain.StatusSuspended, true},
		{identitydomain.StatusActive, false},
	}
	for _, c := range cases {
		t.Run(string(c.status), func(t *testing.T) {
			f := newFixture(t, Config{})
			f.account(t, "1")
			if err := f.g.SetUserStatus(ctx, "admin", "1", c.status); err != nil {
				t.Fatal(err)
			}
			if (f.sessions.deletedByUser == 1) != c.revokesAll {
				t.Fatalf("deletedByUser = %d", f.sessions.deletedByUser)
			}
			if last := f.audit.Events[len(f.audit.Events)-1]; last.Action != "user.status" || last.Metadata["status"] != string(c.status) {
				t.Fatalf("audit = %+v", last)
			}
		})
	}
	t.Run("unknown user", func(t *testing.T) {
		f := newFixture(t, Config{})
		if err := f.g.SetUserStatus(ctx, "admin", "nope", identitydomain.StatusBanned); !errors.Is(err, identitydomain.ErrUserNotFound) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("revoke error", func(t *testing.T) {
		f := newFixture(t, Config{})
		f.account(t, "1")
		f.sessions.deleteByUserErr = errBoom
		if err := f.g.SetUserStatus(ctx, "admin", "1", identitydomain.StatusBanned); !errors.Is(err, errBoom) {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestIssueAPIKey(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, Config{})
	u := f.account(t, "1")
	if _, _, err := f.g.IssueAPIKey(ctx, &Principal{User: u, APIKey: &APIKey{}}, "ci", []string{"*"}, nil, RequestMeta{}); !errors.Is(err, ErrSessionRequired) {
		t.Fatalf("api key principal: %v", err)
	}
	sp := &Principal{User: u, Session: &Session{}}
	if _, _, err := f.g.IssueAPIKey(ctx, sp, "ci", nil, nil, RequestMeta{}); !errors.Is(err, apikeydomain.ErrNoScopes) {
		t.Fatalf("no scopes: %v", err)
	}
	f.keys.createErr = errBoom
	if _, _, err := f.g.IssueAPIKey(ctx, sp, "ci", []string{"*"}, nil, RequestMeta{}); !errors.Is(err, errBoom) {
		t.Fatalf("create: %v", err)
	}
	f.keys.createErr = nil
	k, tok, err := f.g.IssueAPIKey(ctx, sp, "ci", []string{"*"}, nil, RequestMeta{IP: "1.1.1.1"})
	if err != nil || k == nil || tok == "" {
		t.Fatalf("k = %+v, err = %v", k, err)
	}
	if last := f.audit.Events[len(f.audit.Events)-1]; last.Action != "apikey.issue" || last.Target != k.ID {
		t.Fatalf("audit = %+v", last)
	}
}

func TestEnsureAdmin(t *testing.T) {
	ctx := context.Background()
	isAdmin := func(t *testing.T, f *fixture, id string) {
		t.Helper()
		grants, _ := f.store.GrantsOf(ctx, id)
		for _, g := range grants {
			if g.Role.Name == "admin" {
				return
			}
		}
		t.Fatalf("user %s lacks admin: %+v", id, grants)
	}
	t.Run("creates account", func(t *testing.T) {
		f := newFixture(t, Config{})
		if u, err := f.g.EnsureAdmin(ctx, "1", "root@example.com", pw); err != nil || u.ID != "1" {
			t.Fatalf("u = %+v, err = %v", u, err)
		}
		isAdmin(t, f, "1")
	})
	t.Run("existing account", func(t *testing.T) {
		f := newFixture(t, Config{})
		f.account(t, "1")
		if u, err := f.g.EnsureAdmin(ctx, "1", "other@example.com", pw); err != nil || u.Email != "1@example.com" {
			t.Fatalf("u = %+v, err = %v", u, err)
		}
		isAdmin(t, f, "1")
	})
	t.Run("existing account lookup error", func(t *testing.T) {
		f := newFixture(t, Config{})
		f.account(t, "1")
		f.users.byIDErr = errBoom
		if _, err := f.g.EnsureAdmin(ctx, "1", "1@example.com", pw); !errors.Is(err, errBoom) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("invalid input", func(t *testing.T) {
		f := newFixture(t, Config{})
		if _, err := f.g.EnsureAdmin(ctx, "1", "not-an-email", pw); !errors.Is(err, identitydomain.ErrInvalidEmail) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("assign error", func(t *testing.T) {
		f := newFixture(t, Config{})
		f.roles.assignErr = errBoom
		if _, err := f.g.EnsureAdmin(ctx, "1", "root@example.com", pw); !errors.Is(err, errBoom) {
			t.Fatalf("err = %v", err)
		}
	})
}

// freshDatabase creates a dedicated database with a host users table.
func freshDatabase(t *testing.T) (*pgxpool.Pool, redis.UniversalClient, string) {
	t.Helper()
	dsn, addr := os.Getenv("GUARD_TEST_DATABASE_URL"), os.Getenv("GUARD_TEST_REDIS_ADDR")
	if dsn == "" || addr == "" {
		t.Skip("GUARD_TEST_DATABASE_URL / GUARD_TEST_REDIS_ADDR not set")
	}
	ctx := context.Background()
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	suffix := hex.EncodeToString(b)
	name := "guard_cov_root_" + suffix
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.Database = name
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	rdb := redis.NewClient(&redis.Options{Addr: addr})
	t.Cleanup(func() {
		_ = rdb.Close()
		pool.Close()
		c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if _, err := admin.Exec(c, "DROP DATABASE IF EXISTS "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)"); err != nil {
			t.Errorf("drop %s: %v", name, err)
		}
		admin.Close()
	})
	if _, err := pool.Exec(ctx, `CREATE TABLE users (id BIGSERIAL PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	return pool, rdb, "guard-cov-root-" + suffix + ":"
}

func TestNewWithPostgresAndRedisIntegration(t *testing.T) {
	pool, rdb, prefix := freshDatabase(t)
	ctx := context.Background()
	g, err := New(Config{DB: pool, Redis: rdb, RedisPrefix: prefix})
	if err != nil {
		t.Fatal(err)
	}
	if g.Limiter == nil || g.Audit == nil {
		t.Fatal("New must wire limiter and audit")
	}
	ref, err := g.UserRef(ctx)
	if err != nil || ref != (migrations.UserRef{Table: "users", IDColumn: "id", IDType: "bigint"}) {
		t.Fatalf("ref = %+v, err = %v", ref, err)
	}
	dir := filepath.Join(t.TempDir(), "guard")
	// Exactly the embedded set (core 00001-00004 plus 00005/00006 once added).
	if files, err := g.WriteMigrations(ctx, dir); err != nil || len(files) != embeddedMigrationCount(t, ref) {
		t.Fatalf("files = %v, err = %v", files, err)
	}
	if err := g.Migrate(ctx, ""); err != nil {
		t.Fatal(err)
	}
	var id string
	if err := pool.QueryRow(ctx, `INSERT INTO users DEFAULT VALUES RETURNING id::text`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if _, err := g.CreateAccount(ctx, id, "pg@example.com", pw, nil, RequestMeta{}); err != nil {
		t.Fatal(err)
	}
	r, err := g.Login(ctx, "pg@example.com", pw, RequestMeta{})
	if err != nil {
		t.Fatal(err)
	}
	if p, err := g.Authenticate(ctx, string(r.Token)); err != nil || len(p.Roles) != 1 {
		t.Fatalf("p = %+v, err = %v", p, err)
	}

	bad := Build(Repositories{}, Config{UserTable: "missing"})
	bad.db = pool
	if _, err := bad.WriteMigrations(ctx, dir); err == nil {
		t.Fatal("WriteMigrations on missing table: want error")
	}
	if err := bad.Migrate(ctx, ""); err == nil {
		t.Fatal("Migrate on missing table: want error")
	}
}

type failingAudit struct{ audit.Memory }

func (*failingAudit) Record(context.Context, audit.Event) error { return errBoom }

type logBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func testLogger() (*slog.Logger, *logBuffer) {
	buf := &logBuffer{}
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})), buf
}

func TestLoggerDefaultsToSlogDefault(t *testing.T) {
	if g := Build(Repositories{}, Config{}); g.logger != slog.Default() {
		t.Fatal("nil Config.Logger must use slog.Default()")
	}
}

func TestAuditWriteFailureIsLoggedAtWarn(t *testing.T) {
	logger, buf := testLogger()
	f := newFixture(t, Config{Logger: logger})
	f.g.Audit = &failingAudit{}
	f.account(t, "1")
	if s := buf.String(); !strings.Contains(s, "level=WARN") || !strings.Contains(s, "account.create") || !strings.Contains(s, errBoom.Error()) {
		t.Fatalf("log = %q", s)
	}
}

func TestLoginFailureLogsHashedEmailOnly(t *testing.T) {
	logger, buf := testLogger()
	f := newFixture(t, Config{Logger: logger})
	f.account(t, "1")
	const secret = "tr0ub4dor-guard-42-wrong"
	if _, err := f.g.Login(context.Background(), " 1@Example.com", secret, RequestMeta{IP: "9.9.9.9"}); err == nil {
		t.Fatal("want error")
	}
	sum := sha256.Sum256([]byte("1@example.com"))
	s := buf.String()
	if !strings.Contains(s, "level=INFO") || !strings.Contains(s, "email_sha256="+hex.EncodeToString(sum[:])[:16]) || !strings.Contains(s, "ip=9.9.9.9") {
		t.Fatalf("log = %q", s)
	}
	if strings.Contains(strings.ToLower(s), "example.com") || strings.Contains(s, secret) {
		t.Fatalf("log leaks email or password: %q", s)
	}
}

func TestAsyncAuditFlushesOnClose(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, Config{AsyncAudit: 8})
	if _, ok := f.g.Audit.(*audit.Async); !ok {
		t.Fatalf("Audit = %T, want *audit.Async", f.g.Audit)
	}
	f.account(t, "1")
	if err := f.g.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if len(f.audit.Events) != 1 || f.audit.Events[0].Action != "account.create" {
		t.Fatalf("events = %+v", f.audit.Events)
	}
	if sf := newFixture(t, Config{}); sf.g.Close(ctx) != nil || sf.g.Audit != audit.Log(sf.audit) {
		t.Fatal("AsyncAudit 0 must stay synchronous and Close must be a no-op")
	}
	if g := Build(Repositories{}, Config{AsyncAudit: 4}); g.Audit != nil {
		t.Fatal("no audit log: nothing to wrap")
	}
}

func TestHealth(t *testing.T) {
	ctx := context.Background()
	if err := Build(Repositories{}, Config{}).Health(ctx); err == nil {
		t.Fatal("Health without backends: want error")
	}
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	g := Build(Repositories{}, Config{})
	g.redis = rdb
	if err := g.Health(ctx); err != nil {
		t.Fatal(err)
	}
	mr.Close()
	if err := g.Health(ctx); err == nil || !strings.Contains(err.Error(), "redis") {
		t.Fatalf("Health = %v, want redis error", err)
	}
}

func TestHealthAndCloseIntegration(t *testing.T) {
	pool, rdb, prefix := freshDatabase(t)
	ctx := context.Background()
	g, err := New(Config{DB: pool, Redis: rdb, RedisPrefix: prefix, AsyncAudit: 16})
	if err != nil {
		t.Fatal(err)
	}
	if err := g.Migrate(ctx, ""); err != nil {
		t.Fatal(err)
	}
	if err := g.Health(ctx); err != nil {
		t.Fatal(err)
	}
	var id string
	if err := pool.QueryRow(ctx, `INSERT INTO users DEFAULT VALUES RETURNING id::text`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if _, err := g.CreateAccount(ctx, id, "ops@example.com", "tr0ub4dor-guard-42", nil, RequestMeta{}); err != nil {
		t.Fatal(err)
	}
	if err := g.Close(ctx); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM guard_audit_event WHERE action = 'account.create'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("flushed audit rows = %d, err = %v", n, err)
	}
	// Close must not close the caller's pool or client.
	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("pool closed by Guard: %v", err)
	}
	if err := rdb.Ping(ctx).Err(); err != nil {
		t.Fatalf("redis closed by Guard: %v", err)
	}
	pool.Close()
	if err := g.Health(ctx); err == nil || !strings.Contains(err.Error(), "postgres") {
		t.Fatalf("Health = %v, want postgres error", err)
	}
}

func TestAuditBufferEnabledWrapsPostgresAndDisablesAsync(t *testing.T) {
	ctx := context.Background()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	pool, err := pgxpool.New(ctx, "postgres://u:p@127.0.0.1:1/none?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	g, err := New(Config{DB: pool, Redis: rdb, AsyncAudit: 8,
		AuditBuffer: AuditBuffer{Enabled: true, BatchSize: 10, Interval: time.Hour}})
	if err != nil {
		t.Fatal(err)
	}
	if g.asyncAudit != nil || g.auditBuffer == nil {
		t.Fatalf("asyncAudit = %v, auditBuffer = %v; want buffer only", g.asyncAudit, g.auditBuffer)
	}
	if _, ok := g.Audit.(*audit.RedisBuffer); !ok {
		t.Fatalf("Audit = %T, want *audit.RedisBuffer", g.Audit)
	}
	if err := g.Close(ctx); err != nil {
		t.Fatalf("Close with empty queue = %v", err)
	}
	if err := g.Close(ctx); err != nil {
		t.Fatalf("second Close = %v", err)
	}
}

func TestAuditBufferFlushesOnCloseIntegration(t *testing.T) {
	pool, rdb, prefix := freshDatabase(t)
	ctx := context.Background()
	g, err := New(Config{DB: pool, Redis: rdb, RedisPrefix: prefix,
		AuditBuffer: AuditBuffer{Enabled: true, Interval: time.Hour}})
	if err != nil {
		t.Fatal(err)
	}
	if err := g.Migrate(ctx, ""); err != nil {
		t.Fatal(err)
	}
	var id string
	if err := pool.QueryRow(ctx, `INSERT INTO users DEFAULT VALUES RETURNING id::text`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if _, err := g.CreateAccount(ctx, id, "buf@example.com", pw, nil, RequestMeta{}); err != nil {
		t.Fatal(err)
	}
	if n, err := rdb.LLen(ctx, prefix+"{audit}:queue").Result(); err != nil || n != 1 {
		t.Fatalf("queued = %d, err = %v; want 1 before Close", n, err)
	}
	if err := g.Close(ctx); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM guard_audit_event WHERE action = 'account.create'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("flushed audit rows = %d, err = %v", n, err)
	}
}

func TestSessionPolicyFillsEachZeroField(t *testing.T) {
	def := sessiondomain.DefaultPolicy()
	got := sessionPolicy(SessionPolicy{MaxPerUser: 3})
	if got.IdleTimeout != def.IdleTimeout || got.AbsoluteTimeout != def.AbsoluteTimeout || got.MaxPerUser != 3 {
		t.Fatalf("MaxPerUser only: %+v", got)
	}
	got = sessionPolicy(SessionPolicy{IdleTimeout: time.Minute})
	if got.IdleTimeout != time.Minute || got.AbsoluteTimeout != def.AbsoluteTimeout {
		t.Fatalf("idle only: %+v", got)
	}
	got = sessionPolicy(SessionPolicy{AbsoluteTimeout: time.Hour})
	if got.IdleTimeout != def.IdleTimeout || got.AbsoluteTimeout != time.Hour {
		t.Fatalf("absolute only: %+v", got)
	}
	if got := lockoutPolicy(Lockout{MaxAttempts: 9}); got.MaxAttempts != 9 || got.Duration != identitydomain.DefaultLockout().Duration {
		t.Fatalf("lockout attempts only: %+v", got)
	}
	if got := lockoutPolicy(Lockout{Duration: time.Second}); got.Duration != time.Second || got.MaxAttempts != identitydomain.DefaultLockout().MaxAttempts {
		t.Fatalf("lockout duration only: %+v", got)
	}
}

func TestSessionWithOnlyMaxPerUserDoesNotExpireImmediately(t *testing.T) {
	f := newFixture(t, Config{Session: SessionPolicy{MaxPerUser: 2}})
	f.account(t, "1")
	r := f.login(t, "1")
	if _, err := f.g.Authenticate(context.Background(), string(r.Token)); err != nil {
		t.Fatalf("fresh session rejected: %v", err)
	}
}

func TestRotateSession(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, Config{})
	f.account(t, "1")
	r := f.login(t, "1")
	s, tok, err := f.g.RotateSession(ctx, r.Token)
	if err != nil || tok == "" || tok == r.Token || s.UserID != "1" {
		t.Fatalf("rotate: %+v %q %v", s, tok, err)
	}
	if _, err := f.g.Authenticate(ctx, string(r.Token)); err == nil {
		t.Fatal("old token still valid")
	}
	if _, err := f.g.Authenticate(ctx, string(tok)); err != nil {
		t.Fatalf("new token: %v", err)
	}
	if last := f.audit.Events[len(f.audit.Events)-1]; last.Action != "session.rotate" || last.ActorID != "1" {
		t.Fatalf("audit: %+v", last)
	}
	if _, _, err := f.g.RotateSession(ctx, r.Token); !errors.Is(err, sessiondomain.ErrSessionNotFound) {
		t.Fatalf("rotate old: %v", err)
	}
}

func TestPasswordHasher(t *testing.T) {
	h, err := passwordHasher(nil)
	if err != nil {
		t.Fatal(err)
	}
	// Legacy bcrypt hashes must verify (MultiHasher).
	legacy := "$2a$04$" + "invalid"
	if _, err := h.Verify("x", legacy); err == nil {
		t.Fatal("want bcrypt path error for malformed bcrypt hash")
	}
	if !h.NeedsRehash(legacy) {
		t.Fatal("bcrypt must need rehash")
	}
	if _, err := passwordHasher(&PasswordHashParams{Memory: 1, Time: 1, Threads: 1, KeyLen: 32, SaltLen: 16}); !errors.Is(err, identityinfra.ErrWeakHashParams) {
		t.Fatalf("weak params: %v", err)
	}
	h, err = passwordHasher(&PasswordHashParams{Memory: 19456, Time: 2, Threads: 1, KeyLen: 32, SaltLen: 16})
	if err != nil {
		t.Fatal(err)
	}
	enc, _ := h.Hash("s3cret-value")
	if ok, err := h.Verify("s3cret-value", enc); !ok || err != nil {
		t.Fatalf("verify: %v %v", ok, err)
	}
	rdb := redis.NewClient(&redis.Options{Addr: "localhost:1"})
	defer rdb.Close()
	if _, err := New(Config{DB: &pgxpool.Pool{}, Redis: rdb, PasswordHashParams: &PasswordHashParams{Memory: 1}}); !errors.Is(err, identityinfra.ErrWeakHashParams) {
		t.Fatalf("New weak params: %v", err)
	}
}

func TestAccessCacheWiring(t *testing.T) {
	ctx := context.Background()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()

	g, err := New(Config{DB: &pgxpool.Pool{}, Redis: rdb, RedisPrefix: "p1:"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := g.AccessStats(); ok {
		t.Fatal("cache must be off by default")
	}
	if err := g.InvalidateAccess(ctx); err != nil {
		t.Fatalf("invalidate without cache: %v", err)
	}
	if mr.Exists("p1:access:version") {
		t.Fatal("no-cache invalidate touched redis")
	}

	logger, buf := testLogger()
	g, err = New(Config{DB: &pgxpool.Pool{}, Redis: rdb, RedisPrefix: "p2:", Logger: logger, AccessCache: &accessinfra.CacheOptions{}})
	if err != nil {
		t.Fatal(err)
	}
	if g.accessCache == nil {
		t.Fatal("access cache not wired")
	}
	if st, ok := g.AccessStats(); !ok || st != (accessinfra.CacheStats{}) {
		t.Fatalf("stats: %+v %v", st, ok)
	}
	if err := g.InvalidateAccess(ctx); err != nil {
		t.Fatal(err)
	}
	v1, _ := mr.Get("p2:access:version")
	if err := g.InvalidateAccess(ctx); err != nil {
		t.Fatal(err)
	}
	if v2, _ := mr.Get("p2:access:version"); v1 == "" || v1 == v2 {
		t.Fatalf("version not bumped: %q -> %q", v1, v2)
	}

	opts := accessCacheOptions(accessinfra.CacheOptions{}, "p3:", logger)
	if opts.Prefix != "p3:" {
		t.Fatalf("prefix: %q", opts.Prefix)
	}
	opts.OnError(errBoom)
	if !strings.Contains(buf.String(), "access cache") || !strings.Contains(buf.String(), "level=WARN") {
		t.Fatalf("OnError not logged: %s", buf.String())
	}
	called := false
	opts = accessCacheOptions(accessinfra.CacheOptions{Prefix: "own:", OnError: func(error) { called = true }}, "p3:", logger)
	opts.OnError(errBoom)
	if opts.Prefix != "own:" || !called {
		t.Fatal("explicit options overridden")
	}

	gd, err := New(Config{DB: &pgxpool.Pool{}, Redis: rdb, AccessCache: &AccessCacheOptions{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := gd.InvalidateAccess(ctx); err != nil || !mr.Exists("guard:access:version") {
		t.Fatalf("default prefix: %v", err)
	}

	mr.Close()
	if err := g.InvalidateAccess(ctx); err == nil {
		t.Fatal("want redis error")
	}
}

func embeddedMigrationCount(t *testing.T, ref migrations.UserRef) int {
	t.Helper()
	fsys, err := migrations.Render(ref)
	if err != nil {
		t.Fatal(err)
	}
	names, _ := fs.Glob(fsys, "*.sql")
	if len(names) < 4 {
		t.Fatalf("embedded migrations: %v", names)
	}
	return len(names)
}
