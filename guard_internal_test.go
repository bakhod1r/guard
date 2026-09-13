package guard

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
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
	if files, err := g.WriteMigrations(ctx, dir); err != nil || len(files) != 3 {
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
