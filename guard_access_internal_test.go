package guard

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	sessionapp "github.com/bakhod1r/guard/session/application"
	sessiondomain "github.com/bakhod1r/guard/session/domain"
	"github.com/bakhod1r/guard/token"
)

var accessOpts = AccessTokenOptions{Keys: []AccessKey{{ID: "k1", Secret: []byte(strings.Repeat("s", 32))}}, TTL: time.Hour}

// listFail wraps the fixture's session repository and fails ListByUser once armed.
type listFail struct {
	sessiondomain.Repository
	err error
}

func (l *listFail) ListByUser(ctx context.Context, uid string) ([]*sessiondomain.Session, error) {
	if l.err != nil {
		return nil, l.err
	}
	return l.Repository.ListByUser(ctx, uid)
}

type accessFixture struct {
	*fixture
	list *listFail
	mr   *miniredis.Miniredis
	rdb  *redis.Client
}

func newAccessFixture(t *testing.T, withRevocations bool) *accessFixture {
	t.Helper()
	opts := accessOpts
	f := newFixture(t, Config{AccessToken: &opts})
	lf := &listFail{Repository: f.sessions}
	f.g.Sessions = sessionapp.NewService(lf, f.g.Sessions.Policy())
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	if withRevocations {
		f.g.SetAccessRevocations(token.NewRevocations(rdb, "acc:", f.g.AccessTTL()))
	}
	return &accessFixture{fixture: f, list: lf, mr: mr, rdb: rdb}
}

func TestNewValidatesAccessTokenAndWiresRevocations(t *testing.T) {
	rdb := redis.NewClient(&redis.Options{Addr: "localhost:1"})
	defer rdb.Close()
	if _, err := New(Config{DB: &pgxpool.Pool{}, Redis: rdb, AccessToken: &AccessTokenOptions{}}); err == nil ||
		!strings.Contains(err.Error(), "Config.AccessToken") {
		t.Fatalf("bad access options: %v", err)
	}
	opts := accessOpts
	g, err := New(Config{DB: &pgxpool.Pool{}, Redis: rdb, AccessToken: &opts})
	if err != nil {
		t.Fatal(err)
	}
	if g.revocations == nil || g.AccessTTL() != time.Hour || !g.AccessTokensEnabled() {
		t.Fatalf("revocations %v ttl %v", g.revocations, g.AccessTTL())
	}
	opts.DisableRevocation = true
	if g, _ := New(Config{DB: &pgxpool.Pool{}, Redis: rdb, AccessToken: &opts}); g.revocations != nil {
		t.Fatal("DisableRevocation must skip the revocation list")
	}
}

func TestBuildPanicsOnInvalidAccessOptions(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("Build must panic on invalid access options")
		}
	}()
	Build(Repositories{}, Config{AccessToken: &AccessTokenOptions{}})
}

func TestAccessDisabled(t *testing.T) {
	g := Build(Repositories{}, Config{})
	if g.AccessTTL() != 0 || g.AccessTokensEnabled() {
		t.Fatal("access must be disabled")
	}
	if _, _, ok := g.IssueAccess(&Session{}); ok {
		t.Fatal("IssueAccess must report disabled")
	}
}

func TestSetAccessRevocations(t *testing.T) {
	f := newAccessFixture(t, true)
	if f.g.revocations == nil {
		t.Fatal("not installed")
	}
	f.g.SetAccessRevocations(nil)
	if f.g.revocations != nil {
		t.Fatal("not removed")
	}
}

func TestAuthenticateAccessToken(t *testing.T) {
	ctx := context.Background()
	f := newAccessFixture(t, true)
	f.account(t, "1")
	r := f.login(t, "1")
	tok, _, ok := f.g.IssueAccess(r.Session)
	if !ok {
		t.Fatal("IssueAccess disabled")
	}
	p, err := f.g.Authenticate(ctx, string(tok))
	if err != nil || p.Access == nil || p.Session.Family() != r.Session.Family() || string(p.User.ID) != "1" {
		t.Fatalf("authenticate: %+v %v", p, err)
	}

	// bad signature
	bad := string(tok[:len(tok)-2]) + "xx"
	if _, err := f.g.Authenticate(ctx, bad); !errors.Is(err, token.ErrInvalid) {
		t.Fatalf("bad token: %v", err)
	}

	// revoked family
	if err := f.g.revocations.RevokeFamily(ctx, r.Session.Family()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.g.Authenticate(ctx, string(tok)); !errors.Is(err, token.ErrRevoked) {
		t.Fatalf("revoked: %v", err)
	}
}

func TestAuthenticateAccessTokenWithoutRevocations(t *testing.T) {
	f := newAccessFixture(t, false)
	f.account(t, "1")
	r := f.login(t, "1")
	tok, _, _ := f.g.IssueAccess(r.Session)
	if _, err := f.g.Authenticate(context.Background(), string(tok)); err != nil {
		t.Fatal(err)
	}
}

func TestLogoutWithAccessTokenRevokesFamily(t *testing.T) {
	ctx := context.Background()
	for _, withRev := range []bool{true, false} {
		f := newAccessFixture(t, withRev)
		f.account(t, "1")
		r := f.login(t, "1")
		tok, _, _ := f.g.IssueAccess(r.Session)
		p, err := f.g.Authenticate(ctx, string(tok))
		if err != nil {
			t.Fatal(err)
		}
		// a second session of another family must survive
		other := f.login(t, "1")
		if err := f.g.Logout(ctx, p, RequestMeta{}); err != nil {
			t.Fatal(err)
		}
		if _, err := f.g.Sessions.Resolve(ctx, r.Token); err == nil {
			t.Fatal("family session survived logout")
		}
		if _, err := f.g.Sessions.Resolve(ctx, other.Token); err != nil {
			t.Fatalf("other family revoked: %v", err)
		}
	}
}

func TestRevokeFamilyErrors(t *testing.T) {
	ctx := context.Background()
	f := newAccessFixture(t, true)
	u := f.account(t, "1")
	r := f.login(t, "1")
	if err := f.g.revokeFamily(ctx, nil, "x"); err != nil {
		t.Fatal(err)
	}
	if err := f.g.revokeFamily(ctx, u, ""); err != nil {
		t.Fatal(err)
	}
	f.list.err = errBoomAccess
	if err := f.g.revokeFamily(ctx, u, r.Session.Family()); !errors.Is(err, errBoomAccess) {
		t.Fatalf("list: %v", err)
	}
	f.list.err = nil
	f.sessions.deleteErr = errBoomAccess
	if err := f.g.revokeFamily(ctx, u, r.Session.Family()); !errors.Is(err, errBoomAccess) {
		t.Fatalf("revoke: %v", err)
	}

	// Logout surfaces the family revocation failure
	f.sessions.deleteErr = nil
	tok, _, _ := f.g.IssueAccess(r.Session)
	p, err := f.g.Authenticate(ctx, string(tok))
	if err != nil {
		t.Fatal(err)
	}
	f.list.err = errBoomAccess
	if err := f.g.Logout(ctx, p, RequestMeta{}); !errors.Is(err, errBoomAccess) {
		t.Fatalf("logout: %v", err)
	}
}

var errBoomAccess = errors.New("boom")

func TestMetaFromRequest(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("User-Agent", "ua")
	r.Header.Set("X-Forwarded-For", "9.9.9.9")
	r.Header.Set("Accept-Language", " uz-UZ;q=0.9, en")
	m := MetaFromRequest(r, "1.2.3.4")
	if m.IP != "1.2.3.4" || m.UserAgent != "ua" || m.Forwarded != "9.9.9.9" || m.Locale != "uz-UZ" || m.LocaleSource != "header" {
		t.Fatalf("meta: %+v", m)
	}
	r.Header.Set("Accept-Language", "*")
	if m := MetaFromRequest(r, ""); m.Locale != "" {
		t.Fatalf("wildcard: %+v", m)
	}
}
