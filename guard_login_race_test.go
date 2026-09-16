package guard

import (
	"context"
	"errors"
	"testing"
	"time"

	accessdomain "github.com/bakhod1r/guard/access/domain"
	apikeydomain "github.com/bakhod1r/guard/apikey/domain"
	identitydomain "github.com/bakhod1r/guard/identity/domain"
	sessiondomain "github.com/bakhod1r/guard/session/domain"
)

// changedAfterVerify serves ByID as if an admin changed the account while
// the password was being verified.
type changedAfterVerify struct {
	identitydomain.UserRepository
	mutate func(u *identitydomain.User)
	err    error
}

func (c *changedAfterVerify) ByID(ctx context.Context, id identitydomain.UserID) (*identitydomain.User, error) {
	if c.err != nil {
		return nil, c.err
	}
	u, err := c.UserRepository.ByID(ctx, id)
	if err == nil && c.mutate != nil {
		c.mutate(u)
	}
	return u, err
}

func TestLoginRevokesSessionWhenAccountChangedDuringVerify(t *testing.T) {
	ctx := context.Background()
	cases := map[string]*changedAfterVerify{
		"password reset": {mutate: func(u *identitydomain.User) { u.PasswordHash = "reset" }},
		"banned":         {mutate: func(u *identitydomain.User) { u.Status = identitydomain.StatusBanned }},
		"read failure":   {err: errBoom},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, Config{})
			f.account(t, "1")
			c.UserRepository = f.users.UserRepository
			f.users.UserRepository = c
			_, err := f.g.Login(ctx, "1@example.com", pw, RequestMeta{})
			want := identitydomain.ErrInvalidCredentials
			if c.err != nil {
				want = c.err
			}
			if !errors.Is(err, want) {
				t.Fatalf("login: %v, want %v", err, want)
			}
			if f.sessions.deleted != 1 {
				t.Fatalf("session not revoked: deleted=%d", f.sessions.deleted)
			}
			if list, _ := f.g.Sessions.List(ctx, "1"); len(list) != 0 {
				t.Fatalf("%d sessions survived", len(list))
			}
			if ev := f.audit.Events[len(f.audit.Events)-1]; ev.Action != "auth.login" || ev.Success {
				t.Fatalf("audit: %+v", ev)
			}
		})
	}
}

func TestResetPasswordRevokesAPIKeys(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, Config{})
	f.account(t, "1")
	res := f.login(t, "1")
	_, tok, err := f.g.IssueAPIKey(ctx, &Principal{User: res.User, Session: res.Session}, "ci", []string{"*"}, nil, RequestMeta{})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.g.ResetPassword(ctx, "1", "1", "another horse battery"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.g.Authenticate(ctx, string(tok)); !errors.Is(err, apikeydomain.ErrKeyInvalid) {
		t.Fatalf("api key survived reset: %v", err)
	}
	if _, err := f.g.Authenticate(ctx, string(res.Token)); !errors.Is(err, sessiondomain.ErrSessionNotFound) {
		t.Fatalf("session survived reset: %v", err)
	}
}

func TestSetOwnAttributesNeedsSuperAdmin(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, Config{})
	f.account(t, "1")
	if err := f.g.SetAttributes(ctx, "1", "1", map[string]any{"department": "finance"}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("self attributes: %v", err)
	}
	if ev := f.audit.Events[len(f.audit.Events)-1]; ev.Action != "superadmin.denied" {
		t.Fatalf("audit: %+v", ev)
	}
	if err := f.store.CreateRole(ctx, &accessdomain.Role{Name: RoleSuperAdmin, Title: "sa", IsSystem: true, Wildcard: true}); err != nil {
		t.Fatal(err)
	}
	if err := f.g.Access.AssignRole(ctx, "1", RoleSuperAdmin, "", nil); err != nil {
		t.Fatal(err)
	}
	if err := f.g.SetAttributes(ctx, "1", "1", map[string]any{"department": "finance"}); err != nil {
		t.Fatal(err)
	}
	f.roles.grantsErr = errBoom
	if err := f.g.SetAttributes(ctx, "1", "1", nil); !errors.Is(err, errBoom) {
		t.Fatalf("role lookup: %v", err)
	}
}

// revokeAllFails makes APIKeys.RevokeAll fail.
type revokeAllFails struct{ apikeydomain.Repository }

func (revokeAllFails) RevokeAllByUser(context.Context, string, time.Time) error { return errBoom }

func TestResetPasswordKeyRevocationFailure(t *testing.T) {
	f := newFixture(t, Config{})
	f.account(t, "1")
	f.keys.Repository = revokeAllFails{f.keys.Repository}
	if err := f.g.ResetPassword(context.Background(), "1", "1", "another horse battery"); !errors.Is(err, errBoom) {
		t.Fatalf("reset: %v", err)
	}
}
