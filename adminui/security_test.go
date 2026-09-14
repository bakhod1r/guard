package adminui_test

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"

	"github.com/bakhod1r/guard"
	"github.com/bakhod1r/guard/adminui"
	"github.com/bakhod1r/guard/guardtest"
)

// securityFaultHook fails redis commands by name while armed, so internal
// storage errors can be exercised after authentication succeeded.
type securityFaultHook struct {
	mu   sync.Mutex
	fail map[string]bool
}

func (h *securityFaultHook) arm(cmds ...string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.fail = map[string]bool{}
	for _, c := range cmds {
		h.fail[c] = true
	}
}

func (h *securityFaultHook) hit(name string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.fail[name]
}

func (h *securityFaultHook) DialHook(next redis.DialHook) redis.DialHook {
	return func(ctx context.Context, n, a string) (net.Conn, error) { return next(ctx, n, a) }
}

func (h *securityFaultHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		if h.hit(cmd.Name()) {
			err := errors.New("injected redis failure")
			cmd.SetErr(err)
			return err
		}
		return next(ctx, cmd)
	}
}

func (h *securityFaultHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, cmds []redis.Cmder) error {
		for _, c := range cmds {
			if h.hit(c.Name()) {
				err := errors.New("injected redis failure")
				c.SetErr(err)
				return err
			}
		}
		return next(ctx, cmds)
	}
}

func securityPanel(t *testing.T) (*panel, *securityFaultHook) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	hook := &securityFaultHook{}
	rdb.AddHook(hook)
	g := guardtest.New(rdb, guard.Config{})
	r := gin.New()
	adminui.Mount(r, g, adminui.Options{InsecureCookie: true})
	return &panel{t: t, g: g, r: r}, hook
}

// securityOtherSession starts an extra session for email outside the panel.
func securityOtherSession(t *testing.T, p *panel, email string) *guard.LoginResult {
	t.Helper()
	res, err := p.g.Login(context.Background(), email, "tr0ub4dor-guard-42", guard.RequestMeta{IP: "10.9.9.9", UserAgent: "<script>x</script>"})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func securityAlive(p *panel, tok guard.SessionToken) bool {
	_, err := p.g.Authenticate(context.Background(), string(tok))
	return err == nil
}

func securityErr(t *testing.T, h http.Header, want string) {
	t.Helper()
	loc, _ := url.QueryUnescape(location(h))
	if !strings.HasPrefix(loc, "/guard-admin/security?error=") || !strings.Contains(loc, want) {
		t.Fatalf("want error %q, got location %q", want, loc)
	}
}

func securityFlash(t *testing.T, code int, h http.Header) {
	t.Helper()
	if code != http.StatusSeeOther || !strings.HasPrefix(location(h), "/guard-admin/security?flash=") {
		t.Fatalf("want flash redirect, got %d %q", code, location(h))
	}
}

func TestSecurityPageListsSessionsAndKeys(t *testing.T) {
	p, _ := securityPanel(t)
	p.account("u1", "u1@example.com", false)
	p.login("u1@example.com")

	code, body := p.get("/guard-admin/security")
	if code != http.StatusOK || !strings.Contains(body, "No API keys") || strings.Count(body, `class="badge ok">current`) != 1 {
		t.Fatalf("page: %d\n%s", code, body)
	}

	securityOtherSession(t, p, "u1@example.com")
	ctx := context.Background()
	u1, _ := p.g.Authenticate(ctx, p.cookie.Value)
	exp := time.Now().Add(time.Hour)
	if _, _, err := p.g.IssueAPIKey(ctx, u1, "ci", []string{"user.read", "role.*"}, &exp, guard.RequestMeta{}); err != nil {
		t.Fatal(err)
	}
	k2, _, _ := p.g.IssueAPIKey(ctx, u1, "revoked-one", []string{"*"}, nil, guard.RequestMeta{})
	_ = p.g.APIKeys.Revoke(ctx, "u1", k2.ID)

	_, body = p.get("/guard-admin/security")
	for _, want := range []string{"&lt;script&gt;x&lt;/script&gt;", "10.9.9.9", "Sign out other sessions",
		">ci<", "user.read", "role.*", `class="badge ok">active`, `class="badge bad">revoked`, "/revoke"} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %q", want)
		}
	}
	if strings.Contains(body, "<script>x</script>") {
		t.Fatal("user agent not escaped")
	}
}

func TestSecurityKeyStatus(t *testing.T) {
	p, _ := securityPanel(t)
	p.account("u1", "u1@example.com", false)
	p.login("u1@example.com")
	ctx := context.Background()
	u1, _ := p.g.Authenticate(ctx, p.cookie.Value)
	exp := time.Now().Add(1500 * time.Millisecond)
	if _, _, err := p.g.IssueAPIKey(ctx, u1, "short", []string{"*"}, &exp, guard.RequestMeta{}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Until(exp) + 10*time.Millisecond)
	_, body := p.get("/guard-admin/security")
	if !strings.Contains(body, `class="badge bad">expired`) {
		t.Fatal("expired badge missing")
	}
}

func TestSecurityRevokeSessions(t *testing.T) {
	p, _ := securityPanel(t)
	p.account("u1", "u1@example.com", false)
	p.account("u2", "u2@example.com", false)
	other := securityOtherSession(t, p, "u1@example.com")
	foreign := securityOtherSession(t, p, "u2@example.com")
	p.login("u1@example.com")
	p.get("/guard-admin/security")
	cur, _ := p.g.Authenticate(context.Background(), p.cookie.Value)

	code, _, h := p.post("/guard-admin/security/sessions/"+string(cur.Session.ID)+"/revoke", nil)
	if code != http.StatusSeeOther {
		t.Fatal(code)
	}
	securityErr(t, h, "sign out")

	_, _, h = p.post("/guard-admin/security/sessions/"+string(foreign.Session.ID)+"/revoke", nil)
	securityErr(t, h, "session")
	if !securityAlive(p, foreign.Token) {
		t.Fatal("foreign session revoked")
	}

	code, _, h = p.post("/guard-admin/security/sessions/"+string(other.Session.ID)+"/revoke", nil)
	securityFlash(t, code, h)
	if securityAlive(p, other.Token) || !securityAlive(p, guard.SessionToken(p.cookie.Value)) {
		t.Fatal("revoke wrong session")
	}

	o2 := securityOtherSession(t, p, "u1@example.com")
	o3 := securityOtherSession(t, p, "u1@example.com")
	code, _, h = p.post("/guard-admin/security/sessions/revoke-others", nil)
	securityFlash(t, code, h)
	if securityAlive(p, o2.Token) || securityAlive(p, o3.Token) || !securityAlive(p, guard.SessionToken(p.cookie.Value)) || !securityAlive(p, foreign.Token) {
		t.Fatal("revoke-others wrong")
	}
}

func TestSecurityStorageFailures(t *testing.T) {
	p, hook := securityPanel(t)
	p.account("u1", "u1@example.com", false)
	securityOtherSession(t, p, "u1@example.com")
	p.login("u1@example.com")
	p.get("/guard-admin/security")

	hook.arm("smembers")
	if code, body := p.get("/guard-admin/security"); code != http.StatusInternalServerError || !strings.Contains(body, "internal error") {
		t.Fatalf("list failure: %d", code)
	}
	_, _, h := p.post("/guard-admin/security/sessions/x/revoke", nil)
	securityErr(t, h, "internal error")
	_, _, h = p.post("/guard-admin/security/sessions/revoke-others", nil)
	securityErr(t, h, "internal error")

	hook.arm("del")
	_, _, h = p.post("/guard-admin/security/sessions/revoke-others", nil)
	securityErr(t, h, "internal error")
	_, _, h = p.post("/guard-admin/security/password", url.Values{"old_password": {"tr0ub4dor-guard-42"}, "new_password": {"tr0ub4dor-guard-43"}, "confirm_password": {"tr0ub4dor-guard-43"}})
	securityErr(t, h, "internal error")
	hook.arm()
}

var securityTokenRe = regexp.MustCompile(`gk_[A-Za-z0-9_-]+`)

func TestSecurityIssueAndRevokeKey(t *testing.T) {
	p, _ := securityPanel(t)
	p.account("u1", "u1@example.com", false)
	p.account("u2", "u2@example.com", false)
	p.login("u1@example.com")
	p.get("/guard-admin/security")

	exp := time.Now().Add(48 * time.Hour).Format("2006-01-02T15:04")
	req := url.Values{"name": {"deploy"}, "scopes": {"user.read, role.*\n\n audit.read"}, "expires_at": {exp}}
	code, body, h := p.post("/guard-admin/security/api-keys", req)
	if code != http.StatusCreated {
		t.Fatalf("issue: %d %s", code, body)
	}
	if h.Get("Cache-Control") != "no-store" || h.Get("Location") != "" {
		t.Fatalf("headers: %v", h)
	}
	tok := securityTokenRe.FindString(body)
	if tok == "" || !strings.Contains(body, "will not be shown again") {
		t.Fatal("token not shown")
	}
	pr, err := p.g.Authenticate(context.Background(), tok)
	if err != nil || pr.APIKey == nil || len(pr.APIKey.Scopes) != 3 || pr.APIKey.ExpiresAt == nil {
		t.Fatalf("issued key: %v %+v", err, pr)
	}
	_, list := p.get("/guard-admin/security")
	if strings.Contains(list, tok) {
		t.Fatal("token shown again")
	}

	// no-expiry key
	code, body, _ = p.post("/guard-admin/security/api-keys", url.Values{"name": {"forever"}, "scopes": {"*"}})
	if code != http.StatusCreated || securityTokenRe.FindString(body) == "" {
		t.Fatal(code)
	}

	// another user cannot revoke u1's key
	p.login("u2@example.com")
	p.get("/guard-admin/security")
	_, _, h = p.post("/guard-admin/security/api-keys/"+pr.APIKey.ID+"/revoke", nil)
	securityErr(t, h, "not found")
	if _, err := p.g.Authenticate(context.Background(), tok); err != nil {
		t.Fatal("foreign revoke worked")
	}

	p.login("u1@example.com")
	p.get("/guard-admin/security")
	code, _, h = p.post("/guard-admin/security/api-keys/"+pr.APIKey.ID+"/revoke", nil)
	securityFlash(t, code, h)
	if _, err := p.g.Authenticate(context.Background(), tok); err == nil {
		t.Fatal("revoked key still works")
	}

	for _, tc := range []struct {
		form url.Values
		want string
	}{
		{url.Values{"name": {"x"}, "scopes": {"not a scope"}}, "scope"},
		{url.Values{"name": {"x"}, "scopes": {" , \n"}}, "scope"},
		{url.Values{"name": {""}, "scopes": {"*"}}, "name"},
		{url.Values{"name": {"x"}, "scopes": {"*"}, "expires_at": {"tomorrow"}}, "invalid input"},
		{url.Values{"name": {"x"}, "scopes": {"*"}, "expires_at": {"2001-01-01T10:00"}}, "expir"},
	} {
		code, _, h := p.post("/guard-admin/security/api-keys", tc.form)
		if code != http.StatusSeeOther {
			t.Fatalf("%v: %d", tc.form, code)
		}
		securityErr(t, h, tc.want)
	}
}

func TestSecurityChangePassword(t *testing.T) {
	p, _ := securityPanel(t)
	p.account("u1", "u1@example.com", false)
	other := securityOtherSession(t, p, "u1@example.com")
	p.login("u1@example.com")
	p.get("/guard-admin/security")
	pw := func(old, nw, confirm string) http.Header {
		_, _, h := p.post("/guard-admin/security/password", url.Values{"old_password": {old}, "new_password": {nw}, "confirm_password": {confirm}})
		return h
	}

	securityErr(t, pw("tr0ub4dor-guard-42", "tr0ub4dor-guard-43", "password789"), "invalid input")
	securityErr(t, pw("wrong-password", "tr0ub4dor-guard-43", "tr0ub4dor-guard-43"), "invalid")
	securityErr(t, pw("tr0ub4dor-guard-42", "short", "short"), "8-128")
	if !securityAlive(p, other.Token) {
		t.Fatal("failed change revoked sessions")
	}

	h := pw("tr0ub4dor-guard-42", "tr0ub4dor-guard-43", "tr0ub4dor-guard-43")
	securityFlash(t, http.StatusSeeOther, h)
	if securityAlive(p, other.Token) || !securityAlive(p, guard.SessionToken(p.cookie.Value)) {
		t.Fatal("sessions after password change")
	}
	if _, err := p.g.Login(context.Background(), "u1@example.com", "tr0ub4dor-guard-43", guard.RequestMeta{}); err != nil {
		t.Fatal("new password rejected")
	}
}

func TestSecurityCSRFAndAudit(t *testing.T) {
	p, _ := securityPanel(t)
	p.account("u1", "u1@example.com", false)
	other := securityOtherSession(t, p, "u1@example.com")
	p.login("u1@example.com")
	p.get("/guard-admin/security")
	for _, path := range []string{"/security/sessions/" + string(other.Session.ID) + "/revoke", "/security/sessions/revoke-others",
		"/security/api-keys", "/security/api-keys/x/revoke", "/security/password"} {
		if code, _, _ := p.post("/guard-admin"+path, url.Values{"_csrf": {""}, "name": {"x"}, "scopes": {"*"}}); code != http.StatusForbidden {
			t.Fatalf("%s without csrf: %d", path, code)
		}
	}
	if !securityAlive(p, other.Token) {
		t.Fatal("csrf-less request had effect")
	}

	p.post("/guard-admin/security/sessions/"+string(other.Session.ID)+"/revoke", nil)
	p.post("/guard-admin/security/sessions/revoke-others", nil)
	p.post("/guard-admin/security/password", url.Values{"old_password": {"tr0ub4dor-guard-42"}, "new_password": {"tr0ub4dor-guard-43"}, "confirm_password": {"tr0ub4dor-guard-43"}})
	ctx := context.Background()
	u1, _ := p.g.Authenticate(ctx, p.cookie.Value)
	k, _, _ := p.g.IssueAPIKey(ctx, u1, "k", []string{"*"}, nil, guard.RequestMeta{})
	p.post("/guard-admin/security/api-keys/"+k.ID+"/revoke", nil)

	events, err := p.g.Audit.List(ctx, "u1", 1000)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, e := range events {
		got[e.Action] = true
	}
	for _, a := range []string{"session.revoke", "session.revoke_others", "account.password_change", "apikey.revoke", "apikey.issue"} {
		if !got[a] {
			t.Fatalf("audit %s missing: %v", a, got)
		}
	}
}
