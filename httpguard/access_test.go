package httpguard_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/bakhod1r/guard"
	"github.com/bakhod1r/guard/guardtest"
	"github.com/bakhod1r/guard/httpguard"
	identitydomain "github.com/bakhod1r/guard/identity/domain"
)

func setupAccess(t *testing.T) (client, *guard.Guard) {
	t.Helper()
	mr := miniredis.RunT(t)
	g := guardtest.New(redis.NewClient(&redis.Options{Addr: mr.Addr()}), guard.Config{AccessToken: &guard.AccessTokenOptions{
		Keys: []guard.AccessKey{{ID: "k1", Secret: []byte(strings.Repeat("s", 32))}}, TTL: 3 * time.Hour, Issuer: "test", Audience: "test",
	}})
	mux := http.NewServeMux()
	httpguard.Mount(mux, g, options())
	return client{t: t, router: mux}, g
}

// loginAccess logs in and returns the access token and the refresh cookie.
func loginAccess(t *testing.T, c client, email string) (string, *http.Cookie) {
	t.Helper()
	w := httptest.NewRecorder()
	c.router.ServeHTTP(w, c.request("POST", "/api/auth/login", "", map[string]any{"email": email, "password": password}))
	if w.Code != http.StatusOK {
		t.Fatalf("login: %d %s", w.Code, w.Body)
	}
	return accessAndCookie(t, w)
}

func accessAndCookie(t *testing.T, w *httptest.ResponseRecorder) (string, *http.Cookie) {
	t.Helper()
	body := w.Body.String()
	if strings.Contains(body, `"token"`) || strings.Contains(body, "refresh_token") {
		t.Fatalf("refresh token leaked into the body: %s", body)
	}
	var ck *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "guard_refresh" {
			ck = c
		}
		if c.Name == "guard_session" {
			t.Fatalf("session cookie set in access mode")
		}
	}
	if ck == nil || !ck.HttpOnly || !ck.Secure || ck.SameSite != http.SameSiteStrictMode || ck.Path != "/api/auth" || ck.MaxAge <= 0 {
		t.Fatalf("refresh cookie = %+v", ck)
	}
	i := strings.Index(body, `"access_token":"`)
	if i < 0 {
		t.Fatalf("no access token: %s", body)
	}
	rest := body[i+len(`"access_token":"`):]
	return rest[:strings.IndexByte(rest, '"')], ck
}

func refresh(c client, ck *http.Cookie, origin string) *httptest.ResponseRecorder {
	req := c.request("POST", "/api/auth/refresh", "", nil)
	if ck != nil {
		req.AddCookie(ck)
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	w := httptest.NewRecorder()
	c.router.ServeHTTP(w, req)
	return w
}

func TestAccessTokenLoginRefreshLogout(t *testing.T) {
	c, _ := setupAccess(t)
	register0(t, c, "acc@example.com")
	access, ck := loginAccess(t, c, "acc@example.com")
	if !strings.HasPrefix(access, "eyJ") {
		t.Fatalf("access = %q", access)
	}
	if code, body := c.do("GET", "/api/auth/me", access, nil); code != http.StatusOK {
		t.Fatalf("me with access: %d %v", code, body)
	}
	// the refresh cookie alone authenticates nothing
	req := c.request("GET", "/api/auth/me", "", nil)
	req.AddCookie(ck)
	if code, _ := c.send(req); code != http.StatusUnauthorized {
		t.Fatalf("me with refresh cookie only: %d", code)
	}

	if w := refresh(c, ck, "https://evil.example"); w.Code != http.StatusForbidden {
		t.Fatalf("cross-site refresh: %d", w.Code)
	}
	w := refresh(c, ck, "http://example.com")
	if w.Code != http.StatusOK {
		t.Fatalf("refresh: %d %s", w.Code, w.Body)
	}
	access2, ck2 := accessAndCookie(t, w)
	if ck2.Value == ck.Value {
		t.Fatal("refresh token not rotated")
	}
	if w := refresh(c, ck, "http://example.com"); w.Code != http.StatusUnauthorized {
		t.Fatalf("reused refresh token: %d", w.Code)
	}

	if code, _ := c.do("POST", "/api/auth/logout", access2, nil); code != http.StatusNoContent {
		t.Fatalf("logout: %d", code)
	}
	for _, tok := range []string{access, access2} {
		if code, _ := c.do("GET", "/api/auth/me", tok, nil); code != http.StatusUnauthorized {
			t.Fatalf("access after logout: %d", code)
		}
	}
	if w := refresh(c, ck2, "http://example.com"); w.Code != http.StatusUnauthorized {
		t.Fatalf("refresh after logout: %d", w.Code)
	}
}

func TestAccessTokenRevokedByLogoutAllAndBan(t *testing.T) {
	c, g := setupAccess(t)
	id := register0(t, c, "ban@example.com")
	a1, _ := loginAccess(t, c, "ban@example.com")
	a2, _ := loginAccess(t, c, "ban@example.com")
	if code, _ := c.do("POST", "/api/auth/logout-all", a1, nil); code != http.StatusNoContent {
		t.Fatalf("logout-all: %d", code)
	}
	if code, _ := c.do("GET", "/api/auth/me", a2, nil); code != http.StatusUnauthorized {
		t.Fatalf("other device after logout-all: %d", code)
	}

	time.Sleep(2 * time.Millisecond) // a login after RevokeAll is a new token
	a3, _ := loginAccess(t, c, "ban@example.com")
	if code, _ := c.do("GET", "/api/auth/me", a3, nil); code != http.StatusOK {
		t.Fatalf("fresh login after logout-all: %d", code)
	}
	if err := g.SetUserStatus(context.Background(), "", id, identitydomain.StatusBanned); err != nil {
		t.Fatal(err)
	}
	if code, _ := c.do("GET", "/api/auth/me", a3, nil); code != http.StatusUnauthorized && code != http.StatusForbidden {
		t.Fatalf("banned user's access token: %d", code)
	}
}

func TestSessionModeUnchangedWithoutAccessTokens(t *testing.T) {
	c, g, _ := setup(t)
	if g.AccessTokensEnabled() {
		t.Fatal("enabled without config")
	}
	tok, _ := register(t, c, "plain@example.com")
	if strings.HasPrefix(tok, "eyJ") {
		t.Fatal("session mode returned a JWT")
	}
	if w := refresh(c, nil, ""); w.Code != http.StatusNotFound && w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("refresh route mounted in session mode: %d", w.Code)
	}
}

// register0 creates an account without logging in.
func register0(t *testing.T, c client, email string) string {
	t.Helper()
	code, body := c.do("POST", "/api/auth/register", "", map[string]any{"email": email, "password": password})
	if code != http.StatusCreated {
		t.Fatalf("register: %d %v", code, body)
	}
	id, _ := body["id"].(string)
	return id
}
