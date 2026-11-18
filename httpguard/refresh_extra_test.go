package httpguard_test

import (
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
)

func setupAccessMR(t *testing.T) (client, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	g := guardtest.New(redis.NewClient(&redis.Options{Addr: mr.Addr()}), guard.Config{AccessToken: &guard.AccessTokenOptions{
		Keys: []guard.AccessKey{{ID: "k1", Secret: []byte(strings.Repeat("s", 32))}}, TTL: 3 * time.Hour, Issuer: "test", Audience: "test",
	}})
	mux := http.NewServeMux()
	httpguard.Mount(mux, g, options())
	return client{t: t, router: mux}, mr
}

func refreshBearer(c client, tok string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	c.router.ServeHTTP(w, c.request("POST", "/api/auth/refresh", tok, nil))
	return w
}

func TestRefreshWithoutTokenIs401(t *testing.T) {
	c, _ := setupAccess(t)
	if w := refresh(c, nil, ""); w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "refresh token required") {
		t.Fatalf("no token: %d %s", w.Code, w.Body)
	}
}

func TestRefreshWithBearerTokenSkipsCSRF(t *testing.T) {
	c, _ := setupAccess(t)
	register0(t, c, "bearer@example.com")
	_, ck := loginAccess(t, c, "bearer@example.com")
	w := refreshBearer(c, ck.Value)
	if w.Code != http.StatusOK {
		t.Fatalf("bearer refresh: %d %s", w.Code, w.Body)
	}
	// unknown bearer refresh token: 401 and no cookie is cleared
	w = refreshBearer(c, "nope")
	if w.Code != http.StatusUnauthorized || len(w.Result().Cookies()) != 0 {
		t.Fatalf("unknown bearer: %d %v", w.Code, w.Result().Cookies())
	}
}

func TestRefreshStorageOutageKeepsCookie(t *testing.T) {
	c, mr := setupAccessMR(t)
	register0(t, c, "outage@example.com")
	_, ck := loginAccess(t, c, "outage@example.com")
	mr.Close()
	w := refresh(c, ck, "http://example.com")
	if w.Code < 500 {
		t.Fatalf("outage: %d %s", w.Code, w.Body)
	}
	for _, x := range w.Result().Cookies() {
		if x.Name == "guard_refresh" {
			t.Fatalf("cookie touched on outage: %+v", x)
		}
	}
}

func TestRefreshTokenFromAndCSRFOK(t *testing.T) {
	o := options()
	r := httptest.NewRequest("POST", "/", nil)
	if tok, ck := httpguard.RefreshTokenFrom(r, o); tok != "" || ck {
		t.Fatalf("empty: %q %v", tok, ck)
	}
	r.Header.Set("Authorization", "Basic abc")
	if tok, _ := httpguard.RefreshTokenFrom(r, o); tok != "" {
		t.Fatalf("basic: %q", tok)
	}
	r.Header.Set("Authorization", "bearer  xyz ")
	if tok, ck := httpguard.RefreshTokenFrom(r, o); tok != "xyz" || ck {
		t.Fatalf("bearer: %q %v", tok, ck)
	}
	if httpguard.CSRFOK(r, o) {
		t.Fatal("csrf without origin or header must fail")
	}
	r.Header.Set("X-Guard-CSRF", "1")
	if !httpguard.CSRFOK(r, o) {
		t.Fatal("csrf header must pass")
	}
}
