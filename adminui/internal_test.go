package adminui

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"

	"github.com/bakhod1r/guard"
	"github.com/bakhod1r/guard/guardtest"
	identitydomain "github.com/bakhod1r/guard/identity/domain"
)

func TestTemplateFuncs(t *testing.T) {
	tm := funcs["time"].(func(any) string)
	now := time.Date(2026, 1, 2, 3, 4, 0, 0, time.Local)
	var nilTime *time.Time
	cases := map[string]string{
		tm(time.Time{}): "—", tm(nilTime): "—", tm(&time.Time{}): "—", tm("x"): "—",
		tm(now): "2026-01-02 03:04", tm(&now): "2026-01-02 03:04",
	}
	for got, want := range cases {
		if got != want {
			t.Errorf("time: got %q want %q", got, want)
		}
	}
	short := funcs["short"].(func(string) string)
	if short("abc") != "abc" || short("0123456789abcdef") != "0123456789ab…" {
		t.Fatal("short")
	}
}

func TestSafeNext(t *testing.T) {
	for next, want := range map[string]string{
		"": "/guard-admin", "/guard-admin/roles": "/guard-admin/roles", "//evil": "/guard-admin",
		`/guard-admin\evil`: "/guard-admin", "/elsewhere": "/guard-admin",
	} {
		if got := safeNext("/guard-admin", next); got != want {
			t.Errorf("safeNext(%q)=%q want %q", next, got, want)
		}
	}
}

func testApp(t *testing.T) (*app, *guard.Guard) {
	gin.SetMode(gin.TestMode)
	mr := miniredis.RunT(t)
	g := guardtest.New(redis.NewClient(&redis.Options{Addr: mr.Addr()}), guard.Config{})
	return &app{g: g, o: Options{Path: "/guard-admin"}, pages: mustParse(), secret: []byte("k")}, g
}

func TestRenderEdgeCases(t *testing.T) {
	a, _ := testApp(t)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/", nil)
	a.render(c, http.StatusOK, "nope", "x", "", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("unknown page: %d", w.Code)
	}

	w = httptest.NewRecorder()
	c, _ = gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/", nil)
	a.render(c, http.StatusOK, "error", "x", "", 42) // .Data.Message on int fails
	if len(c.Errors) == 0 {
		t.Fatal("template execution error not recorded")
	}

	if ginPrincipal(c) != nil || a.can(c, "user.read") || a.canOn(c, "bad", guard.Resource{}) {
		t.Fatal("anonymous context must not be authorized")
	}
	a.g.Audit = nil
	c.Set(principalKey, &guard.Principal{User: &guard.User{ID: "1"}})
	a.audit(c, "x", "y", nil) // no-op without audit log
}

func TestNewMountDefaults(t *testing.T) {
	_, g := testApp(t)
	r := gin.New()
	Mount(r, g, Options{})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/guard-admin/login?next=/guard-admin/roles", nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `value="/guard-admin/roles"`) {
		t.Fatalf("login page: %d", w.Code)
	}
	if w.Header().Get("X-Frame-Options") != "DENY" || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("security headers: %v", w.Header())
	}
}

type failingUsers struct{ identitydomain.UserRepository }

func (failingUsers) ByEmail(context.Context, identitydomain.Email) (*identitydomain.User, error) {
	return nil, errors.New("db down")
}

func TestLoginErrorMessages(t *testing.T) {
	_, g := testApp(t)
	ctx := context.Background()
	if _, err := g.CreateAccount(ctx, "1", "a@example.com", "password123", nil, guard.RequestMeta{}); err != nil {
		t.Fatal(err)
	}
	r := gin.New()
	Mount(r, g, Options{InsecureCookie: true})
	login := func(r *gin.Engine, pw string) string {
		form := url.Values{"email": {"a@example.com"}, "password": {pw}}
		req := httptest.NewRequest("POST", "/guard-admin/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		loc, _ := url.QueryUnescape(w.Header().Get("Location"))
		return loc
	}
	for i := 0; i < 5; i++ {
		login(r, "wrong-password")
	}
	if loc := login(r, "password123"); !strings.Contains(loc, identitydomain.ErrUserLocked.Error()) {
		t.Fatalf("locked message: %s", loc)
	}

	gi := guard.Build(guard.Repositories{Users: failingUsers{}, Hasher: nil}, guard.Config{})
	r2 := gin.New()
	Mount(r2, gi, Options{})
	if loc := login(r2, "password123"); !strings.Contains(loc, "internal error") {
		t.Fatalf("internal error message: %s", loc)
	}
}
