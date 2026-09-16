package adminui_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/bakhod1r/guard"
	"github.com/bakhod1r/guard/adminui"
	"github.com/bakhod1r/guard/guardtest"
)

// TestHandlerServesPanelOnPlainServeMux checks the framework-agnostic entry
// point: no Gin router on the host side, login and an authenticated page both
// work through a stdlib mux.
func TestHandlerServesPanelOnPlainServeMux(t *testing.T) {
	mr := miniredis.RunT(t)
	g := guardtest.New(redis.NewClient(&redis.Options{Addr: mr.Addr()}), guard.Config{})
	if _, err := g.EnsureAdmin(t.Context(), "1", "admin@example.com", "admin-password-42"); err != nil {
		t.Fatalf("ensure admin: %v", err)
	}
	mux := http.NewServeMux()
	mux.Handle("/guard-admin/", adminui.Handler(g, adminui.Options{InsecureCookie: true}))

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "/guard-admin/login", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("login page: %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "csrf") && !strings.Contains(w.Body.String(), "password") {
		t.Fatalf("login page body unexpected: %.200s", w.Body.String())
	}

	form := url.Values{"email": {"admin@example.com"}, "password": {"admin-password-42"}}
	req := httptest.NewRequest("POST", "/guard-admin/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "http://"+req.Host)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther && w.Code != http.StatusFound {
		t.Fatalf("login: %d %s", w.Code, w.Body)
	}
	cookies := w.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("login set no cookie")
	}

	req = httptest.NewRequest("GET", "/guard-admin/", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("dashboard: %d", w.Code)
	}
}
