package adminui_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestLoginRequiredAndCSRF(t *testing.T) {
	p := newPanel(t)
	p.account("1", "admin@example.com", true)

	code, _ := p.get("/guard-admin/roles")
	if code != http.StatusSeeOther {
		t.Fatalf("anonymous page: %d", code)
	}
	code, _, h := p.post("/guard-admin/login", url.Values{"email": {"admin@example.com"}, "password": {"bad-password"}})
	if code != http.StatusSeeOther || !strings.Contains(location(h), "error=") {
		t.Fatalf("bad login: %d %s", code, location(h))
	}
	p.login("admin@example.com")
	if code, body := p.get("/guard-admin"); code != http.StatusOK || !strings.Contains(body, "Guard admin") {
		t.Fatalf("dashboard: %d", code)
	}
	if code, _, _ := p.post("/guard-admin/logout", url.Values{"_csrf": {"forged"}}); code != http.StatusForbidden {
		t.Fatalf("forged csrf: %d", code)
	}
	if code, _, _ := p.post("/guard-admin/logout", nil); code != http.StatusSeeOther {
		t.Fatalf("logout: %d", code)
	}
	if code, _ := p.get("/guard-admin"); code != http.StatusSeeOther {
		t.Fatalf("session alive after logout: %d", code)
	}
}

func TestOpenRedirectBlocked(t *testing.T) {
	p := newPanel(t)
	p.account("1", "admin@example.com", true)
	for _, next := range []string{"https://evil.example", "//evil.example", "/other", "/guard-admin/../x"} {
		code, _, h := p.post("/guard-admin/login", url.Values{"email": {"admin@example.com"}, "password": {"tr0ub4dor-guard-42"}, "next": {next}})
		if code != http.StatusSeeOther || location(h) != "/guard-admin" {
			t.Fatalf("next %q redirected to %q", next, location(h))
		}
	}
}

func TestNonAdminForbidden(t *testing.T) {
	p := newPanel(t)
	p.account("2", "user@example.com", false)
	p.login("user@example.com")
	if code, _ := p.get("/guard-admin/roles"); code != http.StatusForbidden {
		t.Fatalf("user opened roles: %d", code)
	}
	if code, body := p.get("/guard-admin"); code != http.StatusOK || strings.Contains(body, ">Roles<") {
		t.Fatalf("nav leaks forbidden sections: %d", code)
	}
}
