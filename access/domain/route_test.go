package domain

import (
	"strings"
	"testing"
)

func TestRoutePermission(t *testing.T) {
	cases := []struct{ method, path, prefix, want string }{
		{"GET", "/api/reports", "/api", "reports.read"},
		{"GET", "/api/reports/:id", "/api", "reports.read"},
		{"POST", "/api/reports", "/api", "reports.create"},
		{"PUT", "/api/reports/:id", "/api/", "reports.update"},
		{"PATCH", "/api/reports/:id", "/api", "reports.update"},
		{"DELETE", "/api/reports/:id", "/api", "reports.delete"},
		{"get", "/api/v1/Invoice-Items/:id/lines/*rest", "/api", "v1_invoice-items_lines.read"},
		{"HEAD", "/health", "", "health.read"},
		{"OPTIONS", "/health", "", "health.options"},
		{"GET", "/a b.c", "", "a_b_c.read"},
	}
	for _, c := range cases {
		p, err := RoutePermission(c.method, c.path, c.prefix)
		if err != nil || p.Code() != c.want {
			t.Errorf("%s %s = %q, %v; want %q", c.method, c.path, p.Code(), err, c.want)
		}
	}
}

func TestRoutePermissionRejectsRoutesWithoutResource(t *testing.T) {
	for _, path := range []string{"/", "/api", "/api/:id", ""} {
		if _, err := RoutePermission("GET", path, "/api"); err != ErrInvalidPermission {
			t.Errorf("%q: %v", path, err)
		}
	}
	if _, err := RoutePermission("", "/x", ""); err != ErrInvalidPermission {
		t.Error("empty method accepted")
	}
}

func TestRoutePermissionTruncatesLongResource(t *testing.T) {
	p, err := RoutePermission("GET", "/"+strings.Repeat("a", 70), "")
	if err != nil || len(p.Resource) != 64 {
		t.Fatal(p, err)
	}
}

func TestResolveRoutePermission(t *testing.T) {
	ov := map[string]string{"GET /api/reports/:id/export": " Reports.Export ", "POST /api/bad": "nope"}
	if p, err := ResolveRoutePermission("get", "/api/reports/:id/export", "/api", ov); err != nil || p.Code() != "reports.export" {
		t.Fatal(p, err)
	}
	if p, err := ResolveRoutePermission("GET", "/api/reports", "/api", ov); err != nil || p.Code() != "reports.read" {
		t.Fatal(p, err)
	}
	if _, err := ResolveRoutePermission("POST", "/api/bad", "/api", ov); err != ErrInvalidPermission {
		t.Fatal(err)
	}
	if RouteKey(" get ", "/x") != "GET /x" {
		t.Fatal(RouteKey("get", "/x"))
	}
}

func TestRouteRecordKey(t *testing.T) {
	if (RouteRecord{Method: "get", Path: "/a"}).Key() != "GET /a" {
		t.Fatal()
	}
}
