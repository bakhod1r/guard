package httpguard

import (
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestClientIPTrustedProxies(t *testing.T) {
	proxies := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("10.0.0.0/8")}
	cases := []struct {
		name   string
		remote string
		xff    string
		want   string
	}{
		{"spoofed left entry is skipped", "192.0.2.1:1234", "1.1.1.1, 203.0.113.7, 10.0.0.1", "203.0.113.7"},
		{"untrusted peer ignores header", "198.51.100.9:1234", "203.0.113.7", "198.51.100.9"},
		{"no header uses peer", "192.0.2.1:1234", "", "192.0.2.1"},
		{"garbage entry stops the walk", "192.0.2.1:1234", "203.0.113.7, not-an-ip", "192.0.2.1"},
		{"all hops trusted gives left-most", "192.0.2.1:1234", "10.0.0.5, 10.0.0.1", "10.0.0.5"},
		{"ipv4-mapped peer is trusted", "[::ffff:192.0.2.1]:1234", "203.0.113.7", "203.0.113.7"},
		{"multiple header lines", "192.0.2.1:1234", "", "203.0.113.8"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = c.remote
			if c.xff != "" {
				r.Header.Set("X-Forwarded-For", c.xff)
			}
			if c.name == "multiple header lines" {
				r.Header.Add("X-Forwarded-For", "1.1.1.1")
				r.Header.Add("X-Forwarded-For", "203.0.113.8")
			}
			o := Options{TrustedProxies: proxies}.withDefaults()
			if got := o.ClientIP(r); got != c.want {
				t.Fatalf("ClientIP = %q, want %q", got, c.want)
			}
		})
	}
}

func TestClientIPForwardedForRejectsNonIP(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil) // RemoteAddr 192.0.2.1:1234
	r.Header.Set("X-Forwarded-For", "guard:session:x, 10.0.0.1")
	o := Options{TrustForwardedFor: true}.withDefaults()
	if got := o.ClientIP(r); got != "192.0.2.1" {
		t.Fatalf("ClientIP = %q, want the peer address for a non-IP header", got)
	}
}
