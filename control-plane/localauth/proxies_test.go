package localauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func TestParseTrustedProxies(t *testing.T) {
	if p, err := ParseTrustedProxies(" , "); p != nil || err != nil {
		t.Fatalf("empty list: %v %v", p, err)
	}
	p, err := ParseTrustedProxies("10.1.0.0/16, 192.0.2.7, ::ffff:198.51.100.9, ui, proxy-1.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(p.prefixes) != 3 || strings.Join(p.hosts, ",") != "ui,proxy-1.example.test" {
		t.Fatalf("prefixes %v hosts %v", p.prefixes, p.hosts)
	}
	for _, bad := range []string{"10.0.0.0/33", "ui_proxy", "-ui", "a..b", "http://ui"} {
		if _, err := ParseTrustedProxies(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestTrustedProxiesByName(t *testing.T) {
	p, _ := ParseTrustedProxies("172.16.5.0/24,ui")
	addrs := map[string][]netip.Addr{"ui": {netip.MustParseAddr("172.20.0.9")}}
	p.lookup = func(_ context.Context, h string) ([]netip.Addr, error) {
		if a, ok := addrs[h]; ok {
			return a, nil
		}
		return nil, errors.New("no such host")
	}
	in := func(s string) bool { return p.Contains(netip.MustParseAddr(s)) }
	if !in("172.16.5.200") || in("172.20.0.9") {
		t.Fatal("before the first refresh only the CIDR is trusted")
	}
	p.Refresh(context.Background())
	if !in("172.20.0.9") || !in("::ffff:172.20.0.9") || in("172.20.0.10") {
		t.Fatal("the name's address is trusted, and only it")
	}
	// the proxy restarts with another address: the old one is no longer trusted
	addrs["ui"] = []netip.Addr{netip.MustParseAddr("172.20.0.11")}
	p.Refresh(context.Background())
	if in("172.20.0.9") || !in("172.20.0.11") {
		t.Fatal("refresh did not follow the new address")
	}
	// down: trusted for no address
	delete(addrs, "ui")
	p.Refresh(context.Background())
	if in("172.20.0.11") {
		t.Fatal("an unresolvable name still trusts its old address")
	}
	var none *TrustedProxies
	if none.Contains(netip.MustParseAddr("127.0.0.1")) {
		t.Fatal("nil trusts nothing")
	}
}

func TestClientIPThroughProxies(t *testing.T) {
	p, _ := ParseTrustedProxies("192.0.2.80")
	h := &Handler{TrustedProxies: p}
	ip := func(remote, xff string) string {
		r := httptest.NewRequest(http.MethodPost, "/v1/auth/login", nil)
		r.RemoteAddr = remote
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		return h.clientIP(r)
	}
	for _, c := range []struct{ remote, xff, want string }{
		{"192.0.2.80:5000", "203.0.113.5", "203.0.113.5"},
		// only the address the trusted proxy saw counts, not what the client claimed before it
		{"192.0.2.80:5000", "10.9.9.9, 203.0.113.6", "203.0.113.6"},
		{"192.0.2.80:5000", "", "192.0.2.80"},
		{"192.0.2.80:5000", "garbage", "192.0.2.80"},
		// a client that is not a trusted proxy cannot pick its address
		{"198.51.100.4:6000", "203.0.113.5", "198.51.100.4"},
		{"[::ffff:192.0.2.80]:5000", "2001:db8::1", "2001:db8::1"},
	} {
		if got := ip(c.remote, c.xff); got != c.want {
			t.Errorf("remote %s xff %q: %s, want %s", c.remote, c.xff, got, c.want)
		}
	}
}
