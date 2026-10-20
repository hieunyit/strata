package ingest

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
)

// W19-R-01: every network listed for a country or ASN places its own
// first address there, and the addresses of the fixtures are covered.
func TestGeoIPNetworks(t *testing.T) {
	r, err := NewMMDBReader(t.Context(), cityFixture, asnFixture)
	if err != nil {
		t.Fatal(err)
	}
	n, err := r.Networks(t.Context(), []string{"SE", "GB", "SE"}, []uint32{1221})
	if err != nil {
		t.Fatal(err)
	}
	if n.Version != r.Version() || len(n.Countries["GB"]) == 0 || len(n.Countries["SE"]) == 0 || len(n.ASNs["1221"]) == 0 {
		t.Fatalf("networks %+v", n)
	}
	covers := func(list []string, addr string) bool {
		a := netip.MustParseAddr(addr)
		for _, p := range list {
			if netip.MustParsePrefix(p).Contains(a) {
				return true
			}
		}
		return false
	}
	if !covers(n.Countries["GB"], "81.2.69.142") || !covers(n.Countries["SE"], "89.160.20.112") || !covers(n.ASNs["1221"], "1.128.0.1") {
		t.Errorf("fixture addresses not covered: %+v", n)
	}
	for c, list := range n.Countries {
		for _, p := range list {
			pfx := netip.MustParsePrefix(p)
			loc, err := r.Lookup(net.IP(pfx.Addr().AsSlice()))
			if err != nil || loc == nil || loc.CountryISO != c {
				t.Errorf("%s listed for %s, lookup %+v %v", p, c, loc, err)
			}
			if pfx.Addr().Is4In6() {
				t.Errorf("%s: IPv4 written as IPv6", p)
			}
		}
	}
	// a name without networks, the cache, and no database
	n2, err := r.Networks(t.Context(), []string{"GB", "SE"}, []uint32{1221})
	if err != nil || n2 != n {
		t.Errorf("not cached: %v", err)
	}
	if z, err := r.Networks(t.Context(), []string{"ZZ"}, nil); err != nil || len(z.Countries["ZZ"]) != 0 {
		t.Errorf("ZZ %+v %v", z, err)
	}
	city, err := NewMMDBReader(t.Context(), cityFixture, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := city.Networks(t.Context(), nil, []uint32{1221}); !errors.Is(err, ErrNoGeoIP) {
		t.Errorf("no ASN database: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := r.Networks(ctx, []string{"US"}, nil); err == nil {
		t.Error("canceled walk")
	}
	e := NewGeoIPEnricher(nil)
	if _, err := e.Networks(t.Context(), []string{"GB"}, nil); !errors.Is(err, ErrNoGeoIP) {
		t.Errorf("enricher without reader: %v", err)
	}
	e.SetReader(r)
	if got, err := e.Networks(t.Context(), []string{"GB", "SE"}, []uint32{1221}); err != nil || got != n {
		t.Errorf("enricher %v", err)
	}
}
