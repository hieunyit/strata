package ingest

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
)

type geoReaderFunc func(net.IP) (*GeoIPLocation, error)

func (f geoReaderFunc) Lookup(ip net.IP) (*GeoIPLocation, error) { return f(ip) }

func TestGeoIPReloadCannotPopulateNewCache(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	e := NewGeoIPEnricher(geoReaderFunc(func(net.IP) (*GeoIPLocation, error) {
		close(entered)
		<-release
		return &GeoIPLocation{CountryISO: "US"}, nil
	}))
	done := make(chan struct{})
	go func() { defer close(done); _, _ = e.Resolve("203.0.113.1") }()
	<-entered
	e.SetReader(geoReaderFunc(func(net.IP) (*GeoIPLocation, error) { return &GeoIPLocation{CountryISO: "GB"}, nil }))
	close(release)
	<-done
	loc, err := e.Resolve("203.0.113.1")
	if err != nil || loc == nil || loc.CountryISO != "GB" {
		t.Fatalf("old lookup poisoned replacement: %+v %v", loc, err)
	}
}

func TestGeoIPCacheCanonicalAndOwnedValues(t *testing.T) {
	lat, lon := 51.0, -0.1
	original := &GeoIPLocation{CountryISO: "GB", Lat: &lat, Lon: &lon}
	calls := 0
	e := NewGeoIPEnricher(geoReaderFunc(func(net.IP) (*GeoIPLocation, error) { calls++; return original, nil }))
	first, err := e.Resolve("81.2.69.142")
	if err != nil {
		t.Fatal(err)
	}
	first.CountryISO = "US"
	*first.Lat = -90
	original.CountryISO = "US"
	*original.Lon = 100
	second, err := e.Resolve("[::ffff:81.2.69.142]:443")
	if err != nil || second == nil || second.CountryISO != "GB" || *second.Lat != 51 || *second.Lon != -0.1 || calls != 1 {
		t.Fatalf("cache aliases caller/reader or raw address: %+v %v calls=%d", second, err, calls)
	}
}

func TestGeoIPCacheBoundAndPrivateFastPath(t *testing.T) {
	calls := 0
	e := NewGeoIPEnricher(geoReaderFunc(func(net.IP) (*GeoIPLocation, error) { calls++; return &GeoIPLocation{CountryISO: "GB"}, nil }))
	for _, ip := range []string{"127.0.0.1", "10.0.0.1", "100.64.1.2", "::1", "fe80::1", "fc00::1", "224.0.0.1"} {
		loc, err := e.Resolve(ip)
		if err != nil || loc == nil || loc.CountryISO != "INTERNAL" || loc.Lat != nil {
			t.Fatalf("private fast path: %s %+v %v", ip, loc, err)
		}
	}
	if calls != 0 {
		t.Fatal("private input reached database")
	}
	for i := 0; i < MaxGeoIPCacheEntries+10; i++ {
		ip := netip.AddrFrom4([4]byte{198, 18, byte(i >> 8), byte(i)})
		loc, err := e.Resolve(ip.String())
		if err != nil || loc == nil {
			t.Fatal("uncached lookup lost metadata", err)
		}
	}
	if len(e.snapshot.Load().cache) != MaxGeoIPCacheEntries {
		t.Fatal("cache exceeded its bound")
	}
}

func TestGeoIPConcurrentReloadAndResolve(t *testing.T) {
	r, err := NewMMDBReader(t.Context(), cityFixture, asnFixture)
	if err != nil {
		t.Fatal(err)
	}
	e := NewGeoIPEnricher(r)
	var wg sync.WaitGroup
	for n := 0; n < 8; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				loc, err := e.Resolve("81.2.69.142")
				if err != nil || loc == nil || loc.CountryISO != "GB" {
					t.Errorf("concurrent metadata lost: %v", err)
					return
				}
			}
		}()
	}
	for i := 0; i < 200; i++ {
		e.SetReader(r)
		e.ResetCache()
	}
	wg.Wait()
}

func TestGeoIPLookupErrorsStayVisible(t *testing.T) {
	want := errors.New("synthetic reader failure")
	e := NewGeoIPEnricher(geoReaderFunc(func(net.IP) (*GeoIPLocation, error) { return nil, want }))
	if _, err := e.Resolve("81.2.69.142"); !errors.Is(err, want) {
		t.Fatalf("error swallowed: %v", err)
	}
	for _, bad := range []string{"", "not-an-ip", string(make([]byte, 129))} {
		if loc, err := e.Resolve(bad); loc != nil || err != nil {
			t.Fatalf("invalid input: %v", err)
		}
	}
}

func TestGeoIPReloadPreservesLastGoodPair(t *testing.T) {
	e := NewGeoIPEnricher(geoReaderFunc(func(net.IP) (*GeoIPLocation, error) { return &GeoIPLocation{CountryISO: "US"}, nil }))
	if _, err := e.Resolve("81.2.69.142"); err != nil {
		t.Fatal(err)
	}
	if err := e.Reload(t.Context(), cityFixture, "missing-asn.mmdb"); err == nil {
		t.Fatal("accepted incomplete replacement pair")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := e.Reload(ctx, cityFixture, asnFixture); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v", err)
	}
	got, err := e.Resolve("81.2.69.142")
	if err != nil || got == nil || got.CountryISO != "US" {
		t.Fatalf("failed reload replaced the last good reader: %+v %v", got, err)
	}
	if err := e.Reload(t.Context(), cityFixture, asnFixture); err != nil {
		t.Fatal(err)
	}
	got, err = e.Resolve("81.2.69.142")
	if err != nil || got == nil || got.CountryISO != "GB" || len(got.Version) != 64 {
		t.Fatalf("complete replacement not published: %+v %v", got, err)
	}
}

func TestGeoIPMissingResultCachedAndReset(t *testing.T) {
	calls := 0
	e := NewGeoIPEnricher(geoReaderFunc(func(net.IP) (*GeoIPLocation, error) { calls++; return nil, nil }))
	for i := 0; i < 2; i++ {
		if loc, err := e.Resolve("192.0.2.1"); loc != nil || err != nil {
			t.Fatalf("missing result: %+v %v", loc, err)
		}
	}
	if calls != 1 {
		t.Fatal("negative result not cached")
	}
	e.ResetCache()
	if _, err := e.Resolve("192.0.2.1"); err != nil || calls != 2 {
		t.Fatalf("reset did not discard negative result: %v calls=%d", err, calls)
	}
}
