package ingest

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
)

const MaxGeoIPCacheEntries = 50000

var geoIPSharedAddressSpace = netip.MustParsePrefix("100.64.0.0/10")

type geoIPSnapshot struct {
	reader GeoIPReader
	mu     sync.RWMutex
	cache  map[netip.Addr]*GeoIPLocation
}

// GeoIPEnricher publishes the reader and its bounded cache as one generation.
// A lookup may finish against the old reader, but cannot poison a new cache.
type GeoIPEnricher struct{ snapshot atomic.Pointer[geoIPSnapshot] }

func NewGeoIPEnricher(reader GeoIPReader) *GeoIPEnricher {
	e := &GeoIPEnricher{}
	e.SetReader(reader)
	return e
}

func newGeoSnapshot(r GeoIPReader) *geoIPSnapshot {
	return &geoIPSnapshot{reader: r, cache: make(map[netip.Addr]*GeoIPLocation)}
}

// Readers must be immutable and support concurrent Lookup calls. Heap-backed
// MMDBReader generations remain alive for outstanding lookups without mmap Close races.
func (e *GeoIPEnricher) SetReader(reader GeoIPReader) { e.snapshot.Store(newGeoSnapshot(reader)) }

// Reload publishes a complete verified pair only on success. Failed/canceled
// loads preserve the active reader and its cache. Callers schedule and serialize
// reload attempts; this does not download assets or implement the W17 updater.
func (e *GeoIPEnricher) Reload(ctx context.Context, cityFile, asnFile string) error {
	reader, err := NewMMDBReader(ctx, cityFile, asnFile)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	e.SetReader(reader)
	return nil
}

func (e *GeoIPEnricher) ResetCache() {
	for {
		old := e.snapshot.Load()
		if old == nil {
			return
		}
		if e.snapshot.CompareAndSwap(old, newGeoSnapshot(old.reader)) {
			return
		}
	}
}

func cloneGeoLocation(loc *GeoIPLocation) *GeoIPLocation {
	if loc == nil {
		return nil
	}
	out := *loc
	if loc.Lat != nil {
		v := *loc.Lat
		out.Lat = &v
	}
	if loc.Lon != nil {
		v := *loc.Lon
		out.Lon = &v
	}
	if loc.AccuracyKM != nil {
		v := *loc.AccuracyKM
		out.AccuracyKM = &v
	}
	return &out
}

func parseGeoIPAddr(raw string) (netip.Addr, bool) {
	if len(raw) == 0 || len(raw) > 128 {
		return netip.Addr{}, false
	}
	a, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		hp, err := netip.ParseAddrPort(strings.TrimSpace(raw))
		if err != nil {
			return netip.Addr{}, false
		}
		a = hp.Addr()
	}
	return a.WithZone("").Unmap(), true
}

func (e *GeoIPEnricher) Resolve(raw string) (*GeoIPLocation, error) {
	a, ok := parseGeoIPAddr(raw)
	if !ok {
		return nil, nil
	}
	generation := e.snapshot.Load()
	if generation == nil {
		return nil, nil
	}
	if geoIPInternal(a) {
		return &GeoIPLocation{CountryISO: "INTERNAL"}, nil
	}
	generation.mu.RLock()
	cached, found := generation.cache[a]
	generation.mu.RUnlock()
	if found {
		return cloneGeoLocation(cached), nil
	}
	if generation.reader == nil {
		return nil, nil
	}
	location, err := generation.reader.Lookup(a.AsSlice())
	if err != nil {
		return nil, fmt.Errorf("resolve GeoIP: %w", err)
	}
	location = cloneGeoLocation(location)
	if location != nil {
		if err := validateGeoIPLocation(location); err != nil {
			return nil, err
		}
	}
	generation.mu.Lock()
	if len(generation.cache) < MaxGeoIPCacheEntries {
		generation.cache[a] = cloneGeoLocation(location)
	}
	generation.mu.Unlock()
	return location, nil
}

func geoIPInternal(a netip.Addr) bool {
	return a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsMulticast() || a.IsUnspecified() || !a.IsGlobalUnicast() || geoIPSharedAddressSpace.Contains(a)
}

// Version of the active reader: the fingerprint events get ("" without a
// reader, or for a reader that has none).
func (e *GeoIPEnricher) Version() string {
	g := e.snapshot.Load()
	if g == nil || g.reader == nil {
		return ""
	}
	if v, ok := g.reader.(interface{ Version() string }); ok {
		return v.Version()
	}
	return ""
}
