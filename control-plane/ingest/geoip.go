package ingest

import (
	"net"
	"sync"
	"sync/atomic"
)

// MaxGeoIPCacheEntries prevents unbounded memory consumption under IP flood attacks.
const MaxGeoIPCacheEntries = 50000

// GeoIPLocation encapsulates resolved geographical and network metadata for an IP.
type GeoIPLocation struct {
	CountryISO string  `json:"country_iso"`
	City       string  `json:"city"`
	Lat        float32 `json:"lat"`
	Lon        float32 `json:"lon"`
	ASN        uint32  `json:"asn"`
	ASOrg      string  `json:"as_org"`
}

// GeoIPReader defines the interface for GeoIP database lookups.
type GeoIPReader interface {
	Lookup(ip net.IP) (*GeoIPLocation, error)
}

// GeoIPEnricher enriches incoming security events with GeoIP and ASN metadata.
type GeoIPEnricher struct {
	reader        GeoIPReader
	cache         atomic.Pointer[sync.Map] // atomic swap on max entries
	cachedEntries atomic.Int64
}

// NewGeoIPEnricher creates a GeoIPEnricher with the given reader.
func NewGeoIPEnricher(reader GeoIPReader) *GeoIPEnricher {
	e := &GeoIPEnricher{reader: reader}
	e.cache.Store(&sync.Map{})
	return e
}

func (e *GeoIPEnricher) getCache() *sync.Map {
	c := e.cache.Load()
	if c == nil {
		newMap := &sync.Map{}
		if e.cache.CompareAndSwap(nil, newMap) {
			return newMap
		}
		return e.cache.Load()
	}
	return c
}

// Enrich populates GeoIP fields in the provided Event.
func (e *GeoIPEnricher) Enrich(evt *Event) {
	if evt == nil || evt.ClientIP == "" {
		return
	}

	loc := e.Resolve(evt.ClientIP)
	if loc != nil {
		evt.CountryISO = loc.CountryISO
		evt.City = loc.City
		evt.Lat = loc.Lat
		evt.Lon = loc.Lon
		evt.ASN = loc.ASN
		evt.ASOrg = loc.ASOrg
	}
}

// Resolve looks up the IP, handling private IPs, caching, and reader lookup.
func (e *GeoIPEnricher) Resolve(rawIP string) *GeoIPLocation {
	cache := e.getCache()
	if val, ok := cache.Load(rawIP); ok {
		return val.(*GeoIPLocation)
	}

	host := rawIP
	if h, _, err := net.SplitHostPort(rawIP); err == nil {
		host = h
	}

	parsed := net.ParseIP(host)
	if parsed == nil {
		return nil
	}

	// Check if IP is private, loopback, or internal (RFC 1918, RFC 4193, etc.)
	if isPrivateOrInternal(parsed) {
		loc := &GeoIPLocation{
			CountryISO: "INTERNAL",
			City:       "Internal Network",
		}
		e.storeCache(rawIP, loc)
		return loc
	}

	if e.reader == nil {
		return nil
	}

	loc, err := e.reader.Lookup(parsed)
	if err != nil || loc == nil {
		return nil
	}

	e.storeCache(rawIP, loc)
	return loc
}

func (e *GeoIPEnricher) storeCache(rawIP string, loc *GeoIPLocation) {
	if e.cachedEntries.Load() >= MaxGeoIPCacheEntries {
		if e.cachedEntries.CompareAndSwap(e.cachedEntries.Load(), 0) {
			e.cache.Store(&sync.Map{})
		}
	}
	cache := e.getCache()
	if _, loaded := cache.LoadOrStore(rawIP, loc); !loaded {
		e.cachedEntries.Add(1)
	}
}

func isPrivateOrInternal(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsPrivate() {
		return true
	}
	// CGNAT RFC 6598: 100.64.0.0/10
	if ip4 := ip.To4(); ip4 != nil {
		return ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127
	}
	return false
}

// MockGeoIPReader implements GeoIPReader with predefined mappings for testing.
type MockGeoIPReader struct {
	data map[string]GeoIPLocation
}

// NewMockGeoIPReader creates a mock reader with test IP mappings.
func NewMockGeoIPReader(data map[string]GeoIPLocation) *MockGeoIPReader {
	return &MockGeoIPReader{data: data}
}

// Lookup returns the mapped GeoIPLocation for testing.
func (m *MockGeoIPReader) Lookup(ip net.IP) (*GeoIPLocation, error) {
	if m.data == nil {
		return nil, nil
	}
	if loc, ok := m.data[ip.String()]; ok {
		return &loc, nil
	}
	return nil, nil
}
