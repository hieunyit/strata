package ingest

import (
	"net"
	"sync"
)

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
	reader GeoIPReader
	cache  sync.Map // string (IP) -> *GeoIPLocation
}

// NewGeoIPEnricher creates a GeoIPEnricher with the given reader.
func NewGeoIPEnricher(reader GeoIPReader) *GeoIPEnricher {
	return &GeoIPEnricher{reader: reader}
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
	if val, ok := e.cache.Load(rawIP); ok {
		return val.(*GeoIPLocation)
	}

	parsed := net.ParseIP(rawIP)
	if parsed == nil {
		return nil
	}

	// Check if IP is private, loopback, or internal (RFC 1918, RFC 4193, etc.)
	if isPrivateOrInternal(parsed) {
		loc := &GeoIPLocation{
			CountryISO: "INTERNAL",
			City:       "Internal Network",
		}
		e.cache.Store(rawIP, loc)
		return loc
	}

	if e.reader == nil {
		return nil
	}

	loc, err := e.reader.Lookup(parsed)
	if err != nil || loc == nil {
		return nil
	}

	e.cache.Store(rawIP, loc)
	return loc
}

func isPrivateOrInternal(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return true
	}
	// IPv4 Private subnets
	if ip4 := ip.To4(); ip4 != nil {
		return ip4[0] == 10 ||
			(ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31) ||
			(ip4[0] == 192 && ip4[1] == 168) ||
			(ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127) // CGNAT RFC 6598
	}
	// IPv6 ULA (fc00::/7)
	return len(ip) == net.IPv6len && (ip[0]&0xfe) == 0xfc
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
