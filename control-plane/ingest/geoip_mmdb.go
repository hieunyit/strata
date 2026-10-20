package ingest

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/oschwald/maxminddb-golang/v2"
)

const MaxGeoIPDatabaseBytes = 128 << 20

// GeoIPLocation is server-resolved metadata. Missing coordinates stay nil.
type GeoIPLocation struct {
	CountryISO, Region, City, ASOrg, Version string
	Lat, Lon                                 *float64
	AccuracyKM                               *uint16
	ASN                                      uint32
}

type GeoIPReader interface {
	Lookup(net.IP) (*GeoIPLocation, error)
}

// MMDBReader owns immutable heap-backed databases, not live file mappings.
// Replacing/truncating a source file cannot corrupt in-flight lookups. Old
// readers are reclaimed by Go when their last lookup/cache generation ends.
type MMDBReader struct {
	city, asn *maxminddb.Reader
	version   string
	// networks of countries and ASNs already listed (W19-R-01)
	networks networksCache
}

func NewMMDBReader(ctx context.Context, cityFile, asnFile string) (*MMDBReader, error) {
	if cityFile == "" && asnFile == "" {
		return nil, fmt.Errorf("GeoIP needs a City or ASN database")
	}
	var data [2][]byte
	for i, path := range []string{cityFile, asnFile} {
		if path == "" {
			continue
		}
		b, err := readGeoIPFile(ctx, path)
		if err != nil {
			return nil, fmt.Errorf("GeoIP %s database: %w", []string{"city", "asn"}[i], err)
		}
		data[i] = b
	}
	return NewMMDBReaderBytes(ctx, data[0], data[1])
}

// NewMMDBReaderBytes checks and opens City and ASN databases (either may be
// nil, not both) like NewMMDBReader; the reader keeps the slices.
func NewMMDBReaderBytes(ctx context.Context, city, asn []byte) (*MMDBReader, error) {
	if city == nil && asn == nil {
		return nil, fmt.Errorf("GeoIP needs a City or ASN database")
	}
	r := &MMDBReader{}
	var hashes [64]byte
	for _, input := range []struct {
		data   []byte
		dest   **maxminddb.Reader
		offset int
		kind   string
	}{{city, &r.city, 0, "city"}, {asn, &r.asn, 32, "asn"}} {
		if input.data == nil {
			continue
		}
		db, sum, err := openGeoIPDatabase(ctx, input.data)
		if err != nil {
			return nil, fmt.Errorf("GeoIP %s database: %w", input.kind, err)
		}
		typ := db.Metadata.DatabaseType
		if len(typ) > 64 || !utf8.ValidString(typ) {
			return nil, fmt.Errorf("invalid GeoIP database type")
		}
		if input.kind == "city" && typ != "GeoIP2-City" && typ != "GeoLite2-City" {
			return nil, fmt.Errorf("GeoIP city database has unsupported type %q", typ)
		}
		if input.kind == "asn" && typ != "GeoLite2-ASN" && typ != "GeoIP2-ASN" {
			return nil, fmt.Errorf("GeoIP ASN database has unsupported type %q", typ)
		}
		*input.dest = db
		copy(hashes[input.offset:], sum[:])
	}
	r.version = fmt.Sprintf("%x", sha256.Sum256(hashes[:]))
	return r, nil
}

// Version is the fingerprint stored with each enriched event: SHA-256 of
// the City and ASN files' SHA-256 (zeros for a missing one).
func (r *MMDBReader) Version() string { return r.version }

func readGeoIPFile(ctx context.Context, path string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() > MaxGeoIPDatabaseBytes {
		return nil, fmt.Errorf("database must be a regular file up to 128 MiB")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	data, readErr := io.ReadAll(io.LimitReader(f, MaxGeoIPDatabaseBytes+1))
	closeErr := f.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	return data, nil
}

func openGeoIPDatabase(ctx context.Context, data []byte) (*maxminddb.Reader, [32]byte, error) {
	var sum [32]byte
	if len(data) > MaxGeoIPDatabaseBytes {
		return nil, sum, fmt.Errorf("database exceeds 128 MiB")
	}
	if err := ctx.Err(); err != nil {
		return nil, sum, err
	}
	db, err := maxminddb.OpenBytes(data)
	if err != nil {
		return nil, sum, err
	}
	if err := db.Verify(); err != nil {
		return nil, sum, fmt.Errorf("database structure: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, sum, err
	}
	return db, sha256.Sum256(data), nil
}

type geoNames struct {
	English string `maxminddb:"en,maxsize:256"`
}
type cityRecord struct {
	Country struct {
		ISO string `maxminddb:"iso_code,maxsize:2"`
	} `maxminddb:"country"`
	City struct {
		Names geoNames `maxminddb:"names"`
	} `maxminddb:"city"`
	Subdivisions []struct {
		Names geoNames `maxminddb:"names"`
	} `maxminddb:"subdivisions,maxsize:16"`
	Location struct {
		Lat      *float64 `maxminddb:"latitude"`
		Lon      *float64 `maxminddb:"longitude"`
		Accuracy *uint16  `maxminddb:"accuracy_radius"`
	} `maxminddb:"location"`
}

func (r *MMDBReader) Lookup(ip net.IP) (*GeoIPLocation, error) {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return nil, fmt.Errorf("invalid GeoIP address")
	}
	a = a.Unmap()
	loc := &GeoIPLocation{Version: r.version}
	found := false
	if r.city != nil {
		result := r.city.Lookup(a)
		if err := result.Err(); err != nil {
			return nil, fmt.Errorf("lookup city: %w", err)
		}
		if result.Found() {
			var city cityRecord
			if err := result.Decode(&city); err != nil {
				return nil, fmt.Errorf("decode city record: %w", err)
			}
			loc.CountryISO, loc.City = city.Country.ISO, city.City.Names.English
			if len(city.Subdivisions) > 0 {
				loc.Region = city.Subdivisions[0].Names.English
			}
			loc.Lat, loc.Lon, loc.AccuracyKM = city.Location.Lat, city.Location.Lon, city.Location.Accuracy
			found = true
		}
	}
	if r.asn != nil {
		result := r.asn.Lookup(a)
		if err := result.Err(); err != nil {
			return nil, fmt.Errorf("lookup ASN: %w", err)
		}
		if result.Found() {
			var asn struct {
				Number uint32 `maxminddb:"autonomous_system_number"`
				Org    string `maxminddb:"autonomous_system_organization,maxsize:256"`
			}
			if err := result.Decode(&asn); err != nil {
				return nil, fmt.Errorf("decode ASN record: %w", err)
			}
			loc.ASN, loc.ASOrg = asn.Number, asn.Org
			found = true
		}
	}
	if !found {
		return nil, nil
	}
	if err := validateGeoIPLocation(loc); err != nil {
		return nil, err
	}
	return loc, nil
}

func validateGeoIPLocation(loc *GeoIPLocation) error {
	if c := loc.CountryISO; c != "" && (len(c) != 2 || c[0] < 'A' || c[0] > 'Z' || c[1] < 'A' || c[1] > 'Z') {
		return fmt.Errorf("invalid GeoIP country")
	}
	for _, s := range []string{loc.City, loc.Region, loc.ASOrg} {
		if len(s) > 256 || !utf8.ValidString(s) || strings.IndexFunc(s, func(r rune) bool { return r < 32 || r == 127 }) >= 0 {
			return fmt.Errorf("invalid GeoIP text")
		}
	}
	if (loc.Lat == nil) != (loc.Lon == nil) {
		return fmt.Errorf("incomplete GeoIP coordinates")
	}
	if loc.Lat != nil && (math.IsNaN(*loc.Lat) || math.IsInf(*loc.Lat, 0) || math.Abs(*loc.Lat) > 90 || math.IsNaN(*loc.Lon) || math.IsInf(*loc.Lon, 0) || math.Abs(*loc.Lon) > 180) {
		return fmt.Errorf("invalid GeoIP coordinates")
	}
	return nil
}
