package ingest

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/oschwald/maxminddb-golang/v2"
)

// W19-R-01: the networks of the countries and ASNs a bundle's rules name,
// from the loaded GeoIP databases, in the JSON strata-compile --geo reads.
// The bundle carries only these (not the databases): an engine places the
// client address among them.

// GeoNetworks are networks per country (ISO code) and ASN (decimal).
type GeoNetworks struct {
	Version   string              `json:"version"`
	Countries map[string][]string `json:"countries,omitempty"`
	ASNs      map[string][]string `json:"asns,omitempty"`
}

// GeoNetworker lists the networks of countries and ASNs.
type GeoNetworker interface {
	Networks(ctx context.Context, countries []string, asns []uint32) (*GeoNetworks, error)
}

// ErrNoGeoIP: no GeoIP database to take networks from.
var ErrNoGeoIP = errors.New("geoip: no database loaded (-geoip-city/-geoip-asn or STRATA_GEOIP_*_URL)")

type networksCache struct {
	mu   sync.Mutex
	byID map[string]*GeoNetworks
}

// Networks walks the City database for the countries and the ASN database
// for the ASNs (each once per version and set of names; the result is
// kept). A name with no network gets an empty list.
func (r *MMDBReader) Networks(ctx context.Context, countries []string, asns []uint32) (*GeoNetworks, error) {
	countries = slices.Sorted(slices.Values(countries))
	countries = slices.Compact(countries)
	asns = slices.Sorted(slices.Values(asns))
	asns = slices.Compact(asns)
	if len(countries) > 0 && r.city == nil || len(asns) > 0 && r.asn == nil {
		return nil, ErrNoGeoIP
	}
	key := strings.Join(countries, ",") + "|" + fmt.Sprint(asns)
	r.networks.mu.Lock()
	defer r.networks.mu.Unlock()
	if n, ok := r.networks.byID[key]; ok {
		return n, nil
	}
	out := &GeoNetworks{Version: r.version}
	if len(countries) > 0 {
		want := map[string]bool{}
		out.Countries = map[string][]string{}
		for _, c := range countries {
			want[c] = true
			out.Countries[c] = []string{}
		}
		err := walk(ctx, r.city, func(res maxminddb.Result) error {
			var rec struct {
				Country struct {
					ISO string `maxminddb:"iso_code"`
				} `maxminddb:"country"`
			}
			if err := res.Decode(&rec); err != nil {
				return err
			}
			if want[rec.Country.ISO] {
				out.Countries[rec.Country.ISO] = append(out.Countries[rec.Country.ISO], prefixString(res.Prefix()))
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("geoip: city networks: %w", err)
		}
	}
	if len(asns) > 0 {
		want := map[uint32]bool{}
		out.ASNs = map[string][]string{}
		for _, a := range asns {
			want[a] = true
			out.ASNs[strconv.FormatUint(uint64(a), 10)] = []string{}
		}
		err := walk(ctx, r.asn, func(res maxminddb.Result) error {
			var rec struct {
				Number uint32 `maxminddb:"autonomous_system_number"`
			}
			if err := res.Decode(&rec); err != nil {
				return err
			}
			if want[rec.Number] {
				k := strconv.FormatUint(uint64(rec.Number), 10)
				out.ASNs[k] = append(out.ASNs[k], prefixString(res.Prefix()))
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("geoip: ASN networks: %w", err)
		}
	}
	if r.networks.byID == nil {
		r.networks.byID = map[string]*GeoNetworks{}
	}
	r.networks.byID[key] = out
	return out, nil
}

func walk(ctx context.Context, db *maxminddb.Reader, f func(maxminddb.Result) error) error {
	n := 0
	for res := range db.Networks() {
		if n++; n%4096 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		if err := res.Err(); err != nil {
			return err
		}
		if err := f(res); err != nil {
			return err
		}
	}
	return ctx.Err()
}

// prefixString writes an IPv4 network of an IPv6 database as IPv4.
func prefixString(p netip.Prefix) string {
	if a := p.Addr(); a.Is4In6() && p.Bits() >= 96 {
		return netip.PrefixFrom(a.Unmap(), p.Bits()-96).String()
	}
	return p.String()
}

// Networks of the enricher's current databases.
func (e *GeoIPEnricher) Networks(ctx context.Context, countries []string, asns []uint32) (*GeoNetworks, error) {
	s := e.snapshot.Load()
	if s == nil || s.reader == nil {
		return nil, ErrNoGeoIP
	}
	n, ok := s.reader.(GeoNetworker)
	if !ok {
		return nil, ErrNoGeoIP
	}
	return n.Networks(ctx, countries, asns)
}
