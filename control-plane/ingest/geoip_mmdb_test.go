package ingest

import (
	"context"
	"errors"
	"math"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

const cityFixture = "testdata/geoip/GeoIP2-City-Test.mmdb"
const asnFixture = "testdata/geoip/GeoLite2-ASN-Test.mmdb"

func TestMMDBRealCityAndASN(t *testing.T) {
	r, err := NewMMDBReader(t.Context(), cityFixture, asnFixture)
	if err != nil {
		t.Fatal(err)
	}
	city, err := r.Lookup(net.ParseIP("81.2.69.142"))
	if err != nil || city == nil {
		t.Fatalf("city: %+v %v", city, err)
	}
	if city.CountryISO != "GB" || city.City != "London" || city.Region != "England" || city.Lat == nil || city.Lon == nil || math.Abs(*city.Lat-51.5142) > 0.00001 || math.Abs(*city.Lon+0.0931) > 0.00001 || city.AccuracyKM == nil || *city.AccuracyKM != 10 || len(city.Version) != 64 {
		t.Fatalf("wrong real fixture result: %+v", city)
	}
	asn, err := r.Lookup(net.ParseIP("1.0.0.1"))
	if err != nil || asn == nil || asn.ASN != 15169 || asn.ASOrg != "Google Inc." || asn.Lat != nil || asn.Lon != nil {
		t.Fatalf("ASN or missing coordinates: %+v %v", asn, err)
	}
	if loc, err := r.Lookup(net.ParseIP("192.0.2.1")); err != nil || loc != nil {
		t.Fatalf("fabricated location: %+v %v", loc, err)
	}
	if _, err := r.Lookup(nil); err == nil {
		t.Fatal("accepted invalid address")
	}
}

func TestMMDBRejectsWrongTypeAndCorruption(t *testing.T) {
	for _, files := range [][2]string{{"", ""}, {"missing", ""}, {asnFixture, ""}, {"", cityFixture}} {
		if _, err := NewMMDBReader(t.Context(), files[0], files[1]); err == nil {
			t.Fatalf("accepted invalid sources %v", files)
		}
	}
	d := t.TempDir()
	bad := filepath.Join(d, "bad.mmdb")
	if err := os.WriteFile(bad, []byte("invalid mmdb"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewMMDBReader(t.Context(), bad, ""); err == nil {
		t.Fatal("accepted corrupt database")
	}
	f, err := os.Create(bad)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(MaxGeoIPDatabaseBytes + 1); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := NewMMDBReader(t.Context(), bad, ""); err == nil {
		t.Fatal("accepted oversized database")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := NewMMDBReader(ctx, cityFixture, ""); !errors.Is(err, context.Canceled) {
		t.Fatalf("ignored cancellation: %v", err)
	}
}

func TestMMDBSourceReplacementDoesNotChangeActiveReader(t *testing.T) {
	data, err := os.ReadFile(cityFixture)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "city.mmdb")
	if err := os.WriteFile(file, data, 0600); err != nil {
		t.Fatal(err)
	}
	r, err := NewMMDBReader(t.Context(), file, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("replaced"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := r.Lookup(net.ParseIP("81.2.69.142"))
	if err != nil || got == nil || got.CountryISO != "GB" {
		t.Fatalf("file mutation corrupted active reader: %v", err)
	}
}

func TestMMDBLookupFailureIsNotMissingRecord(t *testing.T) {
	r, err := NewMMDBReader(t.Context(), cityFixture, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := r.city.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Lookup(net.ParseIP("81.2.69.142")); err == nil {
		t.Fatal("lookup failure was silently treated as a missing location")
	}
}

func TestMMDBConcurrentLookupsAndReturnedValueIsolation(t *testing.T) {
	r, err := NewMMDBReader(t.Context(), cityFixture, asnFixture)
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for j := 0; j < 100; j++ {
				got, err := r.Lookup(net.ParseIP("81.2.69.142"))
				if err != nil || got == nil || got.Lat == nil || math.Abs(*got.Lat-51.5142) > 0.00001 {
					t.Errorf("concurrent lookup changed: %v", err)
					return
				}
				*got.Lat = -90
			}
		}()
	}
	workers.Wait()
}

func TestGeoIPLocationRejectsInvalidMetadata(t *testing.T) {
	lat, lon, nan := 91.0, 0.0, math.NaN()
	for _, loc := range []GeoIPLocation{{CountryISO: "ZZZ"}, {CountryISO: "gb"}, {City: "bad\x00city"}, {Lat: &lat, Lon: &lon}, {Lat: &nan, Lon: &lon}, {Lat: &lon}} {
		if err := validateGeoIPLocation(&loc); err == nil {
			t.Fatalf("accepted invalid location: %+v", loc)
		}
	}
	if err := validateGeoIPLocation(&GeoIPLocation{CountryISO: "GB", Lat: &lon, Lon: &lon}); err != nil {
		t.Fatal("valid zero coordinates rejected", err)
	}
}
