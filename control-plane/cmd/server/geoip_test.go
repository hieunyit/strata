package main

import (
	"context"
	"errors"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestConfiguredGeoIPFiles(t *testing.T) {
	city := filepath.Join("..", "..", "ingest", "testdata", "geoip", "GeoIP2-City-Test.mmdb")
	asn := filepath.Join("..", "..", "ingest", "testdata", "geoip", "GeoLite2-ASN-Test.mmdb")
	if geo, err := loadGeoIP(t.Context(), "", ""); err != nil || geo != nil {
		t.Fatalf("default should disable database lookup: %v", err)
	}
	geo, err := loadGeoIP(t.Context(), city, asn)
	if err != nil {
		t.Fatal(err)
	}
	loc, err := geo.Resolve("81.2.69.142")
	if err != nil || loc == nil || loc.City != "London" || loc.CountryISO != "GB" || len(loc.Version) != 64 {
		t.Fatalf("configured City not usable: %+v %v", loc, err)
	}
	geo, err = loadGeoIP(t.Context(), "", asn)
	if err != nil {
		t.Fatal(err)
	}
	loc, err = geo.Resolve("1.0.0.1")
	if err != nil || loc == nil || loc.ASN != 15169 || loc.Lat != nil {
		t.Fatalf("ASN-only configuration: %+v %v", loc, err)
	}
	if geo, err := loadGeoIP(t.Context(), city, "missing-asn.mmdb"); !errors.Is(err, os.ErrNotExist) || geo != nil {
		t.Fatalf("partial file pair accepted: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if geo, err := loadGeoIP(ctx, city, asn); !errors.Is(err, context.Canceled) || geo != nil {
		t.Fatalf("canceled configuration accepted: %v", err)
	}
}

func TestGeoIPStartupRejectsInvalidAssetBeforeServices(t *testing.T) {
	if os.Getenv("STRATA_GEOIP_STARTUP_PROBE") == "1" {
		flag.CommandLine = flag.NewFlagSet("strata-control-plane", flag.ExitOnError)
		os.Args = []string{"strata-control-plane", "-geoip-city", "missing-city.mmdb"}
		main()
		return
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestGeoIPStartupRejectsInvalidAssetBeforeServices$")
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "GOMAXPROCS=2", "STRATA_GEOIP_STARTUP_PROBE=1"}
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 1 || !strings.Contains(string(out), "GeoIP") || strings.Contains(string(out), "PostgreSQL") {
		t.Fatalf("invalid asset did not fail before DB/auth/service setup: %v %s", err, out)
	}
}
