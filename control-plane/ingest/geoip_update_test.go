package ingest

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type memObjects struct {
	mu      sync.Mutex
	m       map[string][]byte
	puts    int
	failPut bool
}

func (o *memObjects) Put(_ context.Context, key string, data []byte, _ string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.failPut {
		return errors.New("object store down")
	}
	if o.m == nil {
		o.m = map[string][]byte{}
	}
	o.m[key] = append([]byte(nil), data...)
	o.puts++
	return nil
}

func (o *memObjects) Get(_ context.Context, key string) ([]byte, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	b, ok := o.m[key]
	if !ok {
		return nil, errors.New("the specified key does not exist")
	}
	return append([]byte(nil), b...), nil
}

// tarGz packs files as MaxMind ships a database: a directory with the
// .mmdb and its license texts.
func tarGz(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	if err := tw.WriteHeader(&tar.Header{Name: "GeoIP2-City-Test_20261019/", Typeflag: tar.TypeDir, Mode: 0o755}); err != nil {
		t.Fatal(err)
	}
	for name, b := range files {
		if err := tw.WriteHeader(&tar.Header{Name: "GeoIP2-City-Test_20261019/" + name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(b))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(b); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

type geoServer struct {
	*httptest.Server
	hits atomic.Int64
}

func newGeoServer(t *testing.T) *geoServer {
	t.Helper()
	city, err := os.ReadFile(cityFixture)
	if err != nil {
		t.Fatal(err)
	}
	asn, err := os.ReadFile(asnFixture)
	if err != nil {
		t.Fatal(err)
	}
	routes := map[string][]byte{
		"/city.tar.gz": tarGz(t, map[string][]byte{"GeoIP2-City-Test.mmdb": city, "LICENSE.txt": []byte("example license")}),
		"/asn.mmdb":    asn,
		"/corrupt":     []byte("not a database at all"),
		"/two.tar.gz":  tarGz(t, map[string][]byte{"a.mmdb": city, "b.mmdb": city}),
		"/none.tar.gz": tarGz(t, map[string][]byte{"README": []byte("x")}),
	}
	s := &geoServer{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.hits.Add(1)
		switch r.URL.Path {
		case "/error":
			http.Error(w, "down", http.StatusInternalServerError)
		case "/to-file":
			http.Redirect(w, r, "file:///etc/passwd", http.StatusFound)
		default:
			b, ok := routes[r.URL.Path]
			if !ok {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write(b)
		}
	}))
	t.Cleanup(s.Close)
	return s
}

const exampleKey = "license_key=example-secret-key"

func TestGeoIPUpdateStoresActivatesAndRedacts(t *testing.T) {
	s := newGeoServer(t)
	objects := &memObjects{}
	enricher := NewGeoIPEnricher(nil)
	u := &GeoIPUpdater{CityURL: s.URL + "/city.tar.gz?" + exampleKey, ASNURL: s.URL + "/asn.mmdb?" + exampleKey,
		Objects: objects, Enricher: enricher, Now: func() time.Time { return time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC) }}

	v, changed, err := u.Update(t.Context())
	if err != nil || !changed || len(v) != 64 || enricher.Version() != v {
		t.Fatalf("first update: %q %v %v (active %q)", v, changed, err, enricher.Version())
	}
	loc, err := enricher.Resolve("81.2.69.142")
	if err != nil || loc == nil || loc.CountryISO != "GB" || loc.Version != v {
		t.Fatalf("new reader not active: %+v %v", loc, err)
	}
	for _, key := range []string{"geoip/" + v + "/city.mmdb", "geoip/" + v + "/asn.mmdb", "geoip/" + v + "/manifest.json", geoIPLatestKey} {
		if _, err := objects.Get(t.Context(), key); err != nil {
			t.Errorf("%s not stored", key)
		}
	}
	latest, _ := objects.Get(t.Context(), geoIPLatestKey)
	var m GeoIPManifest
	if err := json.Unmarshal(latest, &m); err != nil || m.Version != v || len(m.CitySHA256) != 64 || len(m.ASNSHA256) != 64 ||
		m.CityBuiltAt.IsZero() || m.FetchedAt != u.Now() || m.CitySource != s.URL+"/city.tar.gz" {
		t.Fatalf("manifest: %s %v", latest, err)
	}
	for k, b := range objects.m {
		if bytes.Contains(b, []byte("example-secret-key")) {
			t.Fatalf("license key stored in %s", k)
		}
	}
	if !u.LastSuccess().Equal(u.Now()) || u.Failures() != 0 {
		t.Fatalf("last success %v, failures %d", u.LastSuccess(), u.Failures())
	}

	// the same files again: nothing stored, nothing switched
	puts := objects.puts
	if v2, changed, err := u.Update(t.Context()); err != nil || changed || v2 != v || objects.puts != puts {
		t.Fatalf("unchanged update: %q %v %v, %d puts", v2, changed, err, objects.puts-puts)
	}

	// another replica starts: the stored version, without downloading
	hits := s.hits.Load()
	other := NewGeoIPEnricher(nil)
	u2 := &GeoIPUpdater{CityURL: u.CityURL, ASNURL: u.ASNURL, Objects: objects, Enricher: other}
	got, err := u2.LoadLatest(t.Context())
	if err != nil || got == nil || got.Version != v || other.Version() != v || s.hits.Load() != hits {
		t.Fatalf("load latest: %+v %v (active %q, %d downloads)", got, err, other.Version(), s.hits.Load()-hits)
	}
	if loc, _ := other.Resolve("1.0.0.1"); loc == nil || loc.ASN != 15169 {
		t.Fatalf("stored ASN database: %+v", loc)
	}

	// a tampered stored database is refused, the active one kept
	objects.m["geoip/"+v+"/asn.mmdb"][100] ^= 1
	third := NewGeoIPEnricher(nil)
	u3 := &GeoIPUpdater{Objects: objects, Enricher: third}
	if _, err := u3.LoadLatest(t.Context()); err == nil || third.Version() != "" || u3.Failures() != 1 {
		t.Fatalf("tampered database accepted: %v, active %q", err, third.Version())
	}
	// nothing stored yet: no error, nothing loaded
	if m, err := (&GeoIPUpdater{Objects: &memObjects{}, Enricher: third}).LoadLatest(t.Context()); m != nil || err != nil {
		t.Fatalf("empty store: %+v %v", m, err)
	}
}

func TestGeoIPUpdateFailuresKeepTheActiveVersion(t *testing.T) {
	s := newGeoServer(t)
	enricher := NewGeoIPEnricher(nil)
	good := &GeoIPUpdater{CityURL: s.URL + "/city.tar.gz", ASNURL: s.URL + "/asn.mmdb", Objects: &memObjects{}, Enricher: enricher}
	v, _, err := good.Update(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		city, asn string
		failPut   bool
		want      string
	}{
		"HTTP error":       {city: "/error", want: "HTTP 500"},
		"not a database":   {city: "/corrupt", want: "city database"},
		"wrong type":       {city: "/asn.mmdb", want: "unsupported type"},
		"two databases":    {city: "/two.tar.gz", want: "more than one"},
		"no database":      {city: "/none.tar.gz", want: "no .mmdb"},
		"redirect to file": {city: "/to-file", want: "redirect refused"},
		"corrupt ASN":      {city: "/city.tar.gz", asn: "/corrupt", want: "asn database"},
		"store down":       {city: "/city.tar.gz", failPut: true, want: "object store down"},
	} {
		t.Run(name, func(t *testing.T) {
			u := &GeoIPUpdater{CityURL: s.URL + tc.city + "?" + exampleKey, Objects: &memObjects{failPut: tc.failPut}, Enricher: enricher}
			if tc.asn != "" {
				u.ASNURL = s.URL + tc.asn + "?" + exampleKey
			}
			if name == "store down" {
				enricher.SetReader(nil) // so the download differs from the active version
				defer func() {
					if _, _, err := good.Update(t.Context()); err != nil {
						t.Fatal(err)
					}
				}()
			}
			before := enricher.Version()
			got, changed, err := u.Update(t.Context())
			if err == nil || changed || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %q %v %v, want error with %q", got, changed, err, tc.want)
			}
			if strings.Contains(err.Error(), "example-secret-key") {
				t.Fatalf("license key in the error: %v", err)
			}
			if enricher.Version() != before || u.Failures() != 1 || !u.LastSuccess().IsZero() {
				t.Fatalf("active version changed to %q (failures %d)", enricher.Version(), u.Failures())
			}
		})
	}
	if enricher.Version() != v {
		t.Fatalf("active version %q, want %q", enricher.Version(), v)
	}
	// a URL that is not http(s) is never fetched
	u := &GeoIPUpdater{CityURL: "file:///etc/passwd", Objects: &memObjects{}, Enricher: enricher}
	if _, _, err := u.Update(t.Context()); err == nil || !strings.Contains(err.Error(), "only http(s)") {
		t.Fatalf("file URL: %v", err)
	}
	// unreachable host: the error names the host, not the key
	u = &GeoIPUpdater{CityURL: "http://127.0.0.1:1/c.mmdb?" + exampleKey, Objects: &memObjects{}, Enricher: enricher,
		Client: &http.Client{Timeout: 2 * time.Second}}
	if _, _, err := u.Update(t.Context()); err == nil || strings.Contains(err.Error(), "example-secret-key") {
		t.Fatalf("unreachable: %v", err)
	}
}

func TestExtractMMDBBounds(t *testing.T) {
	// a gzip bomb: past the limit (lowered here) in a few KiB
	defer func(l int) { geoIPUnzipLimit = l }(geoIPUnzipLimit)
	geoIPUnzipLimit = 4 << 20
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zero := make([]byte, 1<<20)
	for range 5 {
		if _, err := zw.Write(zero); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := ExtractMMDB(buf.Bytes()); err == nil || !strings.Contains(err.Error(), "above the limit") {
		t.Fatalf("decompressed past the limit: %v", err)
	}
	if b, err := ExtractMMDB([]byte("plain")); err != nil || string(b) != "plain" {
		t.Fatalf("plain bytes: %q %v", b, err)
	}
	for in, want := range map[string]string{
		"https://download.example.test/app/geoip_download?edition_id=GeoLite2-City&" + exampleKey + "&suffix=tar.gz": "https://download.example.test/app/geoip_download",
		"https://user:pass@geo.example.test/c.mmdb#x":                                                                "https://geo.example.test/c.mmdb",
	} {
		if got := RedactURL(in); got != want {
			t.Errorf("RedactURL(%q) = %q", in, got)
		}
	}
}

// Run: nothing stored, so it downloads at once.
func TestGeoIPUpdateRunDownloadsWhenNothingIsStored(t *testing.T) {
	s := newGeoServer(t)
	enricher := NewGeoIPEnricher(nil)
	u := &GeoIPUpdater{CityURL: s.URL + "/city.tar.gz", Objects: &memObjects{}, Enricher: enricher}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { u.Run(ctx, time.Hour); close(done) }()
	deadline := time.Now().Add(10 * time.Second)
	for enricher.Version() == "" && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	if enricher.Version() == "" || u.LastSuccess().IsZero() {
		t.Fatal("Run did not update")
	}
	if loc, _ := enricher.Resolve(net.ParseIP("81.2.69.142").String()); loc == nil || loc.City != "London" {
		t.Fatalf("lookup after Run: %+v", loc)
	}
}
