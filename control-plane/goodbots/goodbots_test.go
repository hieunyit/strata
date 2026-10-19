package goodbots

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

var errMissing = errors.New("missing")

type memObjects struct {
	mu      sync.Mutex
	m       map[string][]byte
	puts    int
	failGet bool
}

func (o *memObjects) Put(_ context.Context, key string, data []byte, _ string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
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
	if o.failGet {
		return nil, errors.New("store down")
	}
	b, ok := o.m[key]
	if !ok {
		return nil, errMissing
	}
	return append([]byte(nil), b...), nil
}

func isMissing(err error) bool { return errors.Is(err, errMissing) }

const google = `{"creationTime": "2026-10-18T14:46:30.000000", "prefixes": [
 {"ipv6Prefix": "2001:4860:4801:10::/64"}, {"ipv4Prefix": "66.249.64.0/27"}, {"ipv4Prefix": "66.249.64.0/27"}]}`
const bing = `{"creationTime": "2026-10-18T00:00:00", "prefixes": [{"ipv4Prefix": "157.55.39.0/24"}]}`

// feeds serves the lists; a handler may be swapped between updates.
func feeds(t *testing.T, routes map[string]string) (*httptest.Server, *sync.Map) {
	t.Helper()
	var m sync.Map
	for k, v := range routes {
		m.Store(k, v)
	}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v, ok := m.Load(r.URL.Path)
		if !ok {
			http.NotFound(w, r)
			return
		}
		if v.(string) == "500" {
			http.Error(w, "down", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(v.(string)))
	}))
	t.Cleanup(s.Close)
	return s, &m
}

func TestParseFeed(t *testing.T) {
	got, created, err := ParseFeed([]byte(google))
	if err != nil || strings.Join(got, ",") != "2001:4860:4801:10::/64,66.249.64.0/27" || created != "2026-10-18T14:46:30.000000" {
		t.Fatalf("%v %q %v", got, created, err)
	}
	for name, bad := range map[string]string{
		"not json":      `<html>`,
		"empty":         `{"prefixes": []}`,
		"host bits":     `{"prefixes": [{"ipv4Prefix": "66.249.64.1/27"}]}`,
		"too broad v4":  `{"prefixes": [{"ipv4Prefix": "0.0.0.0/0"}]}`,
		"too broad v6":  `{"prefixes": [{"ipv6Prefix": "2000::/3"}]}`,
		"family swap":   `{"prefixes": [{"ipv4Prefix": "2001:db8::/32"}]}`,
		"both":          `{"prefixes": [{"ipv4Prefix": "192.0.2.0/24", "ipv6Prefix": "2001:db8::/32"}]}`,
		"neither":       `{"prefixes": [{}]}`,
		"not a prefix":  `{"prefixes": [{"ipv4Prefix": "192.0.2.0"}]}`,
		"zone":          `{"prefixes": [{"ipv6Prefix": "fe80::%eth0/64"}]}`,
		"one bad entry": `{"prefixes": [{"ipv4Prefix": "192.0.2.0/24"}, {"ipv4Prefix": "1.0.0.0/4"}]}`,
	} {
		if _, _, err := ParseFeed([]byte(bad)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestUpdateStoresVersionsAndKeepsRangesOfAFailedFeed(t *testing.T) {
	srv, routes := feeds(t, map[string]string{"/google.json": google, "/bing.json": bing})
	objects := &memObjects{}
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	u := &Updater{Objects: objects, IsNotFound: isMissing, Now: func() time.Time { return now },
		Feeds: []Feed{{"googlebot", srv.URL + "/google.json?key=example-secret"}, {"bingbot", srv.URL + "/bing.json"}}}

	v1, changed, err := u.Update(t.Context())
	if err != nil || !changed || len(v1) != 64 {
		t.Fatalf("first: %q %v %v", v1, changed, err)
	}
	l, err := Latest(t.Context(), objects, isMissing)
	if err != nil || l.Version != v1 || len(l.Crawlers["googlebot"]) != 2 || l.Sources["googlebot"].Prefixes != 2 ||
		l.Sources["googlebot"].URL != srv.URL+"/google.json" || !u.LastSuccess().Equal(now) {
		t.Fatalf("latest: %+v %v", l, err)
	}
	if _, ok := objects.m["goodbots/"+v1+".json"]; !ok {
		t.Fatal("version not stored")
	}
	for k, b := range objects.m {
		if strings.Contains(string(b), "example-secret") {
			t.Fatalf("query of a feed URL stored in %s", k)
		}
	}

	// the same lists: nothing stored
	puts := objects.puts
	if v, changed, err := u.Update(t.Context()); err != nil || changed || v != v1 || objects.puts != puts {
		t.Fatalf("unchanged: %q %v %v (%d puts)", v, changed, err, objects.puts-puts)
	}

	// Bing down, Google changed: Google updated, Bing keeps its ranges
	routes.Store("/bing.json", "500")
	routes.Store("/google.json", `{"prefixes": [{"ipv4Prefix": "66.249.64.0/27"}, {"ipv4Prefix": "66.249.65.0/27"}]}`)
	later := now.Add(24 * time.Hour)
	u.Now = func() time.Time { return later }
	v2, changed, err := u.Update(t.Context())
	if err == nil || !strings.Contains(err.Error(), "HTTP 500") || !changed || v2 == v1 || strings.Contains(err.Error(), "example-secret") {
		t.Fatalf("partial: %q %v %v", v2, changed, err)
	}
	l, _ = Latest(t.Context(), objects, isMissing)
	if strings.Join(l.Crawlers["googlebot"], ",") != "66.249.64.0/27,66.249.65.0/27" ||
		strings.Join(l.Crawlers["bingbot"], ",") != "157.55.39.0/24" || !l.Sources["bingbot"].FetchedAt.Equal(now) {
		t.Fatalf("after a failed feed: %+v", l)
	}
	if !u.LastSuccess().Equal(now) || u.Failures() != 1 {
		t.Fatalf("a partial update is not a success: %v %d", u.LastSuccess(), u.Failures())
	}

	// a poisoned feed is refused whole, the previous ranges stay
	routes.Store("/bing.json", bing)
	routes.Store("/google.json", `{"prefixes": [{"ipv4Prefix": "66.249.64.0/27"}, {"ipv4Prefix": "0.0.0.0/1"}]}`)
	if _, _, err := u.Update(t.Context()); err == nil || !strings.Contains(err.Error(), "too broad") {
		t.Fatalf("poisoned feed: %v", err)
	}
	l, _ = Latest(t.Context(), objects, isMissing)
	if len(l.Crawlers["googlebot"]) != 2 {
		t.Fatalf("poisoned feed changed the ranges: %+v", l.Crawlers)
	}
}

func TestUpdateWithoutAnyGoodFeedStoresNothing(t *testing.T) {
	srv, _ := feeds(t, map[string]string{"/google.json": "500"})
	objects := &memObjects{}
	u := &Updater{Objects: objects, IsNotFound: isMissing, Feeds: []Feed{{"googlebot", srv.URL + "/google.json"}}}
	if v, _, err := u.Update(t.Context()); err == nil || v != "" || objects.puts != 0 {
		t.Fatalf("%q %v, %d puts", v, err, objects.puts)
	}
	for _, f := range []string{"file:///etc/passwd", "ftp://example.test/x"} {
		u.Feeds = []Feed{{"googlebot", f}}
		if _, _, err := u.Update(t.Context()); err == nil || !strings.Contains(err.Error(), "only http(s)") {
			t.Fatalf("%s: %v", f, err)
		}
	}
}

func TestForCompiler(t *testing.T) {
	objects := &memObjects{}
	get := ForCompiler(objects, isMissing)
	if b, err := get(t.Context()); b != nil || err != nil {
		t.Fatalf("nothing stored: %s %v", b, err)
	}
	srv, _ := feeds(t, map[string]string{"/google.json": google})
	u := &Updater{Objects: objects, IsNotFound: isMissing, Feeds: []Feed{{"googlebot", srv.URL + "/google.json"}}}
	if _, _, err := u.Update(t.Context()); err != nil {
		t.Fatal(err)
	}
	b, err := get(t.Context())
	var doc struct {
		Version  string              `json:"version"`
		Crawlers map[string][]string `json:"crawlers"`
	}
	if err != nil || json.Unmarshal(b, &doc) != nil || len(doc.Crawlers["googlebot"]) != 2 || len(doc.Version) != 64 {
		t.Fatalf("%s %v", b, err)
	}
	// a damaged latest.json or a failing store fails the build
	objects.m[LatestKey] = []byte(`{"version": "x", "crawlers": {"googlebot": ["66.249.64.0/27"]}}`)
	if _, err := get(t.Context()); err == nil {
		t.Fatal("damaged list accepted")
	}
	objects.failGet = true
	if _, err := get(t.Context()); err == nil {
		t.Fatal("store failure hidden")
	}
}

// The published lists themselves (STRATA_TEST_REAL_FEEDS=1: needs the
// Internet), through the default feeds.
func TestRealFeeds(t *testing.T) {
	if os.Getenv("STRATA_TEST_REAL_FEEDS") != "1" {
		t.Skip("STRATA_TEST_REAL_FEEDS not set")
	}
	objects := &memObjects{}
	u := &Updater{Objects: objects, IsNotFound: isMissing}
	v, changed, err := u.Update(t.Context())
	if err != nil || !changed || v == "" {
		t.Fatalf("%q %v %v", v, changed, err)
	}
	l, _ := Latest(t.Context(), objects, isMissing)
	for _, f := range DefaultFeeds {
		t.Logf("%s: %d prefixes, list created %s", f.Name, len(l.Crawlers[f.Name]), l.Sources[f.Name].CreationTime)
		if len(l.Crawlers[f.Name]) == 0 {
			t.Errorf("%s: no prefix", f.Name)
		}
	}
}
