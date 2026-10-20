package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

var site = fstest.MapFS{
	"index.html":              {Data: []byte(`<!doctype html><script type="module" src="/assets/index-abc123.js"></script>`)},
	"assets/index-abc123.js":  {Data: []byte("console.log(1)")},
	"assets/index-abc123.css": {Data: []byte("body{}")},
	"favicon.svg":             {Data: []byte("<svg/>")},
	"assets/fonts/plex.woff2": {Data: []byte("font")},
}

var apiHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.URL.Path == "/v1/known" {
		_, _ = w.Write([]byte(`{"ok":true}`))
		return
	}
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte(`{"error":"not found"}`))
})

func get(t *testing.T, h http.Handler, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec
}

func TestRoutesAndCaching(t *testing.T) {
	h := Handler(apiHandler, site, Config{})
	for _, tc := range []struct {
		method, path string
		code         int
		body, cache  string
	}{
		// the API is never answered with index.html, even a wrong path
		{"GET", "/v1/known", 200, `{"ok":true}`, ""},
		{"GET", "/v1/no-such-route", 404, `{"error":"not found"}`, ""},
		{"GET", "/v1", 404, `{"error":"not found"}`, ""},
		{"POST", "/v1/known", 200, `{"ok":true}`, ""},
		{"GET", "/healthz", 404, `{"error":"not found"}`, ""},
		{"GET", "/readyz", 404, `{"error":"not found"}`, ""},
		// hashed assets for a year, everything else revalidated
		{"GET", "/assets/index-abc123.js", 200, "console.log(1)", "public, max-age=31536000, immutable"},
		{"GET", "/favicon.svg", 200, "<svg/>", "no-cache"},
		{"GET", "/", 200, "<!doctype html>", "no-cache"},
		{"GET", "/index.html", 200, "<!doctype html>", "no-cache"},
		// the UI's routes
		{"GET", "/events/STR-0000-0000-0000-0001", 200, "<!doctype html>", "no-cache"},
		{"GET", "/policies/example.api", 200, "<!doctype html>", "no-cache"},
		{"HEAD", "/overview", 200, "", "no-cache"},
		// a chunk of another build is a 404, not HTML
		{"GET", "/assets/index-old999.js", 404, "", ""},
		{"GET", "/assets/fonts", 404, "", ""},
		// no escape from the files
		{"GET", "/../../etc/passwd", 200, "<!doctype html>", "no-cache"},
		{"POST", "/overview", 405, "", ""},
	} {
		rec := get(t, h, tc.method, tc.path)
		if rec.Code != tc.code || !strings.HasPrefix(rec.Body.String(), tc.body) || rec.Header().Get("Cache-Control") != tc.cache {
			t.Errorf("%s %s: %d %q cache %q", tc.method, tc.path, rec.Code, rec.Body.String(), rec.Header().Get("Cache-Control"))
		}
	}
}

func TestSecurityHeadersEverywhere(t *testing.T) {
	h := Handler(apiHandler, site, Config{OIDCAuthority: "https://idp.example.test/realms/strata", OIDCClientID: "strata-ui"})
	for _, p := range []string{"/", "/v1/known", "/assets/index-abc123.js", "/config.json"} {
		rec := get(t, h, "GET", p)
		hd := rec.Header()
		if hd.Get("X-Frame-Options") != "DENY" || hd.Get("X-Content-Type-Options") != "nosniff" || hd.Get("Referrer-Policy") != "no-referrer" {
			t.Errorf("%s: %v", p, hd)
		}
		c := hd.Get("Content-Security-Policy")
		if !strings.Contains(c, "script-src 'self';") || strings.Contains(c, "unsafe-eval") || !strings.Contains(c, "frame-ancestors 'none'") ||
			!strings.Contains(c, "connect-src 'self' https://idp.example.test;") {
			t.Errorf("%s: CSP %q", p, c)
		}
		if strings.Contains(strings.SplitN(strings.SplitN(c, "script-src", 2)[1], ";", 2)[0], "unsafe-inline") {
			t.Errorf("%s: inline scripts allowed", p)
		}
	}
	// without OIDC the CSP names no other origin
	c := get(t, Handler(apiHandler, site, Config{}), "GET", "/").Header().Get("Content-Security-Policy")
	if strings.Contains(c, "https://") || strings.Contains(c, "http://") {
		t.Fatalf("CSP without OIDC: %q", c)
	}
}

func TestConfigJSON(t *testing.T) {
	var body map[string]string
	rec := get(t, Handler(apiHandler, site, Config{OIDCAuthority: "https://idp.example.test/realms/strata", OIDCClientID: "strata-ui"}), "GET", "/config.json")
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body["oidcAuthority"] != "https://idp.example.test/realms/strata" ||
		body["oidcClientId"] != "strata-ui" || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("%s %v", rec.Body, err)
	}
	// local accounts only: no OIDC fields at all
	rec = get(t, Handler(apiHandler, site, Config{}), "GET", "/config.json")
	if strings.TrimSpace(rec.Body.String()) != "{}" {
		t.Fatalf("without OIDC: %s", rec.Body)
	}
}

func TestWithoutEmbeddedUI(t *testing.T) {
	h := Handler(apiHandler, nil, Config{})
	if rec := get(t, h, "GET", "/"); rec.Code != 404 || !strings.Contains(rec.Body.String(), "not found") {
		t.Fatalf("no UI: %d %s", rec.Code, rec.Body)
	}
	if Version(nil) != "" || len(Version(site)) != 12 {
		t.Fatal("version")
	}
}
