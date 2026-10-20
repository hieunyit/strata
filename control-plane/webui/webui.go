// Package webui serves the Web UI from the control plane binary (CP-A08):
// the files of ui/dist are embedded at build time (make control-plane-ui
// copies them into dist/), so the API and the UI share one origin and no
// separate web server or proxy is needed.
package webui

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

// dist holds the built UI; a binary built without it has only .gitkeep.
//
//go:embed all:dist
var dist embed.FS

// Embedded returns the UI built into this binary, or nil when it was built
// without one (then the control plane serves only the API).
func Embedded() fs.FS {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		return nil
	}
	if _, err := fs.Stat(sub, "index.html"); err != nil {
		return nil
	}
	return sub
}

// Version identifies a UI build: the start of the SHA-256 of its
// index.html, which names every hashed asset. "" without a UI.
func Version(assets fs.FS) string {
	if assets == nil {
		return ""
	}
	b, err := fs.ReadFile(assets, "index.html")
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:6])
}

// Config is what the UI needs at run time, served as /config.json.
type Config struct {
	// OIDCAuthority and OIDCClientID: sign-in with an identity provider;
	// empty without OIDC (then /config.json carries neither).
	OIDCAuthority string
	OIDCClientID  string
}

// isAPI: paths the UI never answers, so that a mistyped API path is a
// JSON 404, not index.html with 200.
func isAPI(p string) bool {
	return p == "/v1" || strings.HasPrefix(p, "/v1/") || p == "/healthz" || p == "/readyz"
}

// csp allows scripts only from the control plane (no inline script), the
// identity provider for sign-in, and no framing.
func csp(cfg Config) string {
	idp := ""
	if u, err := url.Parse(cfg.OIDCAuthority); err == nil && cfg.OIDCAuthority != "" && u.Scheme != "" && u.Host != "" {
		idp = " " + u.Scheme + "://" + u.Host
	}
	return "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; " +
		"connect-src 'self'" + idp + "; frame-src 'self'" + idp + "; form-action 'self'" + idp + "; " +
		"frame-ancestors 'none'; base-uri 'self'; object-src 'none'"
}

// Handler answers the API paths with api and everything else with the UI:
// files of assets (hashed files under assets/ cached for a year, the rest
// revalidated), /config.json, and index.html for the UI's own routes.
// Security headers go on every response. assets nil: only api.
func Handler(api http.Handler, assets fs.FS, cfg Config) http.Handler {
	policy := csp(cfg)
	conf, _ := json.Marshal(struct {
		OIDCAuthority string `json:"oidcAuthority,omitempty"`
		OIDCClientID  string `json:"oidcClientId,omitempty"`
	}{cfg.OIDCAuthority, cfg.OIDCClientID})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", policy)
		if assets == nil || isAPI(r.URL.Path) {
			api.ServeHTTP(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			h.Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
		if name == "config.json" {
			h.Set("Content-Type", "application/json")
			h.Set("Cache-Control", "no-store")
			_, _ = w.Write(conf)
			return
		}
		if name != "" && serveFile(w, r, assets, name) {
			return
		}
		if strings.HasPrefix(name, "assets/") {
			// a chunk of another build: a 404, never HTML in place of a script
			http.NotFound(w, r)
			return
		}
		h.Set("Cache-Control", "no-cache")
		serveFile(w, r, assets, "index.html")
	})
}

// serveFile serves name when it is a regular file of assets.
func serveFile(w http.ResponseWriter, r *http.Request, assets fs.FS, name string) bool {
	f, err := assets.Open(name)
	if err != nil {
		return false
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return false
	}
	rs, ok := f.(io.ReadSeeker)
	if !ok {
		return false
	}
	if w.Header().Get("Cache-Control") == "" {
		if strings.HasPrefix(name, "assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
	}
	http.ServeContent(w, r, name, time.Time{}, rs)
	return true
}
