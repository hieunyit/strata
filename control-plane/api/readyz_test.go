package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/strata/strata/control-plane/ingest"
)

// CP-A03: GET /readyz needs no token, reports component states only, and is
// 503 when the control plane cannot serve.
func TestReadyz(t *testing.T) {
	for _, tc := range []struct {
		name  string
		ready func(context.Context) (map[string]string, bool)
		code  int
	}{
		{"not configured", nil, http.StatusOK},
		{"ready, events degraded", func(context.Context) (map[string]string, bool) {
			return map[string]string{"postgres": "ok", "lease": "held", "clickhouse": "degraded"}, true
		}, http.StatusOK},
		{"lease lost", func(context.Context) (map[string]string, bool) {
			return map[string]string{"postgres": "ok", "lease": "lost"}, false
		}, http.StatusServiceUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := NewServer(ServerConfig{Auth: tokenRoles{}, Ready: tc.ready}, ingest.NewMockEventStore())
			rec := httptest.NewRecorder()
			s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
			if rec.Code != tc.code {
				t.Fatalf("status %d, want %d: %s", rec.Code, tc.code, rec.Body)
			}
			var body struct {
				Ready      bool              `json:"ready"`
				Components map[string]string `json:"components"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Ready != (tc.code == http.StatusOK) {
				t.Fatalf("body %s: %v", rec.Body, err)
			}
			if strings.Contains(rec.Body.String(), "127.0.0.1") {
				t.Fatal("readyz leaks addresses")
			}
		})
	}
}
