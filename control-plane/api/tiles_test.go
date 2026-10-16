package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/strata/strata/control-plane/ingest"
)

func TestMapTileRoutes(t *testing.T) {
	store := ingest.NewMockEventStore()
	server := NewServer(ServerConfig{
		Auth: tokenRoles{},
	}, store)
	handler := server.Handler()

	// 1. GET /v1/maps/style.json
	req := httptest.NewRequest(http.MethodGet, "/v1/maps/style.json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("style.json returned %d, want 200", rec.Code)
	}

	var style map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&style); err != nil {
		t.Fatalf("decoding style json: %v", err)
	}
	if style["version"] != float64(8) {
		t.Errorf("expected style version 8, got %v", style["version"])
	}
	layers, ok := style["layers"].([]any)
	if !ok || len(layers) == 0 {
		t.Errorf("expected non-empty layers array in style")
	}

	// 2. GET /v1/maps/tiles/0/0/0.pbf (fallback tile)
	req = httptest.NewRequest(http.MethodGet, "/v1/maps/tiles/0/0/0.pbf", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("tiles 0/0/0.pbf returned %d, want 200", rec.Code)
	}
	if rec.Header().Get("Content-Type") != "application/x-protobuf" {
		t.Errorf("expected Content-Type application/x-protobuf, got %q", rec.Header().Get("Content-Type"))
	}

	// 3. GET /v1/maps/tiles/bad (invalid path)
	req = httptest.NewRequest(http.MethodGet, "/v1/maps/tiles/invalid", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("invalid tile path returned %d, want 404", rec.Code)
	}

	// 4. GET /v1/maps/tiles/../etc/passwd (path traversal attempt rejected by ServeMux or handler)
	req = httptest.NewRequest(http.MethodGet, "/v1/maps/tiles/../../../etc/passwd", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code == http.StatusOK {
		t.Errorf("path traversal attempt must not return 200 OK, got %d", rec.Code)
	}

	// 5. POST /v1/maps/style.json (method not allowed)
	req = httptest.NewRequest(http.MethodPost, "/v1/maps/style.json", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST style.json returned %d, want 405", rec.Code)
	}
}
