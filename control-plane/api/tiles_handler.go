package api

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// MapStyle defines the MapLibre style JSON pointing to the self-hosted PMTiles / vector tile server.
func MapStyle(tileURL string) map[string]any {
	return map[string]any{
		"version": 8,
		"name":    "Strata Dark Basemap (Air-Gapped)",
		"sources": map[string]any{
			"strata-tiles": map[string]any{
				"type":  "vector",
				"tiles": []string{tileURL},
				"minzoom": 0,
				"maxzoom": 8,
			},
		},
		"layers": []map[string]any{
			{
				"id":   "background",
				"type": "background",
				"paint": map[string]any{
					"background-color": "#0B0F19",
				},
			},
			{
				"id":     "water",
				"type":   "fill",
				"source": "strata-tiles",
				"source-layer": "water",
				"paint": map[string]any{
					"fill-color": "#0F172A",
				},
			},
			{
				"id":     "land",
				"type":   "fill",
				"source": "strata-tiles",
				"source-layer": "land",
				"paint": map[string]any{
					"fill-color": "#1E293B",
				},
			},
			{
				"id":     "boundaries",
				"type":   "line",
				"source": "strata-tiles",
				"source-layer": "boundaries",
				"paint": map[string]any{
					"line-color": "#334155",
					"line-width": 1,
				},
			},
		},
	}
}

// RegisterMapTileRoutes registers offline vector tile and style endpoints.
func RegisterMapTileRoutes(mux *http.ServeMux, tilePath string) {
	mux.HandleFunc("/v1/maps/style.json", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		scheme := "http"
		if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
			scheme = "https"
		}
		host := r.Host
		tileURL := scheme + "://" + host + "/v1/maps/tiles/{z}/{x}/{y}.pbf"
		_ = json.NewEncoder(w).Encode(MapStyle(tileURL))
	})

	mux.HandleFunc("/v1/maps/tiles/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Cache-Control", "public, max-age=86400, immutable")

		path := strings.TrimPrefix(r.URL.Path, "/v1/maps/tiles/")
		if strings.Contains(path, "..") {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		parts := strings.Split(path, "/")
		if len(parts) < 3 {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		// If a physical vector tile directory exists, safely serve from it
		if tilePath != "" {
			cleanTilePath := filepath.Clean(tilePath)
			targetFile := filepath.Clean(filepath.Join(cleanTilePath, path))
			if !strings.HasPrefix(targetFile, cleanTilePath+string(filepath.Separator)) {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if fi, err := os.Stat(targetFile); err == nil && !fi.IsDir() {
				w.Header().Set("Content-Type", "application/x-protobuf")
				w.Header().Set("Content-Encoding", "gzip")
				http.ServeFile(w, r, targetFile)
				return
			}
		}

		// Fallback empty vector tile response for test environments
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte{0x1a, 0x00}) // minimal empty MVT protobuf
	})
}
