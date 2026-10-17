package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/strata/strata/control-plane/ingest"
)

// GeoWatchUpdate is emitted over SSE periodically to push live geographic changes.
type GeoWatchUpdate struct {
	Timestamp time.Time               `json:"timestamp"`
	Countries []ingest.GeoCountryStat `json:"countries,omitempty"`
	ASNs      []ingest.GeoASNStat     `json:"asns,omitempty"`
}

// HandleWatchGeo handles GET /v1/stats/geo:watch via Server-Sent Events (SSE).
func (h *EventHandler) HandleWatchGeo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed", "")
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming unsupported by client connection", "")
		return
	}

	geoStore, ok := h.store.(ingest.GeoStatsStore)
	if !ok {
		writeError(w, http.StatusNotImplemented, "geo statistics not supported by this event store", "")
		return
	}

	// Disable HTTP write deadlines for streaming connection
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{})

	// Set required SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache, no-transform")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	// Determine poll interval (default 3s, minimum 1s, maximum 10s)
	interval := 3 * time.Second
	if v := r.URL.Query().Get("interval"); v != "" {
		if sec, err := strconv.Atoi(v); err == nil && sec >= 1 && sec <= 10 {
			interval = time.Duration(sec) * time.Second
		}
	}

	// 1. Send initial snapshot of the past 24 hours
	now := time.Now().UTC()
	initFilter := ingest.GeoStatsFilter{
		From:    now.Add(-24 * time.Hour),
		To:      now,
		GroupBy: "all",
		Limit:   50,
	}
	initSnap, err := geoStore.GeoStats(r.Context(), initFilter)
	if err == nil && initSnap != nil {
		if data, err := json.Marshal(initSnap); err == nil {
			fmt.Fprintf(w, "event: geo_snapshot\ndata: %s\n\n", data)
			flusher.Flush()
		}
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// 2. Stream periodic deltas
	for {
		select {
		case <-r.Context().Done():
			return
		case t := <-ticker.C:
			utcNow := t.UTC()
			deltaFilter := ingest.GeoStatsFilter{
				From:    utcNow.Add(-2 * interval),
				To:      utcNow,
				GroupBy: "all",
				Limit:   20,
			}
			res, err := geoStore.GeoStats(r.Context(), deltaFilter)
			if err != nil {
				continue
			}

			update := GeoWatchUpdate{
				Timestamp: utcNow,
				Countries: res.Countries,
				ASNs:      res.ASNs,
			}

			data, err := json.Marshal(update)
			if err != nil {
				continue
			}

			if _, err := fmt.Fprintf(w, "event: geo_update\ndata: %s\n\n", data); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}
