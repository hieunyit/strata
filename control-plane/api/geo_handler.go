package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/strata/strata/control-plane/ingest"
)

// StatsService of the map (W18-G2-01, nginx-module.md › Bản đồ GeoIP › API):
// counts from the GeoIP aggregates, distinct events (approximate for large
// sets, see ingest/geoagg.go). They hold no IP address: events:read.

// MaxGeoRange bounds a window: the aggregates' default retention.
const MaxGeoRange = 400 * 24 * time.Hour

// GeoResponse is GET /v1/stats/geo.
type GeoResponse struct {
	From    time.Time         `json:"from"`
	To      time.Time         `json:"to"`
	GroupBy string            `json:"group_by"`
	Rows    []ingest.GeoCount `json:"rows"`
	// Approximate: counts are distinct events by HyperLogLog beyond
	// small sets (about 1% off).
	Approximate bool `json:"approximate"`
}

// TimelineResponse is GET /v1/stats/timeline.
type TimelineResponse struct {
	From        time.Time          `json:"from"`
	To          time.Time          `json:"to"`
	Step        string             `json:"step"`
	Buckets     []ingest.GeoBucket `json:"buckets"`
	Approximate bool               `json:"approximate"`
}

var geoActions = []string{"block", "shadow", "pass", "error"}

// geoFilter reads from, to (RFC 3339; default the last 24 hours) and the
// filters policy_id, action, attack_type, country, asn, limit.
func geoFilter(r *http.Request, now time.Time) (ingest.GeoFilter, error) {
	q := r.URL.Query()
	f := ingest.GeoFilter{To: now, PolicyID: q.Get("policy_id"), Action: q.Get("action"),
		AttackType: q.Get("attack_type"), CountryISO: q.Get("country")}
	var err error
	if v := q.Get("to"); v != "" {
		if f.To, err = time.Parse(time.RFC3339, v); err != nil {
			return f, errors.New("to: not RFC 3339")
		}
	}
	f.From = f.To.Add(-24 * time.Hour)
	if v := q.Get("from"); v != "" {
		if f.From, err = time.Parse(time.RFC3339, v); err != nil {
			return f, errors.New("from: not RFC 3339")
		}
	}
	f.From, f.To = f.From.UTC(), f.To.UTC()
	switch {
	case !f.From.Before(f.To):
		return f, errors.New("from must be before to")
	case f.To.Sub(f.From) > MaxGeoRange:
		return f, fmt.Errorf("the window is at most %d days", int(MaxGeoRange/(24*time.Hour)))
	case len(f.PolicyID) > 256:
		return f, errors.New("policy_id: too long")
	case f.Action != "" && !slices.Contains(geoActions, f.Action):
		return f, errors.New("action must be block, shadow, pass or error")
	case f.AttackType != "" && !slices.Contains(ingest.AttackTypes, f.AttackType):
		return f, errors.New("attack_type: unknown")
	case f.CountryISO != "" && f.CountryISO != "INTERNAL" && !isCountryCode(f.CountryISO):
		return f, errors.New("country: an ISO 3166 alpha-2 code or INTERNAL")
	}
	if v := q.Get("asn"); v != "" {
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil || n == 0 {
			return f, errors.New("asn: a positive 32-bit number")
		}
		f.ASN = uint32(n)
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 1000 {
			return f, errors.New("limit: 1 to 1000")
		}
		f.Limit = n
	}
	return f, nil
}

func isCountryCode(s string) bool {
	return len(s) == 2 && s[0] >= 'A' && s[0] <= 'Z' && s[1] >= 'A' && s[1] <= 'Z'
}

func (h *EventHandler) geoStore(w http.ResponseWriter) (ingest.GeoStatsStore, bool) {
	g, ok := h.store.(ingest.GeoStatsStore)
	if !ok {
		writeError(w, http.StatusNotImplemented, "GeoIP statistics are not available with this event store", "")
	}
	return g, ok
}

// geoRows runs the query of groupBy (country, city: geohash cells, asn).
func geoRows(ctx context.Context, g ingest.GeoStatsStore, groupBy string, f ingest.GeoFilter) ([]ingest.GeoCount, error) {
	switch groupBy {
	case "country":
		return g.GeoByCountry(ctx, f)
	case "asn":
		return g.GeoByASN(ctx, f)
	case "attack_type":
		return g.GeoByAttackType(ctx, f)
	default: // city: validated by the caller
		return g.GeoByCell(ctx, f)
	}
}

func geoGroupBy(r *http.Request) (string, error) {
	switch v := r.URL.Query().Get("groupBy"); v {
	case "":
		return "country", nil
	case "country", "city", "asn", "attack_type":
		return v, nil
	}
	return "", errors.New("groupBy must be country, city, asn or attack_type")
}

func (h *EventHandler) statsFailed(w http.ResponseWriter, r *http.Request, what string, err error) {
	if r.Context().Err() != nil && errors.Is(err, r.Context().Err()) {
		writeError(w, http.StatusGatewayTimeout, "statistics query timed out", "")
		return
	}
	log.Printf("[ERROR] %s statistics: %v", what, err)
	eventsUnavailable(w, "")
}

// HandleGeoStats handles GET /v1/stats/geo?from=&to=&groupBy=country|city|asn|attack_type
// and the filters of geoFilter. Rows are most events first; city rows are
// geohash cells (precision 4) at their center, never an IP's location.
func (h *EventHandler) HandleGeoStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed", "")
		return
	}
	g, ok := h.geoStore(w)
	if !ok {
		return
	}
	groupBy, err := geoGroupBy(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), "")
		return
	}
	f, err := geoFilter(r, time.Now().UTC())
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), "")
		return
	}
	rows, err := geoRows(r.Context(), g, groupBy, f)
	if err != nil {
		h.statsFailed(w, r, "GeoIP", err)
		return
	}
	if rows == nil {
		rows = []ingest.GeoCount{}
	}
	writeJSON(w, http.StatusOK, GeoResponse{From: f.From, To: f.To, GroupBy: groupBy, Rows: rows, Approximate: true})
}

// HandleTimeline handles GET /v1/stats/timeline?from=&to=&step= and the
// filters of geoFilter: distinct events per step by action. step is 1m,
// 5m, 1h, 6h or 24h (default from the window), at most
// ingest.MaxGeoBuckets buckets.
func (h *EventHandler) HandleTimeline(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed", "")
		return
	}
	g, ok := h.geoStore(w)
	if !ok {
		return
	}
	f, err := geoFilter(r, time.Now().UTC())
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), "")
		return
	}
	step := ingest.GeoStepFor(f.To.Sub(f.From))
	if v := r.URL.Query().Get("step"); v != "" {
		if step, err = time.ParseDuration(v); err != nil || !ingest.ValidGeoStep(step) {
			writeError(w, http.StatusBadRequest, "step must be 1m, 5m, 1h, 6h or 24h", "")
			return
		}
	}
	if n := f.To.Sub(f.From.Truncate(step)) / step; n >= ingest.MaxGeoBuckets {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("too many buckets: at most %d, use a larger step", ingest.MaxGeoBuckets), "")
		return
	}
	buckets, err := g.GeoTimeline(r.Context(), f, step)
	if err != nil {
		h.statsFailed(w, r, "timeline", err)
		return
	}
	writeJSON(w, http.StatusOK, TimelineResponse{From: f.From, To: f.To, Step: step.String(), Buckets: buckets, Approximate: true})
}

// Live map (GET /v1/stats/geo:watch): server-sent events.
const (
	// MaxGeoWatchers bounds the open streams of one control plane.
	MaxGeoWatchers = 32
	// MaxGeoWatchDuration ends a stream; the client reconnects (and is
	// authenticated again).
	MaxGeoWatchDuration = 15 * time.Minute
	geoWatchKeepalive   = 15 * time.Second
	geoWatchWriteWait   = 10 * time.Second
	geoWatchMaxWindow   = 7 * 24 * time.Hour
)

var geoWatchers = make(chan struct{}, MaxGeoWatchers)

// GeoSnapshot is the first event of a stream (event: snapshot).
type GeoSnapshot struct {
	At          time.Time         `json:"at"`
	From        time.Time         `json:"from"`
	To          time.Time         `json:"to"`
	GroupBy     string            `json:"group_by"`
	Rows        []ingest.GeoCount `json:"rows"`
	Approximate bool              `json:"approximate"`
}

// GeoDelta is a change of the rows (event: delta): rows added or changed,
// keys of rows gone (out of the window or of the top).
type GeoDelta struct {
	At      time.Time         `json:"at"`
	From    time.Time         `json:"from"`
	To      time.Time         `json:"to"`
	Changed []ingest.GeoCount `json:"changed,omitempty"`
	Removed []string          `json:"removed,omitempty"`
}

func geoDiff(prev map[string]ingest.GeoCount, rows []ingest.GeoCount) (map[string]ingest.GeoCount, []ingest.GeoCount, []string) {
	next := make(map[string]ingest.GeoCount, len(rows))
	var changed []ingest.GeoCount
	for _, row := range rows {
		next[row.Key] = row
		if old, ok := prev[row.Key]; !ok || old.Events != row.Events || old.Blocked != row.Blocked ||
			old.TopAttack != row.TopAttack || old.Label != row.Label {
			changed = append(changed, row)
		}
	}
	var removed []string
	for k := range prev {
		if _, ok := next[k]; !ok {
			removed = append(removed, k)
		}
	}
	slices.Sort(removed)
	return next, changed, removed
}

// HandleGeoWatch streams the rows of GET /v1/stats/geo over a sliding
// window (window=, default 1h, at most 7 days, ending now): event
// "snapshot" first, then "delta" with what changed, checked every
// interval (2s to 5s, default 3s), a comment every 15 s when nothing did.
// A stream lasts at most MaxGeoWatchDuration; at most MaxGeoWatchers
// streams at once (503 beyond). Credentials come in the Authorization
// header (EventSource cannot send one: read it with fetch).
func (h *EventHandler) HandleGeoWatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed", "")
		return
	}
	g, ok := h.geoStore(w)
	if !ok {
		return
	}
	groupBy, err := geoGroupBy(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), "")
		return
	}
	q := r.URL.Query()
	if q.Get("from") != "" || q.Get("to") != "" {
		writeError(w, http.StatusBadRequest, "a stream follows now: use window, not from/to", "")
		return
	}
	window, interval := time.Hour, 3*time.Second
	if v := q.Get("window"); v != "" {
		if window, err = time.ParseDuration(v); err != nil || window < time.Minute || window > geoWatchMaxWindow {
			writeError(w, http.StatusBadRequest, "window: 1m to 168h", "")
			return
		}
	}
	if v := q.Get("interval"); v != "" {
		if interval, err = time.ParseDuration(v); err != nil || interval < 2*time.Second || interval > 5*time.Second {
			writeError(w, http.StatusBadRequest, "interval: 2s to 5s", "")
			return
		}
	}
	f, err := geoFilter(r, time.Now().UTC())
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), "")
		return
	}
	select {
	case geoWatchers <- struct{}{}:
		defer func() { <-geoWatchers }()
	default:
		w.Header().Set("Retry-After", "30")
		writeError(w, http.StatusServiceUnavailable, "too many live map streams", "")
		return
	}

	// each write sets its own deadline: the server's WriteTimeout would end
	// the stream
	rc := http.NewResponseController(w)
	send := func(event string, v any) error {
		if err := rc.SetWriteDeadline(time.Now().Add(geoWatchWriteWait)); err != nil {
			return err
		}
		if event != "" {
			data, err := json.Marshal(v)
			if err != nil {
				return err
			}
			if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, data); err != nil {
				return err
			}
		} else if _, err := fmt.Fprint(w, ": keepalive\n\n"); err != nil {
			return err
		}
		return rc.Flush()
	}
	read := func(now time.Time) ([]ingest.GeoCount, ingest.GeoFilter, error) {
		f := f
		f.From, f.To = now.Add(-window), now.Add(time.Second)
		ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
		defer cancel()
		rows, err := geoRows(ctx, g, groupBy, f)
		return rows, f, err
	}

	now := time.Now().UTC()
	rows, cur, err := read(now)
	if err != nil {
		h.statsFailed(w, r, "GeoIP watch", err)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no") // NGINX in front: do not buffer
	w.WriteHeader(http.StatusOK)
	if _, err := fmt.Fprint(w, "retry: 3000\n\n"); err != nil {
		return
	}
	if rows == nil {
		rows = []ingest.GeoCount{}
	}
	if send("snapshot", GeoSnapshot{At: now, From: cur.From, To: cur.To, GroupBy: groupBy, Rows: rows, Approximate: true}) != nil {
		return
	}
	prev, _, _ := geoDiff(nil, rows)

	end := time.NewTimer(MaxGeoWatchDuration)
	defer end.Stop()
	tick := time.NewTicker(interval)
	defer tick.Stop()
	quiet := time.Now()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-end.C:
			return
		case t := <-tick.C:
			rows, cur, err := read(t.UTC())
			if err != nil {
				if r.Context().Err() != nil {
					return
				}
				log.Printf("[WARN] GeoIP watch: %v", err)
				continue // the next tick tries again; the keepalive below keeps the stream
			}
			var changed []ingest.GeoCount
			var removed []string
			prev, changed, removed = geoDiff(prev, rows)
			if len(changed) > 0 || len(removed) > 0 {
				if send("delta", GeoDelta{At: t.UTC(), From: cur.From, To: cur.To, Changed: changed, Removed: removed}) != nil {
					return
				}
				quiet = time.Now()
			} else if time.Since(quiet) >= geoWatchKeepalive {
				if send("", nil) != nil {
					return
				}
				quiet = time.Now()
			}
		}
	}
}
