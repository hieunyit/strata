package api

import (
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/strata/strata/control-plane/auth"
	"github.com/strata/strata/control-plane/ingest"
	"github.com/strata/strata/control-plane/rulecat"
)

// OverviewResponse is the Overview page's data (W10-F-01).
type OverviewResponse struct {
	ingest.Overview
	// Rules: catalog metadata of the top rules, keyed by Rule ID.
	Rules map[string]rulecat.Rule `json:"rules,omitempty"`
}

// HandleOverview handles GET /v1/stats/overview?from=&to=&policy_id=&step=.
// from and to are RFC 3339 (default: the last 24 hours), step is 1h, 6h or
// 24h (default from the window). Top clients are left out for callers
// that may not see full client IPs.
func (h *EventHandler) HandleOverview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed", "")
		return
	}
	stats, ok := h.store.(ingest.StatsStore)
	if !ok {
		writeError(w, http.StatusNotImplemented, "statistics are not available with this event store", "")
		return
	}
	q := r.URL.Query()
	to := time.Now().UTC()
	from := to.Add(-24 * time.Hour)
	var err error
	if v := q.Get("to"); v != "" {
		if to, err = time.Parse(time.RFC3339, v); err != nil {
			writeError(w, http.StatusBadRequest, "to: "+err.Error(), "")
			return
		}
		if q.Get("from") == "" {
			from = to.Add(-24 * time.Hour)
		}
	}
	if v := q.Get("from"); v != "" {
		if from, err = time.Parse(time.RFC3339, v); err != nil {
			writeError(w, http.StatusBadRequest, "from: "+err.Error(), "")
			return
		}
	}
	f := ingest.OverviewFilter{
		From: from, To: to, PolicyID: q.Get("policy_id"),
		Clients: auth.FromContext(r.Context()).Can(auth.PermEventsReadSensitive),
	}
	if v := q.Get("step"); v != "" {
		if f.Step, err = time.ParseDuration(v); err != nil || !ingest.ValidStep(f.Step) {
			writeError(w, http.StatusBadRequest, "step must be 1h, 6h or 24h", "")
			return
		}
	}
	if err := f.Normalize(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), "")
		return
	}
	o, err := stats.Overview(r.Context(), f)
	if err != nil {
		if errors.Is(err, r.Context().Err()) && r.Context().Err() != nil {
			writeError(w, http.StatusGatewayTimeout, "statistics query timed out", "")
			return
		}
		log.Printf("[ERROR] overview statistics: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error", "")
		return
	}
	ids := make([]uint32, 0, len(o.TopRules))
	for _, rc := range o.TopRules {
		ids = append(ids, rc.RuleID)
	}
	writeJSON(w, http.StatusOK, OverviewResponse{Overview: *o, Rules: h.rules.For(ids)})
}

// HandleGeoStats handles GET /v1/stats/geo?from=&to=&groupBy=country|city|asn&policy_id=&action=&limit=.
func (h *EventHandler) HandleGeoStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed", "")
		return
	}
	geoStore, ok := h.store.(ingest.GeoStatsStore)
	if !ok {
		writeError(w, http.StatusNotImplemented, "geo statistics are not available with this event store", "")
		return
	}
	q := r.URL.Query()
	to := time.Now().UTC()
	from := to.Add(-24 * time.Hour)
	var err error
	if v := q.Get("to"); v != "" {
		if to, err = time.Parse(time.RFC3339, v); err != nil {
			writeError(w, http.StatusBadRequest, "to: "+err.Error(), "")
			return
		}
		if q.Get("from") == "" {
			from = to.Add(-24 * time.Hour)
		}
	}
	if v := q.Get("from"); v != "" {
		if from, err = time.Parse(time.RFC3339, v); err != nil {
			writeError(w, http.StatusBadRequest, "from: "+err.Error(), "")
			return
		}
	}

	filter := ingest.GeoStatsFilter{
		From:     from,
		To:       to,
		GroupBy:  q.Get("groupBy"),
		PolicyID: q.Get("policy_id"),
		Action:   q.Get("action"),
	}

	res, err := geoStore.GeoStats(r.Context(), filter)
	if err != nil {
		if errors.Is(err, r.Context().Err()) && r.Context().Err() != nil {
			writeError(w, http.StatusGatewayTimeout, "geo statistics query timed out", "")
			return
		}
		log.Printf("[ERROR] geo statistics: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error", "")
		return
	}

	writeJSON(w, http.StatusOK, res)
}

