package api

import (
	"errors"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/strata/strata/control-plane/ingest"
)

// HandleTimelineStats handles GET /v1/stats/timeline?from=&to=&step=&policy_id=&country_iso=&asn=&action=.
func (h *EventHandler) HandleTimelineStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed", "")
		return
	}
	timelineStore, ok := h.store.(ingest.TimelineStore)
	if !ok {
		writeError(w, http.StatusNotImplemented, "timeline statistics are not available with this event store", "")
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

	if from.After(to) {
		writeError(w, http.StatusBadRequest, "'from' timestamp must be before or equal to 'to' timestamp", "")
		return
	}

	var step time.Duration
	if v := q.Get("step"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || !ingest.ValidTimelineStep(d) {
			writeError(w, http.StatusBadRequest, "invalid step: must be 1m, 5m, 1h, 6h or 24h", "")
			return
		}
		step = d
	}

	var asn uint32
	if v := q.Get("asn"); v != "" {
		if a, err := strconv.ParseUint(v, 10, 32); err == nil {
			asn = uint32(a)
		}
	}

	filter := ingest.TimelineFilter{
		From:       from,
		To:         to,
		Step:       step,
		PolicyID:   q.Get("policy_id"),
		CountryISO: q.Get("country_iso"),
		ASN:        asn,
		Action:     q.Get("action"),
	}

	res, err := timelineStore.Timeline(r.Context(), filter)
	if err != nil {
		if errors.Is(err, r.Context().Err()) && r.Context().Err() != nil {
			writeError(w, http.StatusGatewayTimeout, "timeline statistics query timed out", "")
			return
		}
		log.Printf("[ERROR] timeline statistics: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error", "")
		return
	}

	writeJSON(w, http.StatusOK, res)
}
