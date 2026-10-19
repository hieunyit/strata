package api

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/strata/strata/control-plane/policy"
	"github.com/strata/strata/control-plane/rulehealth"
)

type HealthReader interface {
	Read(context.Context, uint32, string, time.Time, time.Time) (rulehealth.Health, error)
}

func healthPath(path string) (string, bool) {
	if !strings.HasPrefix(path, "/v1/rules/") {
		return "", false
	}
	id, action, ok := strings.Cut(strings.TrimPrefix(path, "/v1/rules/"), "/")
	return id, ok && action == "health"
}

func (s *Server) handleRuleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeError(w, 405, "GET required", "")
		return
	}
	id, _ := healthPath(r.URL.Path)
	if len(id) == 0 || len(id) > 10 || len(r.URL.RawQuery) > 2048 {
		writeError(w, 400, "invalid rule health query", "")
		return
	}
	n, err := strconv.ParseUint(id, 10, 32)
	if err != nil || n == 0 {
		writeError(w, 400, "invalid rule health query", "")
		return
	}
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		writeError(w, 400, "invalid query encoding", "")
		return
	}
	for k, values := range q {
		if (k != "policy_id" && k != "from" && k != "to") || len(values) != 1 {
			writeError(w, 400, "unknown or repeated query parameter", "")
			return
		}
	}
	to := time.Now().UTC()
	if v, ok := q["to"]; ok {
		to, err = time.Parse(time.RFC3339Nano, v[0])
		if err != nil {
			writeError(w, 400, "invalid to timestamp", "")
			return
		}
	}
	from := to.Add(-5 * time.Minute)
	if v, ok := q["from"]; ok {
		from, err = time.Parse(time.RFC3339Nano, v[0])
		if err != nil {
			writeError(w, 400, "invalid from timestamp", "")
			return
		}
	}
	policyID := q.Get("policy_id")
	if from.IsZero() || to.IsZero() || !to.After(from) || to.Sub(from) > 24*time.Hour || (policyID != "" && !policy.ValidName(policyID)) {
		writeError(w, 400, "window must be positive and at most 24 hours; invalid policy_id", "")
		return
	}
	health, err := s.cfg.Health.Read(r.Context(), uint32(n), policyID, from, to)
	if err != nil {
		if errors.Is(err, rulehealth.ErrInvalid) {
			writeError(w, 400, "invalid rule health query", "")
			return
		}
		if errors.Is(err, rulehealth.ErrBusy) {
			w.Header().Set("Retry-After", "1")
		}
		writeError(w, 503, "rule telemetry unavailable", "")
		return
	}
	writeJSON(w, 200, health)
}
