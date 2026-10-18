package api

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/strata/strata/control-plane/store"
)

type auditSearcher interface {
	SearchAudit(context.Context, store.AuditFilter) ([]store.Audit, error)
}

func parseAuditFilter(r *http.Request) (store.AuditFilter, error) {
	f := store.AuditFilter{Limit: 100}
	if len(r.URL.RawQuery) > 8192 {
		return f, fmt.Errorf("query too long")
	}
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return f, fmt.Errorf("invalid query encoding")
	}
	for name, values := range q {
		switch name {
		case "limit", "actor", "channel", "action", "resource", "from", "to":
		default:
			return f, fmt.Errorf("unknown filter")
		}
		if len(values) != 1 || len(values[0]) > 256 || !utf8.ValidString(values[0]) || strings.ContainsAny(values[0], "\x00\r\n") {
			return f, fmt.Errorf("invalid filter")
		}
	}
	if raw, ok := q["limit"]; ok {
		n, err := strconv.Atoi(raw[0])
		if err != nil || n < 1 || n > 500 {
			return f, fmt.Errorf("invalid limit")
		}
		f.Limit = n
	}
	f.Actor = q.Get("actor")
	f.Channel = q.Get("channel")
	f.Action = q.Get("action")
	f.Resource = q.Get("resource")
	for name, dest := range map[string]*time.Time{"from": &f.From, "to": &f.To} {
		if raw, ok := q[name]; ok {
			v, err := time.Parse(time.RFC3339Nano, raw[0])
			if err != nil {
				return f, fmt.Errorf("invalid time")
			}
			*dest = v.UTC()
		}
	}
	if !f.From.IsZero() && !f.To.IsZero() && !f.From.Before(f.To) {
		return f, fmt.Errorf("invalid range")
	}
	return f, nil
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	f, err := parseAuditFilter(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid audit filters", "")
		return
	}
	limit := f.Limit
	f.Limit++
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	var entries []store.Audit
	if search, ok := s.cfg.Audit.(auditSearcher); ok {
		entries, err = search.SearchAudit(ctx, f)
	} else {
		if f.Actor != "" || f.Channel != "" || f.Action != "" || f.Resource != "" || !f.From.IsZero() || !f.To.IsZero() {
			writeError(w, http.StatusServiceUnavailable, "audit search unavailable", "")
			return
		}
		entries, err = s.cfg.Audit.AuditEntries(ctx, f.Limit)
	}
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "audit unavailable", "")
		return
	}
	more := len(entries) > limit
	if more {
		entries = entries[:limit]
	}
	if entries == nil {
		entries = []store.Audit{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": entries, "has_more": more, "limit": limit})
}
