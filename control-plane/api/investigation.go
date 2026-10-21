package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/strata/strata/agent/pkg/privacy"
	"github.com/strata/strata/control-plane/auth"
	"github.com/strata/strata/control-plane/ingest"
	"github.com/strata/strata/control-plane/store"
)

func investigationError(w http.ResponseWriter, err error) {
	code, message := 503, "investigation store unavailable"
	switch {
	case errors.Is(err, store.ErrNotFound), errors.Is(err, ingest.ErrEventNotFound):
		code, message = 404, "investigation resource not found"
	case errors.Is(err, store.ErrEtagMismatch):
		code, message = 409, "resource changed; reload its etag"
	case errors.Is(err, store.ErrRequestReused):
		code, message = 409, "request_id reused with different content"
	case strings.HasPrefix(err.Error(), "investigation:"):
		code, message = 400, "invalid investigation request"
	}
	writeError(w, code, message, "")
}
func investigationAudit(r *http.Request, requestID, resource string) store.Audit {
	p := auth.FromContext(r.Context())
	return store.Audit{Actor: p.Name, Subject: p.Subject, Action: r.Method + " " + r.URL.Path, Resource: resource, RequestID: requestID}
}
func filterSensitive(v SearchEventsRequest) bool { return v.ClientIP != "" || v.HTTPPath != "" }
func validateInvestigationFilter(v *SearchEventsRequest) bool {
	if v.From.IsZero() || v.To.IsZero() || v.To.Before(v.From) || v.To.Sub(v.From) > 31*24*time.Hour || len(v.PolicyID) > 128 || len(v.NodeID) > 128 || len(v.HTTPHost) > 253 || len(v.HTTPPath) > 2048 || len(v.ClientIP) > 64 || len(v.HTTPMethod) > 16 || len(v.Country) > 8 || len(v.AttackType) > 64 {
		return false
	}
	v.PageToken = ""
	v.PageSize = 200
	return true
}
func investigationFilter(v SearchEventsRequest) ingest.SearchFilter {
	return ingest.SearchFilter{From: v.From, To: v.To, PolicyID: v.PolicyID, NodeID: v.NodeID, Action: v.Action, ClientIP: v.ClientIP, RuleID: v.RuleID, HTTPMethod: v.HTTPMethod, HTTPHost: v.HTTPHost, HTTPPath: v.HTTPPath, CountryISO: v.Country, ASN: v.ASN, AttackType: v.AttackType, Limit: 200}
}
func (s *Server) investigationScope(r *http.Request, app, env string) (context.Context, error) {
	if app == "" || env == "" {
		return nil, errors.New("investigation: application and environment required")
	}
	p := auth.FromContext(r.Context())
	if p.Access != nil && !p.Access.Environments[app+"/"+env] && !p.Access.Environments[app+"/*"] {
		return nil, store.ErrNotFound
	}
	return s.cfg.Applications.ApplicationEventScope(r.Context(), app, env, p)
}
func (s *Server) savedSearchCollection(w http.ResponseWriter, r *http.Request) {
	p := auth.FromContext(r.Context())
	st := s.cfg.Applications
	if r.Method == http.MethodGet {
		app, env := r.URL.Query().Get("application_id"), r.URL.Query().Get("environment_id")
		if _, err := s.investigationScope(r, app, env); err != nil {
			investigationError(w, err)
			return
		}
		rows, err := st.SavedSearches(r.Context(), app, env, p.Subject, r.URL.Query().Get("after"))
		if err != nil {
			investigationError(w, err)
			return
		}
		visible := []store.SavedSearch{}
		for _, v := range rows {
			if !v.Sensitive || p.Can(auth.PermEventsReadSensitive) {
				v.Editable = v.Owner == p.Subject
				visible = append(visible, v)
			}
		}
		next := ""
		if len(rows) == 50 {
			next = rows[len(rows)-1].ID
		}
		writeJSON(w, 200, map[string]any{"searches": visible, "next_cursor": next})
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(405)
		return
	}
	s.saveSearch(w, r, "")
}
func (s *Server) savedSearchItem(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	id := strings.TrimPrefix(r.URL.Path, "/v1/saved-searches/")
	search := strings.HasSuffix(id, ":search")
	id = strings.TrimSuffix(id, ":search")
	v, err := s.cfg.Applications.SavedSearch(r.Context(), id)
	if err != nil {
		investigationError(w, err)
		return
	}
	p := auth.FromContext(r.Context())
	v.Editable = v.Owner == p.Subject
	if v.Owner != p.Subject && !v.Shared || v.Sensitive && !p.Can(auth.PermEventsReadSensitive) {
		investigationError(w, store.ErrNotFound)
		return
	}
	if _, err := s.investigationScope(r, v.ApplicationID, v.EnvironmentID); err != nil {
		investigationError(w, err)
		return
	}
	if search {
		if r.Method != http.MethodPost {
			w.WriteHeader(405)
			return
		}
		var page struct {
			PageToken string `json:"page_token"`
		}
		if !appBody(w, r, &page) {
			return
		}
		var filter SearchEventsRequest
		if err := json.Unmarshal(v.Filter, &filter); err != nil {
			investigationError(w, err)
			return
		}
		filter.PageToken = page.PageToken
		raw, err := json.Marshal(filter)
		if err != nil {
			investigationError(w, err)
			return
		}
		scoped, err := s.investigationScope(r, v.ApplicationID, v.EnvironmentID)
		if err != nil {
			investigationError(w, err)
			return
		}
		request := r.Clone(scoped)
		request.Body = io.NopCloser(bytes.NewReader(raw))
		s.handler.HandleSearchEvents(w, request)
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, 200, map[string]any{"search": v})
	case http.MethodPut:
		if v.Owner != p.Subject {
			investigationError(w, store.ErrNotFound)
			return
		}
		s.saveSearch(w, r, id)
	default:
		w.WriteHeader(405)
	}
}
func (s *Server) saveSearch(w http.ResponseWriter, r *http.Request, id string) {
	var req struct {
		Search    store.SavedSearch `json:"search"`
		RequestID string            `json:"request_id"`
	}
	if !appBody(w, r, &req) {
		return
	}
	if req.Search.ID != id {
		writeError(w, 400, "saved search ID mismatch", "")
		return
	}
	var filter SearchEventsRequest
	if err := json.Unmarshal(req.Search.Filter, &filter); err != nil || !validateInvestigationFilter(&filter) {
		writeError(w, 400, "bounded filter required", "")
		return
	}
	p := auth.FromContext(r.Context())
	req.Search.Sensitive = filterSensitive(filter)
	if req.Search.Sensitive && !p.Can(auth.PermEventsReadSensitive) {
		writeError(w, 403, "sensitive filter permission required", "")
		return
	}
	if _, err := s.investigationScope(r, req.Search.ApplicationID, req.Search.EnvironmentID); err != nil {
		investigationError(w, err)
		return
	}
	req.Search.Title = (*privacy.Filter)(nil).Text(req.Search.Title)
	raw, err := json.Marshal(filter)
	if err != nil {
		investigationError(w, err)
		return
	}
	req.Search.Filter = raw
	out, err := s.cfg.Applications.SaveSearch(r.Context(), req.Search, id == "", investigationAudit(r, req.RequestID, "saved-searches/"+id))
	if err != nil {
		investigationError(w, err)
		return
	}
	out.Editable = out.Owner == p.Subject
	writeJSON(w, 200, map[string]any{"search": out})
}
func (s *Server) investigationEvent(w http.ResponseWriter, r *http.Request, suffix string) (*ingest.Event, bool) {
	block := strings.ToUpper(strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/events/"), suffix))
	if err := ingest.ValidateBlockID(block); err != nil {
		writeError(w, 400, "invalid block ID", "")
		return nil, false
	}
	e, err := s.handler.store.GetEvent(r.Context(), block)
	if err != nil {
		investigationError(w, err)
		return nil, false
	}
	return e, true
}
func (s *Server) handleEventCase(w http.ResponseWriter, r *http.Request) {
	e, ok := s.investigationEvent(w, r, ":case")
	if !ok {
		return
	}
	p := auth.FromContext(r.Context())
	if r.Method == http.MethodGet {
		v, err := s.cfg.Applications.EventCase(r.Context(), e.BlockID)
		if errors.Is(err, store.ErrNotFound) {
			writeJSON(w, 200, map[string]any{"case": store.EventCase{BlockID: e.BlockID, Status: "open"}})
			return
		}
		if err != nil {
			investigationError(w, err)
			return
		}
		if !p.Can(auth.PermEventsReadSensitive) {
			v.Note = ""
		}
		writeJSON(w, 200, map[string]any{"case": v})
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(405)
		return
	}
	if !p.CanResource("eventpolicies/"+e.PolicyID, auth.PermExceptionsWrite) {
		writeError(w, 403, "event outside assigned write scope", "")
		return
	}
	var req struct {
		Case      store.EventCase `json:"case"`
		RequestID string          `json:"request_id"`
	}
	if !appBody(w, r, &req) {
		return
	}
	if req.Case.BlockID != e.BlockID {
		writeError(w, 400, "case block mismatch", "")
		return
	}
	if req.Case.Assignee == "@me" {
		req.Case.Assignee = p.Subject
	}
	if req.Case.Assignee != "" && req.Case.Assignee != p.Subject {
		allowed, err := s.cfg.Applications.EventAssigneeAllowed(r.Context(), e.PolicyID, e.HTTPHost, e.HTTPPath, e.NodeID, req.Case.Assignee)
		if err != nil {
			investigationError(w, err)
			return
		}
		if !allowed {
			writeError(w, 400, "assignee outside event scope", "")
			return
		}
	}
	req.Case.Note = (*privacy.Filter)(nil).Text(req.Case.Note)
	out, err := s.cfg.Applications.SaveEventCase(r.Context(), req.Case, investigationAudit(r, req.RequestID, "events/"+e.BlockID))
	if err != nil {
		investigationError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"case": out})
}
func (s *Server) handleSimilarEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(405)
		return
	}
	e, ok := s.investigationEvent(w, r, ":similar")
	if !ok {
		return
	}
	filter := ingest.SearchFilter{PolicyID: e.PolicyID, HTTPMethod: e.HTTPMethod, HTTPHost: e.HTTPHost, HTTPPath: e.HTTPPath, From: e.Timestamp.Add(-12 * time.Hour), To: e.Timestamp.Add(12 * time.Hour), Limit: 200}
	if len(e.MatchedRules) > 0 {
		filter.RuleID = e.MatchedRules[0]
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	res, err := s.handler.store.SearchEvents(ctx, filter)
	if err != nil {
		eventsUnavailable(w, "")
		return
	}
	for i := range res.Events {
		res.Events[i] = sanitizeEvent(res.Events[i], auth.FromContext(r.Context()))
	}
	writeJSON(w, 200, SearchEventsResponse{Events: res.Events, TotalMatched: res.Total})
}
