package api

import (
	"encoding/json"
	"errors"
	"github.com/strata/strata/control-plane/auth"
	"github.com/strata/strata/control-plane/ruleinventory"
	"github.com/strata/strata/control-plane/store"
	"net/http"
	"strings"
	"time"
)

func (s *Server) registerOperations(mux *http.ServeMux) {
	mux.HandleFunc("/v1/incidents", auth.RequireHTTP(auth.PermNodesRead, s.incidentCollection))
	mux.HandleFunc("/v1/incidents:acknowledge", auth.RequireHTTP(auth.PermPoliciesWrite, s.incidentAck))
	mux.HandleFunc("/v1/report-schedule", auth.RequireHTTP(auth.PermEventsRead, s.reportSchedule))
	mux.HandleFunc("/v1/application-reports", auth.RequireHTTP(auth.PermEventsRead, s.reportCollection))
	mux.HandleFunc("/v1/application-reports/", auth.RequireHTTP(auth.PermEventsRead, s.reportDownload))
}

// Aggregates require the whole current environment; app read alone is not
// authority over the data of a second environment, route or shared node.
func (s *Server) operationScope(w http.ResponseWriter, r *http.Request, app, env string, write, global bool) (string, bool) {
	p := auth.FromContext(r.Context())
	if len(app) > 63 || len(env) > 63 {
		writeError(w, 400, "invalid operational scope", "")
		return "", false
	}
	if app == "" && env == "" && global {
		if p.Access != nil || !p.Can(auth.PermAuditRead) {
			writeError(w, 403, "global operational scope required", "")
			return "", false
		}
		return "", true
	}
	a, err := ruleinventory.Application(r.Context(), s.cfg.Applications, app, env)
	if err != nil {
		investigationError(w, err)
		return "", false
	}
	full, err := s.cfg.Applications.OperationPrincipal(r.Context(), a, env)
	if err != nil {
		investigationError(w, err)
		return "", false
	}
	if !p.Can(auth.PermEventsRead) {
		writeError(w, 403, "environment events permission required", "")
		return "", false
	}
	for resource, perms := range full.Access.Resources {
		for permission := range perms {
			if !p.CanResource(resource, permission) {
				writeError(w, 403, "complete environment permission required", "")
				return "", false
			}
		}
		if write && strings.HasPrefix(resource, "policies/") && !p.CanResource(resource, auth.PermPoliciesWrite) {
			writeError(w, 403, "complete policy write scope required", "")
			return "", false
		}
	}
	if write && !p.Can(auth.PermPoliciesWrite) {
		writeError(w, 403, "policy write permission required", "")
		return "", false
	}
	return a.Etag, true
}
func operationError(w http.ResponseWriter, err error) {
	if strings.HasPrefix(err.Error(), "operations:") {
		writeError(w, 400, "invalid operational request or quota reached", "")
		return
	}
	investigationError(w, err)
}
func (s *Server) incidentCollection(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != "GET" {
		w.WriteHeader(405)
		return
	}
	q := r.URL.Query()
	app, env := q.Get("application_id"), q.Get("environment_id")
	scope, ok := s.operationScope(w, r, app, env, false, true)
	if !ok {
		return
	}
	rows, err := s.cfg.Applications.Incidents(r.Context(), app, env, scope)
	if err != nil {
		operationError(w, err)
		return
	}
	if rows == nil {
		rows = []store.Incident{}
	}
	writeJSON(w, 200, map[string]any{"incidents": rows, "limit": 200, "editable": s.operationEditable(r, app, env)})
}

type incidentAckRequest struct {
	ID            string `json:"id"`
	ApplicationID string `json:"application_id"`
	EnvironmentID string `json:"environment_id"`
	Etag          string `json:"etag"`
	RequestID     string `json:"request_id"`
}

func (s *Server) incidentAck(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(405)
		return
	}
	var req incidentAckRequest
	if !appBody(w, r, &req) {
		return
	}
	if len(req.ID) > 64 || req.ID == "" || len(req.Etag) > 128 || req.Etag == "" || len(req.RequestID) > 128 || req.RequestID == "" {
		writeError(w, 400, "bounded id, etag and request_id required", "")
		return
	}
	scope, ok := s.operationScope(w, r, req.ApplicationID, req.EnvironmentID, true, true)
	if !ok {
		return
	}
	a := investigationAudit(r, req.RequestID, "incidents/"+req.ID)
	out, err := s.cfg.Applications.AcknowledgeIncident(r.Context(), req.ID, req.Etag, req.ApplicationID, req.EnvironmentID, scope, a)
	if err != nil {
		operationError(w, err)
		return
	}
	writeJSON(w, 200, out)
}

type scheduleRequest struct {
	Schedule  store.ReportSchedule `json:"schedule"`
	RequestID string               `json:"request_id"`
}

func (s *Server) reportSchedule(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	switch r.Method {
	case "GET":
		q := r.URL.Query()
		app, env := q.Get("application_id"), q.Get("environment_id")
		scope, ok := s.operationScope(w, r, app, env, false, false)
		if !ok {
			return
		}
		v, err := s.cfg.Applications.ReportSchedule(r.Context(), app, env)
		if errors.Is(err, store.ErrNotFound) {
			writeJSON(w, 200, map[string]any{"schedule": nil, "scope_changed": false, "editable": s.operationEditable(r, app, env)})
			return
		}
		if err != nil {
			operationError(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"schedule": v, "scope_changed": scope != v.ScopeEtag, "editable": s.operationEditable(r, app, env)})
	case "PUT":
		var req scheduleRequest
		if !appBody(w, r, &req) {
			return
		}
		if req.RequestID == "" || len(req.RequestID) > 128 {
			writeError(w, 400, "bounded request_id required", "")
			return
		}
		scope, ok := s.operationScope(w, r, req.Schedule.ApplicationID, req.Schedule.EnvironmentID, true, false)
		if !ok {
			return
		}
		req.Schedule.ScopeEtag = scope
		a := investigationAudit(r, req.RequestID, "applications/"+req.Schedule.ApplicationID)
		v, err := s.cfg.Applications.SaveReportSchedule(r.Context(), req.Schedule, a)
		if err != nil {
			operationError(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"schedule": v, "scope_changed": false, "editable": true})
	default:
		w.WriteHeader(405)
	}
}
func (s *Server) reportCollection(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != "GET" {
		w.WriteHeader(405)
		return
	}
	q := r.URL.Query()
	app, env := q.Get("application_id"), q.Get("environment_id")
	scope, ok := s.operationScope(w, r, app, env, false, false)
	if !ok {
		return
	}
	rows, err := s.cfg.Applications.ApplicationReports(r.Context(), app, env, scope, time.Now().UTC())
	if err != nil {
		operationError(w, err)
		return
	}
	if rows == nil {
		rows = []store.ApplicationReport{}
	}
	writeJSON(w, 200, map[string]any{"reports": rows})
}
func (s *Server) reportDownload(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != "GET" {
		w.WriteHeader(405)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/v1/application-reports/")
	if len(id) > 64 || id == "" {
		writeError(w, 400, "invalid report id", "")
		return
	}
	q := r.URL.Query()
	app, env := q.Get("application_id"), q.Get("environment_id")
	scope, ok := s.operationScope(w, r, app, env, false, false)
	if !ok {
		return
	}
	rows, err := s.cfg.Applications.ApplicationReports(r.Context(), app, env, scope, time.Now().UTC())
	if err != nil {
		operationError(w, err)
		return
	}
	for _, v := range rows {
		if v.ID != id {
			continue
		}
		body, err := json.Marshal(v)
		if err != nil {
			operationError(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", `attachment; filename="application-report.json"`)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_, _ = w.Write(body)
		return
	}
	writeError(w, 404, "report not found", "")
}

func (s *Server) operationEditable(r *http.Request, app, env string) bool {
	p := auth.FromContext(r.Context())
	if !p.Can(auth.PermPoliciesWrite) {
		return false
	}
	if app == "" {
		return p.Access == nil && p.Can(auth.PermAuditRead)
	}
	a, err := s.cfg.Applications.GetApplication(r.Context(), app)
	if err != nil {
		return false
	}
	for _, route := range a.Routes {
		if route.EnvironmentID == env && !p.CanResource("policies/"+route.PolicyID, auth.PermPoliciesWrite) {
			return false
		}
	}
	return true
}
