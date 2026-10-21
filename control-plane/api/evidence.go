package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/strata/strata/control-plane/auth"
	"github.com/strata/strata/control-plane/investigation"
	"github.com/strata/strata/control-plane/store"
)

func (s *Server) evidenceCollection(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodGet {
		app, env := r.URL.Query().Get("application_id"), r.URL.Query().Get("environment_id")
		if _, err := s.investigationScope(r, app, env); err != nil {
			investigationError(w, err)
			return
		}
		rows, err := s.cfg.Applications.EvidenceExports(r.Context(), auth.FromContext(r.Context()).Subject, app, env)
		if err != nil {
			investigationError(w, err)
			return
		}
		visible := []store.EvidenceExport{}
		for _, v := range rows {
			if _, err := investigation.Scope(r.Context(), s.cfg.Applications, v, auth.FromContext(r.Context())); err == nil {
				visible = append(visible, v)
			}
		}
		writeJSON(w, 200, map[string]any{"exports": visible})
		return
	}

	if r.Method != http.MethodPost {
		w.WriteHeader(405)
		return
	}
	if s.cfg.Evidence == nil {
		writeError(w, 503, "evidence worker not configured", "")
		return
	}
	var req struct {
		ApplicationID string              `json:"application_id"`
		EnvironmentID string              `json:"environment_id"`
		Sensitive     bool                `json:"sensitive"`
		Filter        SearchEventsRequest `json:"filter"`
		RequestID     string              `json:"request_id"`
	}
	if !appBody(w, r, &req) {
		return
	}
	p := auth.FromContext(r.Context())
	if !validateInvestigationFilter(&req.Filter) {
		writeError(w, 400, "export window must be at most 31 days", "")
		return
	}
	if (req.Sensitive || filterSensitive(req.Filter)) && !p.Can(auth.PermEventsReadSensitive) {
		writeError(w, 403, "sensitive permission required", "")
		return
	}
	ctx, err := s.investigationScope(r, req.ApplicationID, req.EnvironmentID)
	if err != nil {
		investigationError(w, err)
		return
	}
	scoped := auth.FromContext(ctx)
	if len(scoped.Access.Events) == 0 {
		investigationError(w, store.ErrNotFound)
		return
	}
	// Store the original roles but the narrowed event scope. Workers re-resolve
	// current local account state and bindings before query and publication.
	snapshot := investigation.Capture(p)
	snapshot.RequiresSensitive = filterSensitive(req.Filter)
	snapshot.Events = scoped.Access.Events
	principal, err := json.Marshal(snapshot)
	if err != nil {
		investigationError(w, err)
		return
	}
	filter, err := json.Marshal(investigationFilter(req.Filter))
	if err != nil {
		investigationError(w, err)
		return
	}
	v, err := s.cfg.Applications.CreateEvidenceExport(r.Context(), store.EvidenceExport{ApplicationID: req.ApplicationID, EnvironmentID: req.EnvironmentID, Sensitive: req.Sensitive, Filter: filter, Principal: principal}, investigationAudit(r, req.RequestID, "evidence"))
	if err != nil {
		investigationError(w, err)
		return
	}
	writeJSON(w, 202, map[string]any{"export": v})
}
func (s *Server) evidenceItem(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet {
		w.WriteHeader(405)
		return
	}
	if s.cfg.Evidence == nil {
		writeError(w, 503, "evidence worker not configured", "")
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/v1/evidence/")
	download := strings.HasSuffix(id, "/download")
	id = strings.TrimSuffix(id, "/download")
	v, err := s.cfg.Applications.EvidenceExport(r.Context(), id)
	if err != nil {
		investigationError(w, err)
		return
	}
	if _, err := investigation.Scope(r.Context(), s.cfg.Applications, v, auth.FromContext(r.Context())); err != nil {
		investigationError(w, store.ErrNotFound)
		return
	}
	if !download {
		writeJSON(w, 200, map[string]any{"export": v})
		return
	}
	if v.State != "done" {
		writeError(w, 409, "export not complete", "")
		return
	}
	data, err := s.cfg.Evidence.Objects.Get(r.Context(), v.ArtifactKey)
	if err != nil || len(data) > investigation.MaxBytes {
		writeError(w, 503, "evidence artifact unavailable", "")
		return
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != v.SHA256 {
		writeError(w, 503, "evidence integrity check failed", "")
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="evidence-`+v.ID+`.csv"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(200)
	_, _ = w.Write(data)
}
