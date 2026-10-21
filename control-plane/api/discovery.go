package api

import (
	"errors"
	"github.com/strata/strata/control-plane/apidiscovery"
	"github.com/strata/strata/control-plane/auth"
	"github.com/strata/strata/control-plane/ruleinventory"
	"github.com/strata/strata/control-plane/store"
	"net/http"
	"strings"
	"time"
)

func (s *Server) registerDiscovery(mux *http.ServeMux) {
	mux.HandleFunc("/v1/discovery", auth.RequireHTTP(auth.PermEventsRead, s.discoveryInventory))
	mux.HandleFunc("/v1/discovery/observations", auth.RequireHTTP(auth.PermDiscoveryIngest, s.discoveryObserve))
	mux.HandleFunc("/v1/discovery/document", auth.RequireHTTP(auth.PermPoliciesWrite, s.discoveryDocument))
	mux.HandleFunc("/v1/discovery/proposals", auth.RequireHTTP(auth.PermPoliciesWrite, s.discoveryPropose))
	mux.HandleFunc("/v1/discovery/proposals:draft", auth.RequireHTTP(auth.PermPoliciesWrite, s.discoveryDraft))
	mux.HandleFunc("/v1/discovery/proposals/", auth.RequireHTTP(auth.PermEventsRead, s.discoveryDownload))
}
func discoveryError(w http.ResponseWriter, err error) {
	if strings.Contains(err.Error(), "discovery:") {
		writeError(w, 400, "invalid discovery input, insufficient evidence or quota reached", "")
		return
	}
	investigationError(w, err)
}
func (s *Server) discoveryInventory(w http.ResponseWriter, r *http.Request) {
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
	now := time.Now().UTC()
	endpoints, err := s.cfg.Applications.DiscoveredEndpoints(r.Context(), app, env, scope, now)
	if err != nil {
		discoveryError(w, err)
		return
	}
	if endpoints == nil {
		endpoints = []store.DiscoveredEndpoint{}
	}
	doc, err := s.cfg.Applications.DiscoveryDocument(r.Context(), app, env, scope)
	var document *store.DiscoveryDocument
	scopeChanged := false
	etag := ""
	if err == nil {
		document = &doc
		etag = doc.Etag
	} else if errors.Is(err, store.ErrNotFound) {
		etag, err = s.cfg.Applications.DiscoveryDocumentEtag(r.Context(), app, env)
		if errors.Is(err, store.ErrNotFound) {
			err = nil
		} else if err == nil {
			scopeChanged = true
		}
	}
	if err != nil {
		discoveryError(w, err)
		return
	}
	proposals, err := s.cfg.Applications.DiscoveryProposals(r.Context(), app, env, scope, now)
	if err != nil {
		discoveryError(w, err)
		return
	}
	if proposals == nil {
		proposals = []store.DiscoveryProposal{}
	}
	if err = s.enrichDiscoveryProposals(r, app, env, proposals); err != nil {
		discoveryError(w, err)
		return
	}
	var expires *time.Time
	if !s.cfg.Discovery.ApprovalExpires.IsZero() {
		expires = &s.cfg.Discovery.ApprovalExpires
	}
	writeJSON(w, 200, map[string]any{"endpoints": endpoints, "document": document, "document_etag": etag, "scope_changed": scopeChanged, "proposals": proposals, "editable": s.operationEditable(r, app, env), "collection_enabled": s.cfg.Discovery.Approved(now), "approval_expires_at": expires, "runtime_enforcement": false, "source": "trusted_backend_2xx_only", "limits": map[string]int{"min_samples": 20, "min_sources": 3, "min_span_seconds": 600, "retention_days": 7}})
}

type discoveryObservationRequest struct {
	ApplicationID string                     `json:"application_id"`
	EnvironmentID string                     `json:"environment_id"`
	RequestID     string                     `json:"request_id"`
	Observations  []apidiscovery.Observation `json:"observations"`
}

func (s *Server) discoveryObserve(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(405)
		return
	}
	caller := auth.FromContext(r.Context())
	now := time.Now().UTC()
	if !strings.HasPrefix(caller.Subject, "sa:") || caller.Scopes == nil || !s.cfg.Discovery.TrustedCollectors[caller.Subject] {
		writeError(w, 403, "trusted machine collector required", "")
		return
	}
	if !s.cfg.Discovery.Approved(now) {
		writeError(w, 503, "discovery collection is disabled or legal approval expired", "DISCOVERY_DISABLED")
		return
	}
	var req discoveryObservationRequest
	if !appBody(w, r, &req) {
		return
	}
	if req.RequestID == "" || len(req.RequestID) > 128 || len(req.Observations) == 0 || len(req.Observations) > 100 {
		writeError(w, 400, "bounded batch required", "")
		return
	}
	app, err := ruleinventory.Application(r.Context(), s.cfg.Applications, req.ApplicationID, req.EnvironmentID)
	if err != nil {
		discoveryError(w, err)
		return
	}
	samples := make([]apidiscovery.Sample, 0, len(req.Observations))
	for _, v := range req.Observations {
		allowed := false
		path, _, _ := strings.Cut(v.Path, "?")
		for _, route := range app.Routes {
			if route.ID == v.RouteID && route.EnvironmentID == req.EnvironmentID && strings.HasPrefix(path, route.PathPrefix) && caller.CanResource("policies/"+route.PolicyID, auth.PermPoliciesRead) {
				allowed = true
				break
			}
		}
		if !allowed {
			writeError(w, 403, "observation outside collector route scope", "")
			return
		}
		sample, err := apidiscovery.Normalize(v, s.cfg.Discovery.Key, app.ID+"/"+req.EnvironmentID, now)
		if err != nil {
			discoveryError(w, err)
			return
		}
		samples = append(samples, sample)
	}
	if err = s.cfg.Applications.SaveDiscoveryBatch(r.Context(), app.ID, req.EnvironmentID, app.Etag, req.RequestID, caller.Subject, samples); err != nil {
		discoveryError(w, err)
		return
	}
	writeJSON(w, 202, map[string]any{"accepted": true})
}

type discoveryDocumentRequest struct {
	ApplicationID string `json:"application_id"`
	EnvironmentID string `json:"environment_id"`
	Etag          string `json:"etag"`
	Document      string `json:"document"`
	RequestID     string `json:"request_id"`
}

func (s *Server) discoveryDocument(w http.ResponseWriter, r *http.Request) {
	if r.Method != "PUT" {
		w.WriteHeader(405)
		return
	}
	var req discoveryDocumentRequest
	if !appBody(w, r, &req) {
		return
	}
	if len(req.Document) > 128<<10 || req.RequestID == "" || len(req.RequestID) > 128 || len(req.Etag) > 128 {
		writeError(w, 400, "bounded OpenAPI document, etag and request_id required", "")
		return
	}
	scope, ok := s.operationScope(w, r, req.ApplicationID, req.EnvironmentID, true, false)
	if !ok {
		return
	}
	ops, err := apidiscovery.ParseDocument([]byte(req.Document))
	if err != nil {
		discoveryError(w, err)
		return
	}
	app, err := s.cfg.Applications.GetApplication(r.Context(), req.ApplicationID)
	if err != nil {
		discoveryError(w, err)
		return
	}
	for _, op := range ops {
		owned := false
		for _, route := range app.Routes {
			if route.EnvironmentID == req.EnvironmentID && strings.HasPrefix(op.Path, route.PathPrefix) {
				owned = true
				break
			}
		}
		if !owned {
			writeError(w, 403, "schema path outside environment routes", "")
			return
		}
	}
	v, err := s.cfg.Applications.SaveDiscoveryDocument(r.Context(), store.DiscoveryDocument{ApplicationID: app.ID, EnvironmentID: req.EnvironmentID, ScopeEtag: scope, Etag: req.Etag, Operations: ops}, investigationAudit(r, req.RequestID, "applications/"+app.ID))
	if err != nil {
		discoveryError(w, err)
		return
	}
	writeJSON(w, 200, v)
}
