package api

import (
	"github.com/strata/strata/control-plane/apidiscovery"
	"github.com/strata/strata/control-plane/auth"
	"github.com/strata/strata/control-plane/store"
	"net/http"
	"strings"
	"time"
)

type discoveryProposalRequest struct {
	ApplicationID string `json:"application_id"`
	EnvironmentID string `json:"environment_id"`
	EndpointKey   string `json:"endpoint_key"`
	BaseDigest    string `json:"base_digest"`
	RequestID     string `json:"request_id"`
}

func (s *Server) discoveryPropose(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(405)
		return
	}
	var req discoveryProposalRequest
	if !appBody(w, r, &req) {
		return
	}
	if req.RequestID == "" || len(req.RequestID) > 128 || !catalogDigest.MatchString(req.EndpointKey) || !catalogDigest.MatchString(req.BaseDigest) {
		writeError(w, 400, "bounded proposal command required", "")
		return
	}
	scope, ok := s.operationScope(w, r, req.ApplicationID, req.EnvironmentID, true, false)
	if !ok {
		return
	}
	v, err := s.cfg.Applications.CreateDiscoveryProposal(r.Context(), req.ApplicationID, req.EnvironmentID, scope, req.EndpointKey, req.BaseDigest, investigationAudit(r, req.RequestID, "applications/"+req.ApplicationID))
	if err != nil {
		discoveryError(w, err)
		return
	}
	row := []store.DiscoveryProposal{v}
	if err = s.enrichDiscoveryProposals(r, req.ApplicationID, req.EnvironmentID, row); err != nil {
		discoveryError(w, err)
		return
	}
	v = row[0]
	v.ReviewState = "PROPOSED"
	writeJSON(w, 200, v)
}

type discoveryDraftRequest struct {
	ApplicationID string `json:"application_id"`
	EnvironmentID string `json:"environment_id"`
	ID            string `json:"id"`
	Etag          string `json:"etag"`
	PolicyEtag    string `json:"policy_etag"`
	RequestID     string `json:"request_id"`
}

func (s *Server) discoveryDraft(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(405)
		return
	}
	var req discoveryDraftRequest
	if !appBody(w, r, &req) {
		return
	}
	if len(req.ID) > 64 || req.ID == "" || req.Etag == "" || len(req.Etag) > 128 || req.PolicyEtag == "" || len(req.PolicyEtag) > 128 || req.RequestID == "" || len(req.RequestID) > 128 {
		writeError(w, 400, "bounded id, etags and request_id required", "")
		return
	}
	scope, ok := s.operationScope(w, r, req.ApplicationID, req.EnvironmentID, true, false)
	if !ok {
		return
	}
	proposals, err := s.cfg.Applications.DiscoveryProposals(r.Context(), req.ApplicationID, req.EnvironmentID, scope, time.Now().UTC())
	if err != nil {
		discoveryError(w, err)
		return
	}
	route := ""
	for _, v := range proposals {
		if v.ID == req.ID {
			route = v.RouteID
			break
		}
	}
	if route == "" {
		writeError(w, 404, "proposal not found", "")
		return
	}
	app, err := s.cfg.Applications.GetApplication(r.Context(), req.ApplicationID)
	if err != nil {
		discoveryError(w, err)
		return
	}
	policyID := ""
	for _, v := range app.Routes {
		if v.ID == route && v.EnvironmentID == req.EnvironmentID {
			policyID = v.PolicyID
		}
	}
	if policyID == "" || !auth.FromContext(r.Context()).CanResource("policies/"+policyID, auth.PermPoliciesWrite) {
		writeError(w, 403, "complete policy write scope required", "")
		return
	}
	if s.cfg.ReplayKick == nil {
		writeError(w, 503, "replay runner not configured", "")
		return
	}
	v, err := s.cfg.Applications.DraftDiscoveryProposal(r.Context(), req.ID, req.Etag, policyID, req.PolicyEtag, scope, investigationAudit(r, req.RequestID, "policies/"+policyID))
	if err != nil {
		discoveryError(w, err)
		return
	}
	s.cfg.ReplayKick()
	writeJSON(w, 200, eventRuleReply(v))
}
func (s *Server) discoveryDownload(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != "GET" {
		w.WriteHeader(405)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/v1/discovery/proposals/")
	if id == "" || len(id) > 64 {
		writeError(w, 400, "invalid proposal id", "")
		return
	}
	q := r.URL.Query()
	app, env := q.Get("application_id"), q.Get("environment_id")
	scope, ok := s.operationScope(w, r, app, env, false, false)
	if !ok {
		return
	}
	rows, err := s.cfg.Applications.DiscoveryProposals(r.Context(), app, env, scope, time.Now().UTC())
	if err != nil {
		discoveryError(w, err)
		return
	}
	for _, v := range rows {
		if v.ID != id {
			continue
		}
		doc, err := apidiscovery.Document(v.Operations)
		if err != nil {
			discoveryError(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", `attachment; filename="openapi-proposal.json"`)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_, _ = w.Write(doc)
		return
	}
	writeError(w, 404, "proposal not found", "")
}

func (s *Server) enrichDiscoveryProposals(r *http.Request, app, env string, rows []store.DiscoveryProposal) error {
	a, err := s.cfg.Applications.GetApplication(r.Context(), app)
	if err != nil {
		return err
	}
	p := auth.FromContext(r.Context())
	for i, v := range rows {
		for _, route := range a.Routes {
			if route.ID != v.RouteID || route.EnvironmentID != env || !p.CanResource("policies/"+route.PolicyID, auth.PermPoliciesRead) {
				continue
			}
			policy, err := s.cfg.Applications.GetPolicy(r.Context(), route.PolicyID)
			if err != nil {
				return err
			}
			rows[i].PolicyID = policy.ID
			rows[i].PolicyEtag = policy.Etag
			rows[i].PolicyVersion = policy.CurrentVersion
			rows[i].Draftable = v.DraftVersion == 0 && p.CanResource("policies/"+policy.ID, auth.PermPoliciesWrite) && s.cfg.ReplayKick != nil
		}
	}
	return nil
}
