package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/strata/strata/control-plane/auth"
	"github.com/strata/strata/control-plane/policy"
	"github.com/strata/strata/control-plane/store"
)

type EventRuleRequest struct {
	Dimension string `json:"dimension"` // country or asn, sourced from stored GeoIP
	Action    string `json:"action"`    // log or block, draft only
	Etag      string `json:"etag"`
	RequestID string `json:"request_id"`
}
type EventRuleDraft struct {
	PolicyID      string `json:"policy_id"`
	PolicyVersion int    `json:"policy_version"`
	Etag          string `json:"etag"`
	State         string `json:"state"`
	ReplayURL     string `json:"replay_url"`
}

func (s *Server) handleEventRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(405)
		return
	}
	var req EventRuleRequest
	if !appBody(w, r, &req) {
		return
	}
	if (req.Dimension != "country" && req.Dimension != "asn") || (req.Action != "log" && req.Action != "block") || req.Etag == "" || len(req.Etag) > 128 || req.RequestID == "" || len(req.RequestID) > 128 {
		writeError(w, 400, "country/asn, draft action, etag and request_id required", "")
		return
	}
	command, err := json.Marshal(req)
	if err != nil {
		investigationError(w, err)
		return
	}
	a := investigationAudit(r, req.RequestID, r.URL.Path)
	p := auth.FromContext(r.Context())
	st := s.cfg.Applications
	// Return a committed result even if the original event has aged out. Recheck
	// current policy authorization before disclosing the durable reply.
	draft, err := st.GetPolicyReplayEditResult(r.Context(), req.Etag, command, a)
	if err == nil {
		if !p.CanResource("policies/"+draft.ID, auth.PermPoliciesWrite) {
			writeError(w, 403, "policy outside assigned scope", "")
			return
		}
		writeJSON(w, 200, eventRuleReply(draft))
		return
	}
	if !errors.Is(err, store.ErrNotFound) {
		investigationError(w, err)
		return
	}
	if s.cfg.ReplayKick == nil {
		writeError(w, 503, "replay runner not configured", "")
		return
	}
	e, ok := s.investigationEvent(w, r, ":propose-rule")
	if !ok {
		return
	}
	if e.GeoIPVersion == "" || req.Dimension == "country" && !isCountryCode(e.CountryISO) || req.Dimension == "asn" && e.ASN == 0 {
		writeError(w, 409, "event lacks verified GeoIP evidence", "")
		return
	}
	before, err := st.GetPolicyByName(r.Context(), e.PolicyID)
	if err != nil {
		investigationError(w, err)
		return
	}
	if !p.CanResource("policies/"+before.ID, auth.PermPoliciesWrite) {
		writeError(w, 403, "policy outside assigned write scope", "")
		return
	}
	draft, err = st.EditGeoPolicyAndReplayOnce(r.Context(), before.ID, req.Etag, command, a, func(locked store.Policy, id uint32) (json.RawMessage, error) {
		spec, err := policy.Parse(locked.Spec)
		if err != nil {
			return nil, err
		}
		rule := policy.GeoRule{ID: id, Action: req.Action}
		if req.Dimension == "country" {
			rule.Countries = []string{e.CountryISO}
		} else {
			rule.ASNs = []uint32{e.ASN}
		}
		spec.GeoRules = append(spec.GeoRules, rule)
		if err := spec.Validate(); err != nil {
			return nil, fmt.Errorf("investigation: invalid geo draft: %w", err)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(locked.Spec, &fields); err != nil {
			return nil, err
		}
		fields["geo_rules"], err = json.Marshal(spec.GeoRules)
		if err != nil {
			return nil, err
		}
		return json.Marshal(fields)
	})
	if err != nil {
		investigationError(w, err)
		return
	}
	s.cfg.ReplayKick()
	writeJSON(w, 200, eventRuleReply(draft))
}
func eventRuleReply(v store.Policy) EventRuleDraft {
	return EventRuleDraft{v.ID, v.CurrentVersion, v.Etag, store.VersionDraft, fmt.Sprintf("/v1/policies/%s/versions/%d/replay", v.ID, v.CurrentVersion)}
}
