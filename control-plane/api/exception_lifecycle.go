package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/strata/strata/control-plane/auth"
	"github.com/strata/strata/control-plane/policy"
	"github.com/strata/strata/control-plane/ruleinventory"
	"github.com/strata/strata/control-plane/store"
)

type ExceptionLifecycleRequest struct {
	ApplicationID string `json:"application_id"`
	EnvironmentID string `json:"environment_id"`
	PolicyID      string `json:"policy_id"`
	ExceptionID   string `json:"exception_id,omitempty"`
	Etag          string `json:"etag"`
	RequestID     string `json:"request_id"`
}

func (s *Server) exceptionLifecycleDraft(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(405)
		return
	}
	var req ExceptionLifecycleRequest
	if !appBody(w, r, &req) {
		return
	}
	if req.PolicyID == "" || len(req.PolicyID) > 128 || req.Etag == "" || len(req.Etag) > 128 || req.RequestID == "" || len(req.RequestID) > 128 || len(req.ExceptionID) > 64 {
		writeError(w, 400, "bounded policy, etag and request_id required", "")
		return
	}
	a, err := ruleinventory.Application(r.Context(), s.cfg.Applications, req.ApplicationID, req.EnvironmentID)
	if err != nil {
		investigationError(w, err)
		return
	}
	found := false
	for _, route := range a.Routes {
		if route.EnvironmentID == req.EnvironmentID && route.PolicyID == req.PolicyID {
			found = true
		}
	}
	caller := auth.FromContext(r.Context())
	if !found || !caller.CanResource("policies/"+req.PolicyID, auth.PermExceptionsWrite) {
		writeError(w, 403, "policy outside assigned write scope", "")
		return
	}
	command, err := json.Marshal(req)
	if err != nil {
		investigationError(w, err)
		return
	}
	audit := investigationAudit(r, req.RequestID, "policies/"+req.PolicyID)
	draft, err := s.cfg.Applications.GetPolicyReplayEditResult(r.Context(), req.Etag, command, audit)
	if err == nil {
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
	revoke := strings.HasSuffix(r.URL.Path, ":revoke")
	draft, err = s.cfg.Applications.EditPolicyAndReplayOnce(r.Context(), req.PolicyID, req.Etag, command, audit, func(before store.Policy) (json.RawMessage, error) {
		spec, err := policy.Parse(before.Spec)
		if err != nil {
			return nil, err
		}
		keep := []policy.Exception{}
		removed := false
		now := time.Now().UnixMilli()
		for _, e := range spec.Exceptions {
			remove := !revoke && e.ExpiresUnixMS <= now || revoke && e.ID == req.ExceptionID
			if remove {
				removed = true
			} else {
				keep = append(keep, e)
			}
		}
		if !removed {
			return nil, fmt.Errorf("investigation: no matching exception to remove")
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(before.Spec, &fields); err != nil {
			return nil, err
		}
		if len(keep) == 0 {
			delete(fields, "exceptions")
		} else {
			fields["exceptions"], err = json.Marshal(keep)
			if err != nil {
				return nil, err
			}
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
