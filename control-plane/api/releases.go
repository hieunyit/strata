package api

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/strata/strata/control-plane/auth"
	"github.com/strata/strata/control-plane/policy"
	"github.com/strata/strata/control-plane/store"
)

func releaseError(w http.ResponseWriter, err error) {
	code := 503
	message := "release service unavailable"
	reason := ""
	switch {
	case errors.Is(err, store.ErrIncompatible):
		code = 412
		message = err.Error()
		reason = "NODES_INCOMPATIBLE"
	case errors.Is(err, store.ErrNotFound):
		code = 404
		message = "release not found"
	case errors.Is(err, store.ErrFourEyes):
		code = 403
		message = "independent reviewer required"
	case errors.Is(err, store.ErrEtagMismatch), errors.Is(err, store.ErrApplicationConflict), errors.Is(err, store.ErrReleaseState), errors.Is(err, store.ErrReleaseBaseline):
		code = 409
		message = err.Error()
	default:
		var proof *policy.ReplayError
		if errors.As(err, &proof) {
			code = 412
			message = proof.Error()
			reason = "REPLAY_REQUIRED"
		} else if strings.HasPrefix(err.Error(), "release: invalid") {
			code = 400
			message = "invalid release request"
		}
	}
	writeJSON(w, code, ErrorResponse{Error: message, Code: code, Reason: reason})
}
func registerReleases(mux *http.ServeMux, service *policy.Releases) {
	authorized := func(w http.ResponseWriter, r *http.Request, perm auth.Permission) bool {
		p := auth.FromContext(r.Context())
		if p == nil || p.Access != nil || !p.Can(perm) {
			writeJSON(w, 403, ErrorResponse{Error: "global release permission required", Code: 403})
			return false
		}
		return true
	}
	mux.HandleFunc("/v1/releases", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			if !authorized(w, r, auth.PermPoliciesRead) {
				return
			}
			items, err := service.Store.ListReleases(r.Context(), r.URL.Query().Get("after"))
			if err != nil {
				releaseError(w, err)
				return
			}
			if items == nil {
				items = []store.Release{}
			}
			next := ""
			if len(items) == 100 {
				next = items[len(items)-1].ID
			}
			writeJSON(w, 200, map[string]any{"releases": items, "next_cursor": next})
		case http.MethodPost:
			if !authorized(w, r, auth.PermPoliciesWrite) {
				return
			}
			var req struct {
				RequestID string `json:"request_id"`
				Source    string `json:"source_release"`
			}
			if !appBody(w, r, &req) {
				return
			}
			if req.RequestID == "" || len(req.Source) > 63 {
				writeJSON(w, 400, ErrorResponse{Error: "invalid release request", Code: 400})
				return
			}
			out, err := service.Create(r.Context(), req.RequestID, req.Source, applicationAudit(r))
			if err != nil {
				releaseError(w, err)
				return
			}
			writeJSON(w, 201, map[string]any{"release": out})
		default:
			w.WriteHeader(405)
		}
	})
	mux.HandleFunc("/v1/releases/", func(w http.ResponseWriter, r *http.Request) {
		id, action, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/v1/releases/"), ":")
		if strings.ContainsAny(id, "/\\") || id == "" {
			http.NotFound(w, r)
			return
		}
		if r.Method == http.MethodGet && action == "" {
			if !authorized(w, r, auth.PermPoliciesRead) {
				return
			}
			out, err := service.Store.GetRelease(r.Context(), id)
			if err != nil {
				releaseError(w, err)
				return
			}
			current, err := service.Store.LatestBundle(r.Context())
			if err != nil && !errors.Is(err, store.ErrNotFound) {
				releaseError(w, err)
				return
			}
			var rollout *store.Rollout
			if out.RolloutID != 0 {
				ro, err := service.Store.GetRollout(r.Context(), out.RolloutID)
				if err != nil {
					releaseError(w, err)
					return
				}
				rollout = &ro
			}
			warning := out.Snapshot.Baseline != current.Version || out.SourceRelease != "" || out.Snapshot.ReplayBaselineMismatch
			writeJSON(w, 200, map[string]any{"release": out, "rollout": rollout, "current_baseline": strconv.FormatUint(current.Version, 10), "baseline_warning": warning})
			return
		}
		if r.Method != http.MethodPost {
			w.WriteHeader(405)
			return
		}
		perm := auth.PermPoliciesApprove
		if action == "deploy" {
			perm = auth.PermPoliciesDeploy
		} else if action != "approve" && action != "reject" {
			http.NotFound(w, r)
			return
		}
		if !authorized(w, r, perm) {
			return
		}
		var req struct {
			Etag         string            `json:"etag"`
			SnapshotHash string            `json:"snapshot_hash"`
			ReplayIDs    map[string]string `json:"replay_ids"`
			AckBaseline  *string           `json:"ack_baseline"`
		}
		if !appBody(w, r, &req) {
			return
		}
		var out store.Release
		var err error
		if action == "deploy" {
			var ack *uint64
			if req.AckBaseline != nil {
				v, e := strconv.ParseUint(*req.AckBaseline, 10, 63)
				if e != nil {
					writeJSON(w, 400, ErrorResponse{Error: "invalid baseline", Code: 400})
					return
				}
				ack = &v
			}
			out, err = service.Deploy(r.Context(), id, req.Etag, ack, applicationAudit(r))
		} else {
			out, err = service.Store.ReviewRelease(r.Context(), id, req.Etag, req.SnapshotHash, req.ReplayIDs, action == "approve", applicationAudit(r))
		}
		if err != nil {
			releaseError(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"release": out})
	})
}
