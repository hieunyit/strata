package localauth

import (
	"net/http"
	"strings"

	"github.com/strata/strata/control-plane/auth"
)

func (h *Handler) security(w http.ResponseWriter, r *http.Request) {
	name := LocalUsername(auth.FromContext(r.Context()))
	token := auth.TokenFromRequest(r)
	if name == "" || !strings.HasPrefix(token, TokenPrefix) {
		writeErr(w, 403, "local session required")
		return
	}
	path := r.URL.Path
	if r.Method == http.MethodGet {
		switch path {
		case "/v1/auth/mfa":
			state, err := h.Service.MFAStatus(r.Context(), name)
			if err != nil {
				fail(w, err)
				return
			}
			writeJSON(w, 200, state)
		case "/v1/auth/sessions":
			items, err := h.Service.Sessions(r.Context(), name, token)
			if err != nil {
				fail(w, err)
				return
			}
			writeJSON(w, 200, map[string]any{"sessions": items})
		default:
			writeErr(w, 404, "not found")
		}
		return
	}
	if r.Method != http.MethodPost {
		writeErr(w, 405, "method not allowed")
		return
	}
	var req struct {
		Password  string `json:"password"`
		Code      string `json:"code"`
		Recovery  bool   `json:"recovery"`
		Etag      string `json:"etag"`
		RequestID string `json:"request_id"`
	}
	if !decode(w, r, &req) {
		return
	}
	switch path {
	case "/v1/auth/mfa:begin":
		out, err := h.Service.BeginMFA(r.Context(), name, req.Password, token, req.RequestID)
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, 200, out)
	case "/v1/auth/mfa:confirm":
		codes, err := h.Service.ConfirmMFA(r.Context(), name, token, req.Etag, req.Code)
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"recovery_codes": codes})
	case "/v1/auth/mfa:disable", "/v1/auth/mfa:recovery":
		codes, err := h.Service.ChangeMFA(r.Context(), name, req.Password, token, req.Etag, req.Code, req.Recovery, strings.HasSuffix(path, ":disable"))
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"recovery_codes": codes})
	default:
		id, ok := strings.CutSuffix(strings.TrimPrefix(path, "/v1/auth/sessions/"), ":revoke")
		if !ok || !strings.HasPrefix(path, "/v1/auth/sessions/") {
			writeErr(w, 404, "not found")
			return
		}
		if err := h.Service.RevokeSession(r.Context(), name, id, req.Etag); err != nil {
			fail(w, err)
			return
		}
		w.WriteHeader(204)
	}
}
