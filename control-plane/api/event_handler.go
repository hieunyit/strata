package api

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"

	"github.com/strata/strata/control-plane/auth"
	"github.com/strata/strata/control-plane/ingest"
)

// EventHandler handles security event inspection and search HTTP endpoints.
type EventHandler struct {
	store ingest.EventStore
}

// NewEventHandler creates an EventHandler with the provided EventStore.
func NewEventHandler(store ingest.EventStore) *EventHandler {
	return &EventHandler{store: store}
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, message string, blockID string) {
	writeJSON(w, status, ErrorResponse{
		Error:   message,
		BlockID: blockID,
		Code:    status,
	})
}

func maskIP(ip string) string {
	if strings.Contains(ip, ".") {
		parts := strings.Split(ip, ".")
		if len(parts) == 4 {
			return parts[0] + "." + parts[1] + "." + parts[2] + ".0/24"
		}
	} else if strings.Contains(ip, ":") {
		parts := strings.Split(ip, ":")
		if len(parts) >= 3 {
			return parts[0] + ":" + parts[1] + ":" + parts[2] + "::/48"
		}
	}
	return "[REDACTED]"
}

// sanitizeEvent masks the full client IP and the input snippets unless the
// caller may read them (nginx-module.md › Giao diện quản trị: not for viewer).
func sanitizeEvent(e ingest.Event, p *auth.Principal) ingest.Event {
	if p.Can(auth.PermEventsReadSensitive) {
		return e
	}

	e.ClientIP = maskIP(e.ClientIP)
	maskedViolations := make([]ingest.Violation, len(e.Violations))
	for i, v := range e.Violations {
		v.Snippet = "[REDACTED]"
		maskedViolations[i] = v
	}
	e.Violations = maskedViolations
	return e
}

// HandleGetEvent handles GET /v1/events/{block_id}.
func (h *EventHandler) HandleGetEvent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed", "")
		return
	}

	// Extract block_id from path: /v1/events/{block_id}
	path := strings.TrimPrefix(r.URL.Path, "/v1/events/")
	blockID := strings.TrimSpace(path)
	if blockID == "" || strings.Contains(blockID, "/") {
		writeError(w, http.StatusBadRequest, "block_id path parameter is required", "")
		return
	}

	blockID = strings.ToUpper(blockID)
	if err := ingest.ValidateBlockID(blockID); err != nil {
		writeError(w, http.StatusBadRequest, "invalid block_id format: "+err.Error(), blockID)
		return
	}

	event, err := h.store.GetEvent(r.Context(), blockID)
	if err != nil {
		if errors.Is(err, ingest.ErrEventNotFound) {
			writeError(w, http.StatusNotFound, "event not found", blockID)
			return
		}
		log.Printf("[ERROR] failed to query event %s: %v", blockID, err)
		writeError(w, http.StatusInternalServerError, "internal server error", blockID)
		return
	}

	sanitized := sanitizeEvent(*event, auth.FromContext(r.Context()))

	writeJSON(w, http.StatusOK, GetEventResponse{
		Event: sanitized,
	})
}

// HandleSearchEvents handles POST /v1/events:search.
func (h *EventHandler) HandleSearchEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed", "")
		return
	}

	// Protect against unbounded request body
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MB limit

	var req SearchEventsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json request body: "+err.Error(), "")
		return
	}

	if !req.From.IsZero() && !req.To.IsZero() && req.From.After(req.To) {
		writeError(w, http.StatusBadRequest, "'from' timestamp must be before 'to' timestamp", "")
		return
	}

	pageSize := req.PageSize
	if pageSize <= 0 {
		pageSize = 50
	}
	if pageSize > 200 {
		pageSize = 200
	}

	offset, err := DecodePageToken(req.PageToken)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid page_token: "+err.Error(), "")
		return
	}

	filter := ingest.SearchFilter{
		From:       req.From,
		To:         req.To,
		PolicyID:   req.PolicyID,
		Action:     req.Action,
		ClientIP:   req.ClientIP,
		RuleID:     req.RuleID,
		NodeID:     req.NodeID,
		HTTPMethod: req.HTTPMethod,
		Limit:      pageSize,
		Offset:     offset,
	}

	res, err := h.store.SearchEvents(r.Context(), filter)
	if err != nil {
		log.Printf("[ERROR] failed to search events: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error", "")
		return
	}

	var nextToken string
	if offset+len(res.Events) < int(res.Total) {
		nextToken = EncodePageToken(offset + len(res.Events))
	}

	caller := auth.FromContext(r.Context())
	events := make([]ingest.Event, len(res.Events))
	for i, e := range res.Events {
		events[i] = sanitizeEvent(e, caller)
	}

	writeJSON(w, http.StatusOK, SearchEventsResponse{
		Events:        events,
		NextPageToken: nextToken,
		TotalMatched:  res.Total,
	})
}
