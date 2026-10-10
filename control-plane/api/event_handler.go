package api

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"

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

// sanitizeEventForRole masks sensitive fields (full IP and violation snippets)
// for viewer role and unauthenticated callers per AGENTS.md section 6.
func sanitizeEventForRole(e ingest.Event, role string) ingest.Event {
	// Privileged roles allowed full access to raw IPs and violation snippets
	if role == "admin" || role == "operator" || role == "approver" {
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

// callerRole returns the role of an authenticated caller. There is no
// authentication yet (W03-G2-01), so every caller is a viewer. Never read the
// role from a request header: the client chooses its value.
func callerRole(_ *http.Request) string {
	return "viewer"
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

	sanitized := sanitizeEventForRole(*event, callerRole(r))

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

	role := callerRole(r)
	events := make([]ingest.Event, len(res.Events))
	for i, e := range res.Events {
		events[i] = sanitizeEventForRole(e, role)
	}

	writeJSON(w, http.StatusOK, SearchEventsResponse{
		Events:        events,
		NextPageToken: nextToken,
		TotalMatched:  res.Total,
	})
}
