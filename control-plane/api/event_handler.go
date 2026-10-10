package api

import (
	"encoding/json"
	"errors"
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
		writeError(w, http.StatusInternalServerError, "failed to query event: "+err.Error(), blockID)
		return
	}

	writeJSON(w, http.StatusOK, GetEventResponse{
		Event: *event,
	})
}

// HandleSearchEvents handles POST /v1/events:search.
func (h *EventHandler) HandleSearchEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed", "")
		return
	}

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
		writeError(w, http.StatusInternalServerError, "failed to search events: "+err.Error(), "")
		return
	}

	var nextToken string
	if offset+len(res.Events) < int(res.Total) {
		nextToken = EncodePageToken(offset + len(res.Events))
	}

	events := res.Events
	if events == nil {
		events = []ingest.Event{}
	}

	writeJSON(w, http.StatusOK, SearchEventsResponse{
		Events:        events,
		NextPageToken: nextToken,
		TotalMatched:  res.Total,
	})
}
