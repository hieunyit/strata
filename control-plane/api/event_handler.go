package api

import (
	"encoding/json"
	"errors"
	"github.com/strata/strata/control-plane/rulecat"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/strata/strata/control-plane/auth"
	"github.com/strata/strata/control-plane/ingest"
)

// EventHandler handles security event inspection and search HTTP endpoints.
type EventHandler struct {
	store ingest.EventStore
	rules *rulecat.Catalog
}

// NewEventHandler creates an EventHandler with the provided EventStore and
// rule catalog (nil: events come without rule metadata).
func NewEventHandler(store ingest.EventStore, rules *rulecat.Catalog) *EventHandler {
	return &EventHandler{store: store, rules: rules}
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
	// RV-G2-01 context: header names and the User-Agent stay, values and
	// the Referer (it may carry personal data in its query) do not
	if e.Referer != "" {
		e.Referer = "[REDACTED]"
	}
	if len(e.Headers) > 0 {
		hs := make([]ingest.Header, len(e.Headers))
		for i, h := range e.Headers {
			hs[i] = ingest.Header{Name: h.Name, Value: "[REDACTED]"}
		}
		e.Headers = hs
	}
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

	ids := append([]uint32(nil), sanitized.MatchedRules...)
	for _, v := range sanitized.Violations {
		ids = append(ids, v.RuleID)
	}
	writeJSON(w, http.StatusOK, GetEventResponse{
		Event: sanitized,
		Rules: h.rules.For(ids),
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

// HandleMarkFalsePositive handles POST /v1/events/{block_id}:markFalsePositive.
func (h *EventHandler) HandleMarkFalsePositive(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed", "")
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/v1/events/")
	path = strings.TrimSuffix(path, ":markFalsePositive")
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

	var req MarkFalsePositiveRequest
	if r.Body != nil && r.ContentLength > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10) // 64 KB limit
		_ = json.NewDecoder(r.Body).Decode(&req)
	}

	reason := strings.TrimSpace(req.Reason)
	if len(reason) > 500 {
		writeError(w, http.StatusBadRequest, "reason cannot exceed 500 characters", blockID)
		return
	}

	caller := auth.FromContext(r.Context())
	actor := caller.Name
	if actor == "" {
		actor = caller.Subject
	}
	if actor == "" {
		actor = "unknown"
	}

	if err := h.store.MarkFalsePositive(r.Context(), blockID, reason); err != nil {
		if errors.Is(err, ingest.ErrEventNotFound) {
			writeError(w, http.StatusNotFound, "event not found", blockID)
			return
		}
		log.Printf("[ERROR] failed to mark false positive for event %s: %v", blockID, err)
		writeError(w, http.StatusInternalServerError, "internal server error", blockID)
		return
	}

	writeJSON(w, http.StatusOK, MarkFalsePositiveResponse{
		BlockID:       blockID,
		FalsePositive: true,
		Reason:        reason,
		MarkedBy:      actor,
		MarkedAt:      time.Now().UTC(),
	})
}

