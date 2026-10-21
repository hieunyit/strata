package api

import (
	"encoding/json"
	"errors"
	"github.com/strata/strata/control-plane/rulecat"
	"log"
	"net/http"
	"slices"
	"strings"

	"github.com/strata/strata/control-plane/auth"
	"github.com/strata/strata/control-plane/ingest"
)

// EventHandler handles security event inspection and search HTTP endpoints.
type EventHandler struct {
	authenticate auth.Authenticator
	annotations  EventAnnotationStore

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

// eventsUnavailable answers a failed event store query: 503, so that no
// client mistakes it for "no events".
func eventsUnavailable(w http.ResponseWriter, blockID string) {
	writeJSON(w, http.StatusServiceUnavailable, ErrorResponse{
		Error: "event data unavailable", BlockID: blockID, Code: http.StatusServiceUnavailable, Reason: ReasonEventsUnavailable,
	})
}

func sanitizeEvent(e ingest.Event, p *auth.Principal) ingest.Event { return ingest.SanitizeEvent(e, p) }

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
		eventsUnavailable(w, blockID)
		return
	}

	if err := h.overlayAnnotations(r.Context(), []*ingest.Event{event}); err != nil {
		writeError(w, http.StatusServiceUnavailable, "annotations unavailable", blockID)
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

	switch {
	case req.Country != "" && req.Country != "INTERNAL" && !isCountryCode(req.Country):
		writeError(w, http.StatusBadRequest, "country: an ISO 3166 alpha-2 code or INTERNAL", "")
		return
	case req.AttackType != "" && !slices.Contains(ingest.AttackTypes, req.AttackType):
		writeError(w, http.StatusBadRequest, "attack_type: unknown", "")
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
		HTTPHost:   req.HTTPHost, HTTPPath: req.HTTPPath,
		CountryISO: req.Country,
		ASN:        req.ASN,
		AttackType: req.AttackType,
		Limit:      pageSize,
		Offset:     offset,
	}

	res, err := h.store.SearchEvents(r.Context(), filter)
	if err != nil {
		log.Printf("[ERROR] failed to search events: %v", err)
		eventsUnavailable(w, "")
		return
	}

	var nextToken string
	if offset+len(res.Events) < int(res.Total) {
		nextToken = EncodePageToken(offset + len(res.Events))
	}

	refs := make([]*ingest.Event, len(res.Events))
	for i := range res.Events {
		refs[i] = &res.Events[i]
	}
	if err := h.overlayAnnotations(r.Context(), refs); err != nil {
		writeError(w, http.StatusServiceUnavailable, "annotations unavailable", "")
		return
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
