package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/strata/strata/control-plane/auth"
	"github.com/strata/strata/control-plane/ingest"
)

var (
	ErrExceptionNotFound = errors.New("exception not found")
	ErrExceptionConflict = errors.New("active exception already exists for this rule and field")
)

// ExceptionStore abstracts storage for rule exceptions.
type ExceptionStore interface {
	CreateException(ctx context.Context, exp Exception) (Exception, error)
	GetException(ctx context.Context, id string) (Exception, error)
	ListExceptions(ctx context.Context, policyID string, ruleID uint32, state string) ([]Exception, error)
	ApproveException(ctx context.Context, id string, approver string) (Exception, error)
	DeleteException(ctx context.Context, id string) error
}

// MemExceptionStore is an in-memory thread-safe implementation of ExceptionStore.
type MemExceptionStore struct {
	mu         sync.RWMutex
	exceptions map[string]Exception
	order      []string
}

// NewMemExceptionStore creates an empty MemExceptionStore.
func NewMemExceptionStore() *MemExceptionStore {
	return &MemExceptionStore{
		exceptions: make(map[string]Exception),
		order:      make([]string, 0),
	}
}

func (s *MemExceptionStore) CreateException(ctx context.Context, exp Exception) (Exception, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Idempotency: check if an identical active exception exists
	for _, existing := range s.exceptions {
		if existing.PolicyID == exp.PolicyID &&
			existing.RuleID == exp.RuleID &&
			existing.Field == exp.Field &&
			(existing.State == "SUBMITTED" || existing.State == "APPROVED") &&
			existing.ExpiresAt.After(time.Now()) {
			return existing, nil
		}
	}

	s.exceptions[exp.ID] = exp
	s.order = append(s.order, exp.ID)
	return exp, nil
}

func (s *MemExceptionStore) GetException(ctx context.Context, id string) (Exception, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	exp, ok := s.exceptions[id]
	if !ok {
		return Exception{}, ErrExceptionNotFound
	}
	return exp, nil
}

func (s *MemExceptionStore) ListExceptions(ctx context.Context, policyID string, ruleID uint32, state string) ([]Exception, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]Exception, 0, len(s.order))
	now := time.Now()
	for _, id := range s.order {
		e := s.exceptions[id]
		if policyID != "" && e.PolicyID != policyID {
			continue
		}
		if ruleID > 0 && e.RuleID != ruleID {
			continue
		}
		if state != "" && e.State != state {
			continue
		}
		// Auto-mark expired in display
		if (e.State == "SUBMITTED" || e.State == "APPROVED") && now.After(e.ExpiresAt) {
			e.State = "EXPIRED"
		}
		out = append(out, e)
	}
	return out, nil
}

func (s *MemExceptionStore) ApproveException(ctx context.Context, id string, approver string) (Exception, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	exp, ok := s.exceptions[id]
	if !ok {
		return Exception{}, ErrExceptionNotFound
	}
	exp.State = "APPROVED"
	exp.ApprovedBy = approver
	s.exceptions[id] = exp
	return exp, nil
}

func (s *MemExceptionStore) DeleteException(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	exp, ok := s.exceptions[id]
	if !ok {
		return ErrExceptionNotFound
	}
	exp.State = "REVOKED"
	s.exceptions[id] = exp
	return nil
}

// ExceptionHandler handles HTTP endpoints for exception lifecycle.
type ExceptionHandler struct {
	events ingest.EventStore
	store  ExceptionStore
}

// NewExceptionHandler initializes an ExceptionHandler.
func NewExceptionHandler(events ingest.EventStore, store ExceptionStore) *ExceptionHandler {
	if store == nil {
		store = NewMemExceptionStore()
	}
	return &ExceptionHandler{events: events, store: store}
}

func newExceptionID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return "exp-" + hex.EncodeToString(b[:])
}

// HandleCreateFromBlockID handles POST /v1/exceptions:fromBlockId.
func (h *ExceptionHandler) HandleCreateFromBlockID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed", "")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 64<<10) // 64 KB limit
	var req CreateExceptionFromBlockIDRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json request body: "+err.Error(), "")
		return
	}

	blockID := strings.TrimSpace(strings.ToUpper(req.BlockID))
	if err := ingest.ValidateBlockID(blockID); err != nil {
		writeError(w, http.StatusBadRequest, "invalid block_id format: "+err.Error(), blockID)
		return
	}

	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		writeError(w, http.StatusBadRequest, "reason is required", blockID)
		return
	}
	if len(reason) > 500 {
		writeError(w, http.StatusBadRequest, "reason cannot exceed 500 characters", blockID)
		return
	}

	// Validate TTL (60s to 30 days)
	ttl := req.TTLSeconds
	if ttl <= 0 {
		ttl = 14 * 86400 // Default 14 days
	}
	if ttl < 60 {
		writeError(w, http.StatusBadRequest, "ttl_seconds must be at least 60 seconds", blockID)
		return
	}
	if ttl > 30*86400 {
		writeError(w, http.StatusBadRequest, "ttl_seconds cannot exceed 30 days (2592000 seconds)", blockID)
		return
	}

	// Fetch event to inspect findings and extract narrowest scope
	event, err := h.events.GetEvent(r.Context(), blockID)
	if err != nil {
		if errors.Is(err, ingest.ErrEventNotFound) {
			writeError(w, http.StatusNotFound, "event not found", blockID)
			return
		}
		log.Printf("[ERROR] failed to lookup event %s for exception: %v", blockID, err)
		writeError(w, http.StatusInternalServerError, "internal server error", blockID)
		return
	}

	// Extract narrowest scope: route/policy + rule_id + field
	policyID := strings.TrimSpace(event.PolicyID)
	if policyID == "" {
		policyID = "default"
	}

	var ruleID uint32
	var field string

	if len(event.Violations) > 0 {
		ruleID = event.Violations[0].RuleID
		field = event.Violations[0].Field
	} else if len(event.MatchedRules) > 0 {
		ruleID = event.MatchedRules[0]
	}

	if ruleID == 0 {
		writeError(w, http.StatusBadRequest, "event has no matched rules or violations to except", blockID)
		return
	}

	if field == "" {
		field = "*"
	}

	caller := auth.FromContext(r.Context())
	creator := caller.Subject
	if creator == "" {
		creator = caller.Name
	}
	if creator == "" {
		creator = "unknown"
	}

	now := time.Now().UTC()
	exp := Exception{
		ID:        newExceptionID(),
		BlockID:   blockID,
		PolicyID:  policyID,
		RuleID:    ruleID,
		Field:     field,
		Reason:    reason,
		State:     "SUBMITTED",
		CreatedBy: creator,
		CreatedAt: now,
		ExpiresAt: now.Add(time.Duration(ttl) * time.Second),
	}

	created, err := h.store.CreateException(r.Context(), exp)
	if err != nil {
		log.Printf("[ERROR] failed to save exception: %v", err)
		writeError(w, http.StatusInternalServerError, "failed to create exception", blockID)
		return
	}

	writeJSON(w, http.StatusCreated, created)
}

// HandleListExceptions handles GET /v1/exceptions.
func (h *ExceptionHandler) HandleListExceptions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed", "")
		return
	}

	query := r.URL.Query()
	policyID := query.Get("policy_id")
	state := query.Get("state")
	var ruleID uint32
	if rStr := query.Get("rule_id"); rStr != "" {
		if parsed, err := strconv.ParseUint(rStr, 10, 32); err == nil {
			ruleID = uint32(parsed)
		}
	}

	list, err := h.store.ListExceptions(r.Context(), policyID, ruleID, state)
	if err != nil {
		log.Printf("[ERROR] failed to list exceptions: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error", "")
		return
	}

	writeJSON(w, http.StatusOK, ListExceptionsResponse{Exceptions: list})
}

// HandleGetException handles GET /v1/exceptions/{id}.
func (h *ExceptionHandler) HandleGetException(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed", "")
		return
	}

	id := strings.TrimPrefix(r.URL.Path, "/v1/exceptions/")
	id = strings.TrimSpace(id)
	if id == "" {
		writeError(w, http.StatusBadRequest, "exception id required", "")
		return
	}

	exp, err := h.store.GetException(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrExceptionNotFound) {
			writeError(w, http.StatusNotFound, "exception not found", "")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal server error", "")
		return
	}

	writeJSON(w, http.StatusOK, exp)
}

// HandleApproveException handles POST /v1/exceptions/{id}:approve.
func (h *ExceptionHandler) HandleApproveException(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed", "")
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/v1/exceptions/")
	id := strings.TrimSuffix(path, ":approve")
	id = strings.TrimSpace(id)
	if id == "" {
		writeError(w, http.StatusBadRequest, "exception id required", "")
		return
	}

	exp, err := h.store.GetException(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrExceptionNotFound) {
			writeError(w, http.StatusNotFound, "exception not found", "")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal server error", "")
		return
	}

	// 4-Eyes rule: whoever created the exception cannot approve it
	caller := auth.FromContext(r.Context())
	approver := caller.Subject
	if approver == "" {
		approver = caller.Name
	}

	if approver != "" && (approver == exp.CreatedBy || (caller.Name != "" && caller.Name == exp.CreatedBy)) {
		writeError(w, http.StatusForbidden, "four-eyes rule: the creator of an exception cannot approve it", exp.BlockID)
		return
	}

	if exp.State != "SUBMITTED" {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("cannot approve exception in %s state", exp.State), exp.BlockID)
		return
	}

	if time.Now().After(exp.ExpiresAt) {
		writeError(w, http.StatusBadRequest, "cannot approve expired exception", exp.BlockID)
		return
	}

	approved, err := h.store.ApproveException(r.Context(), id, approver)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to approve exception", exp.BlockID)
		return
	}

	writeJSON(w, http.StatusOK, ApproveExceptionResponse{Exception: approved})
}

// HandleDeleteException handles DELETE /v1/exceptions/{id}.
func (h *ExceptionHandler) HandleDeleteException(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed", "")
		return
	}

	id := strings.TrimPrefix(r.URL.Path, "/v1/exceptions/")
	id = strings.TrimSpace(id)
	if id == "" {
		writeError(w, http.StatusBadRequest, "exception id required", "")
		return
	}

	if err := h.store.DeleteException(r.Context(), id); err != nil {
		if errors.Is(err, ErrExceptionNotFound) {
			writeError(w, http.StatusNotFound, "exception not found", "")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal server error", "")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
