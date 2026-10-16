package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/strata/strata/control-plane/auth"
	"github.com/strata/strata/control-plane/ingest"
	"github.com/strata/strata/control-plane/store"
)

// EventAnnotationStore keeps classifications separate from original events.
type EventAnnotationStore interface {
	MarkEventFalsePositive(context.Context, string, string, string, store.Audit) (store.EventAnnotation, error)
	EventAnnotations(context.Context, []string) (map[string]store.EventAnnotation, error)
}

type MarkFalsePositiveRequest struct {
	Reason    string `json:"reason"`
	RequestID string `json:"request_id,omitempty"`
	Etag      string `json:"etag,omitempty"`
}

type MarkFalsePositiveResponse struct {
	BlockID       string    `json:"block_id"`
	FalsePositive bool      `json:"false_positive"`
	Reason        string    `json:"reason"`
	MarkedBy      string    `json:"marked_by"`
	MarkedAt      time.Time `json:"marked_at"`
	Etag          string    `json:"etag"`
}

func (h *EventHandler) HandleMarkFalsePositive(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, 405, "method not allowed", "")
		return
	}
	block := strings.ToUpper(strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/events/"), ":markFalsePositive"))
	if err := ingest.ValidateBlockID(block); err != nil {
		writeError(w, 400, "invalid block_id", block)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var req MarkFalsePositiveRequest
	if err := dec.Decode(&req); err != nil {
		writeError(w, 400, "invalid annotation JSON", block)
		return
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		writeError(w, 400, "one JSON object required", block)
		return
	}
	req.Reason = strings.TrimSpace(req.Reason)
	if req.Reason == "" || len(req.Reason) > 500 || len(req.RequestID) > 128 {
		writeError(w, 400, "reason or request_id invalid", block)
		return
	}
	caller := auth.FromContext(r.Context())
	if caller.Subject == "" {
		writeError(w, 401, "authenticated subject required", block)
		return
	}
	if h.annotations == nil {
		writeError(w, 503, "durable annotations not configured", block)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if _, err := h.store.GetEvent(ctx, block); err != nil {
		if errors.Is(err, ingest.ErrEventNotFound) {
			writeError(w, 404, "event not found", block)
		} else {
			writeError(w, 503, "events unavailable", block)
		}
		return
	}
	actor := caller.Name
	if actor == "" {
		actor = caller.Subject
	}
	a, err := h.annotations.MarkEventFalsePositive(ctx, block, req.Reason, req.Etag, store.Audit{Actor: actor, Subject: caller.Subject, Action: "events.markFalsePositive", Resource: "events/" + block, RequestID: req.RequestID})
	if err != nil {
		switch {
		case errors.Is(err, store.ErrEtagMismatch):
			writeError(w, 409, "annotation changed; reload its etag", block)
		case errors.Is(err, store.ErrRequestReused):
			writeError(w, 400, "request_id reused with different content", block)
		default:
			writeError(w, 503, "annotation could not be persisted", block)
		}
		return
	}
	writeJSON(w, 200, MarkFalsePositiveResponse{BlockID: a.BlockID, FalsePositive: true, Reason: a.Reason, MarkedBy: a.MarkedBy, MarkedAt: a.MarkedAt, Etag: a.Etag})
}

func (h *EventHandler) overlayAnnotations(ctx context.Context, events []*ingest.Event) error {
	// Never trust annotation fields ingested from an agent.
	blocks := make([]string, len(events))
	for i, e := range events {
		blocks[i] = e.BlockID
		e.FalsePositive = false
		e.FalsePositiveReason = ""
		e.FalsePositiveBy = ""
		e.FalsePositiveAt = nil
		e.AnnotationEtag = ""
	}
	if h.annotations == nil {
		return nil
	}
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	annotations, err := h.annotations.EventAnnotations(bounded, blocks)
	if err != nil {
		return err
	}
	for _, e := range events {
		if a, ok := annotations[e.BlockID]; ok {
			e.FalsePositive = true
			e.FalsePositiveReason = a.Reason
			e.FalsePositiveBy = a.MarkedBy
			e.FalsePositiveAt = &a.MarkedAt
			e.AnnotationEtag = a.Etag
		}
	}
	return nil
}
