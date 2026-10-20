package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/strata/strata/control-plane/auth"
	"github.com/strata/strata/control-plane/ingest"
	"github.com/strata/strata/control-plane/policy"
	"github.com/strata/strata/control-plane/store"
)

// ExceptionPolicyStore persists drafts, request replies, replay and audit together.
type ExceptionPolicyStore interface {
	GetPolicyByName(context.Context, string) (store.Policy, error)
	GetPolicyReplayEditResult(context.Context, string, json.RawMessage, store.Audit) (store.Policy, error)
	EditPolicyAndReplayOnce(context.Context, string, string, json.RawMessage, store.Audit, func(store.Policy) (json.RawMessage, error)) (store.Policy, error)
}

type ExceptionFromBlockRequest struct {
	BlockID    string `json:"block_id"`
	RuleID     uint32 `json:"rule_id"`
	Field      string `json:"field"`
	Reason     string `json:"reason"`
	TTLSeconds int64  `json:"ttl_seconds"`
	Etag       string `json:"etag"`
	RequestID  string `json:"request_id"`
}

type ExceptionDraftResponse struct {
	Exception     policy.Exception `json:"exception"`
	PolicyID      string           `json:"policy_id"`
	PolicyVersion int              `json:"policy_version"`
	Etag          string           `json:"etag"`
	State         string           `json:"state"`
	ReplayURL     string           `json:"replay_url"`
}

var errExceptionScope = errors.New("exception scope does not match the stored event")
var errExceptionDuplicate = errors.New("active exception already exists for this scope")

// HandleExceptionFromBlock creates a draft; it never activates an exception.
func (s *Server) HandleExceptionFromBlock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, 405, "method not allowed", "")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var req ExceptionFromBlockRequest
	if err := dec.Decode(&req); err != nil {
		writeError(w, 400, "invalid exception JSON", "")
		return
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		writeError(w, 400, "one JSON object required", "")
		return
	}
	req.BlockID = strings.ToUpper(strings.TrimSpace(req.BlockID))
	req.Reason = strings.TrimSpace(req.Reason)
	if ingest.ValidateBlockID(req.BlockID) != nil || !strings.HasPrefix(req.BlockID, "STR-") || req.RuleID == 0 || req.Field == "" || len(req.Field) > 160 || !utf8.ValidString(req.Reason) || req.Reason == "" || len(req.Reason) > 500 || strings.ContainsRune(req.Reason, 0) || req.TTLSeconds < 60 || req.TTLSeconds > 30*24*3600 || req.Etag == "" || len(req.Etag) > 128 || req.RequestID == "" || len(req.RequestID) > 128 || !utf8.ValidString(req.RequestID) || strings.ContainsAny(req.RequestID, "\x00\r\n") {
		writeError(w, 400, "block_id, rule_id, field, etag, request_id and TTL 60..2592000 seconds required", req.BlockID)
		return
	}
	caller := auth.FromContext(r.Context())
	if caller.Subject == "" {
		writeError(w, 401, "authenticated subject required", req.BlockID)
		return
	}
	if s.cfg.Exceptions == nil {
		writeError(w, 503, "durable policy exceptions not configured", req.BlockID)
		return
	}
	actor := caller.Name
	if actor == "" {
		actor = caller.Subject
	}
	a := store.Audit{Actor: actor, Subject: caller.Subject, Channel: "api", Action: "exceptions.fromBlockId", Resource: "events/" + req.BlockID + ":exceptions", RequestID: req.RequestID}
	command, err := json.Marshal(req)
	if err != nil {
		writeError(w, 400, "invalid exception command", req.BlockID)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	cached, err := s.cfg.Exceptions.GetPolicyReplayEditResult(ctx, req.Etag, command, a)
	if err == nil {
		s.exceptionDraftReply(w, req, cached, caller.Subject)
		return
	}
	if !errors.Is(err, store.ErrNotFound) {
		exceptionWriteError(w, err, req.BlockID)
		return
	}
	if s.cfg.ReplayKick == nil {
		writeError(w, 503, "replay runner not configured", req.BlockID)
		return
	}
	event, err := s.handler.store.GetEvent(ctx, req.BlockID)
	if err != nil {
		if errors.Is(err, ingest.ErrEventNotFound) {
			writeError(w, 404, "event not found", req.BlockID)
		} else {
			eventsUnavailable(w, req.BlockID)
		}
		return
	}
	// Catalog membership is checked again by the compiler before signing.
	rule, ok := s.cfg.Rules.For([]uint32{req.RuleID})[strconv.FormatUint(uint64(req.RuleID), 10)]
	if !ok || rule.Layer != "managed" {
		writeError(w, 409, "rule is not in the managed rule catalog", req.BlockID)
		return
	}
	matched := false
	for _, v := range event.Violations {
		if v.RuleID == req.RuleID && v.Field == req.Field {
			matched = true
		}
	}
	// Event field text cannot distinguish a decoder alias from a literal name.
	// Never strip an alias suffix or infer a wider source field from this evidence.
	if !matched || strings.HasSuffix(req.Field, "|base64") || event.Action != "block" {
		writeError(w, 409, "select an unambiguous field recorded for this blocked rule", req.BlockID)
		return
	}
	p, err := s.cfg.Exceptions.GetPolicyByName(ctx, event.PolicyID)
	if err != nil {
		exceptionWriteError(w, err, req.BlockID)
		return
	}
	draft, err := s.cfg.Exceptions.EditPolicyAndReplayOnce(ctx, p.ID, req.Etag, command, a, func(before store.Policy) (json.RawMessage, error) {
		if before.Name != event.PolicyID {
			return nil, errExceptionScope
		}
		spec, err := policy.Parse(before.Spec)
		if err != nil {
			return nil, err
		}
		now := time.Now().UnixMilli()
		e := policy.Exception{ID: exceptionID(caller.Subject, req.RequestID), RuleID: req.RuleID, Method: event.HTTPMethod, Host: event.HTTPHost, Path: event.HTTPPath, Field: req.Field, ExpiresUnixMS: now + req.TTLSeconds*1000, Reason: req.Reason, SourceBlockID: req.BlockID}
		if err := e.Validate(); err != nil {
			return nil, fmt.Errorf("%w: %v", errExceptionScope, err)
		}
		for _, old := range spec.Exceptions {
			if old.ExpiresUnixMS > now && old.RuleID == e.RuleID && old.Method == e.Method && strings.EqualFold(old.Host, e.Host) && old.Path == e.Path && sameExceptionField(old.Field, e.Field) {
				return nil, errExceptionDuplicate
			}
		}
		spec.Exceptions = append(spec.Exceptions, e)
		if err := spec.Validate(); err != nil {
			return nil, fmt.Errorf("%w: %v", errExceptionScope, err)
		}
		// Preserve every stored setting, including future fields unknown to this server.
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(before.Spec, &fields); err != nil {
			return nil, err
		}
		fields["exceptions"], err = json.Marshal(spec.Exceptions)
		if err != nil {
			return nil, err
		}
		return json.Marshal(fields)
	})
	if err != nil {
		exceptionWriteError(w, err, req.BlockID)
		return
	}
	s.cfg.ReplayKick()
	s.exceptionDraftReply(w, req, draft, caller.Subject)
}

func exceptionID(subject, request string) string {
	raw, _ := json.Marshal([]string{"strata-exception/v1", subject, request})
	sum := sha256.Sum256(raw)
	return "exc-" + hex.EncodeToString(sum[:16])
}
func sameExceptionField(a, b string) bool {
	if strings.HasPrefix(a, "REQUEST_HEADERS:") && strings.HasPrefix(b, "REQUEST_HEADERS:") {
		return strings.EqualFold(a, b)
	}
	return a == b
}
func (s *Server) exceptionDraftReply(w http.ResponseWriter, req ExceptionFromBlockRequest, p store.Policy, subject string) {
	spec, err := policy.Parse(p.Spec)
	if err == nil {
		for _, e := range spec.Exceptions {
			if e.ID == exceptionID(subject, req.RequestID) {
				writeJSON(w, 200, ExceptionDraftResponse{Exception: e, PolicyID: p.ID, PolicyVersion: p.CurrentVersion, Etag: p.Etag, State: store.VersionDraft, ReplayURL: fmt.Sprintf("/v1/policies/%s/versions/%d/replay", p.ID, p.CurrentVersion)})
				return
			}
		}
	}
	writeError(w, 503, "persisted exception reply unavailable", req.BlockID)
}
func exceptionWriteError(w http.ResponseWriter, err error, block string) {
	switch {
	case errors.Is(err, store.ErrRequestReused):
		writeError(w, 409, "request_id reused with different content", block)
	case errors.Is(err, store.ErrEtagMismatch):
		writeError(w, 409, "policy changed; reload its etag", block)
	case errors.Is(err, store.ErrNotFound):
		writeError(w, 404, "policy not found", block)
	case errors.Is(err, errExceptionScope), errors.Is(err, errExceptionDuplicate):
		writeError(w, 409, err.Error(), block)
	default:
		writeError(w, 503, "exception draft could not be persisted", block)
	}
}
