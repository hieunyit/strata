package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/strata/strata/control-plane/auth"
	"github.com/strata/strata/control-plane/policy"
	"github.com/strata/strata/control-plane/store"
)

// QuickRulePolicyStore defines the store operations required for quick-rule policy management.
type QuickRulePolicyStore interface {
	GetPolicy(ctx context.Context, id string) (store.Policy, error)
	UpdatePolicy(ctx context.Context, id, etag string, spec json.RawMessage, a store.Audit) (store.Policy, error)
}

// QuickRuleHandler processes one-click rule generation from security events (W19-G2-01).
type QuickRuleHandler struct {
	store QuickRulePolicyStore
}

// NewQuickRuleHandler creates a new QuickRuleHandler.
func NewQuickRuleHandler(store QuickRulePolicyStore) *QuickRuleHandler {
	return &QuickRuleHandler{store: store}
}

// QuickRuleRequest defines parameters for generating a quick mitigation rule.
type QuickRuleRequest struct {
	Type   string `json:"type"`   // "geo", "asn", "geo_block", "asn_block"
	Target string `json:"target"` // Country ISO code or ASN string/int
	Action string `json:"action"` // "block" or "challenge"
	Reason string `json:"reason,omitempty"`
}

// QuickRuleResponse reports the resulting draft policy version.
type QuickRuleResponse struct {
	PolicyID string `json:"policy_id"`
	Version  int    `json:"version"`
	Etag     string `json:"etag"`
	Message  string `json:"message"`
}

// HandleQuickRule handles POST /v1/policies/{id}:quick-rule.
func (h *QuickRuleHandler) HandleQuickRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed", "")
		return
	}

	// Extract {id} from path: /v1/policies/{id}:quick-rule
	path := strings.TrimPrefix(r.URL.Path, "/v1/policies/")
	if !strings.HasSuffix(path, ":quick-rule") {
		writeError(w, http.StatusBadRequest, "invalid quick-rule path", "")
		return
	}
	policyID := strings.TrimSuffix(path, ":quick-rule")
	if !policy.IDPattern.MatchString(policyID) {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid policy id %q", policyID), "")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MB limit
	var req QuickRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json request body: "+err.Error(), "")
		return
	}

	action := strings.ToLower(strings.TrimSpace(req.Action))
	if action != "block" && action != "challenge" {
		writeError(w, http.StatusBadRequest, "action must be 'block' or 'challenge'", "")
		return
	}

	ruleType := strings.ToLower(strings.TrimSpace(req.Type))
	rawTarget := strings.TrimSpace(req.Target)
	if rawTarget == "" {
		writeError(w, http.StatusBadRequest, "target is required", "")
		return
	}

	var (
		isGeo      bool
		countryISO string
		asnVal     uint32
	)

	switch ruleType {
	case "geo", "geo_block", "country":
		isGeo = true
		countryISO = strings.ToUpper(rawTarget)
		if len(countryISO) != 2 || countryISO[0] < 'A' || countryISO[0] > 'Z' || countryISO[1] < 'A' || countryISO[1] > 'Z' {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid country ISO code %q (must be 2 uppercase letters)", countryISO), "")
			return
		}
	case "asn", "asn_block":
		isGeo = false
		cleanASN := strings.TrimPrefix(strings.ToUpper(rawTarget), "AS")
		parsed, err := strconv.ParseUint(cleanASN, 10, 32)
		if err != nil || parsed == 0 {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid ASN %q (must be a positive integer)", rawTarget), "")
			return
		}
		asnVal = uint32(parsed)
	default:
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unsupported rule type %q (use 'geo' or 'asn')", req.Type), "")
		return
	}

	// 1. Fetch existing policy
	p, err := h.store.GetPolicy(r.Context(), policyID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, fmt.Sprintf("policy %q not found", policyID), "")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to get policy: "+err.Error(), "")
		return
	}

	// 2. Parse current spec
	var spec policy.Spec
	if err := json.Unmarshal(p.Spec, &spec); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to parse current policy spec: "+err.Error(), "")
		return
	}

	// 3. Initialize or update geo_restrictions
	if spec.GeoRestrictions == nil {
		enabled := true
		spec.GeoRestrictions = &policy.GeoRestrictions{
			Enabled:       &enabled,
			DefaultAction: "pass",
		}
	} else {
		// Ensure geo restrictions are active when an operator creates a quick rule mitigation
		enabled := true
		spec.GeoRestrictions.Enabled = &enabled
		if spec.GeoRestrictions.DefaultAction == "" {
			spec.GeoRestrictions.DefaultAction = "pass"
		}
	}

	if isGeo {
		if action == "block" {
			spec.GeoRestrictions.BlockedCountries = addToSliceUnique(spec.GeoRestrictions.BlockedCountries, countryISO)
			spec.GeoRestrictions.ChallengedCountries = removeFromSlice(spec.GeoRestrictions.ChallengedCountries, countryISO)
		} else {
			spec.GeoRestrictions.ChallengedCountries = addToSliceUnique(spec.GeoRestrictions.ChallengedCountries, countryISO)
			spec.GeoRestrictions.BlockedCountries = removeFromSlice(spec.GeoRestrictions.BlockedCountries, countryISO)
		}
	} else {
		if action == "block" {
			spec.GeoRestrictions.BlockedASNs = addUint32Unique(spec.GeoRestrictions.BlockedASNs, asnVal)
			spec.GeoRestrictions.ChallengedASNs = removeUint32(spec.GeoRestrictions.ChallengedASNs, asnVal)
		} else {
			spec.GeoRestrictions.ChallengedASNs = addUint32Unique(spec.GeoRestrictions.ChallengedASNs, asnVal)
			spec.GeoRestrictions.BlockedASNs = removeUint32(spec.GeoRestrictions.BlockedASNs, asnVal)
		}
	}

	// 4. Validate updated spec
	if err := spec.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, "resulting policy spec is invalid: "+err.Error(), "")
		return
	}

	updatedSpecRaw, err := json.Marshal(spec)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to encode policy spec: "+err.Error(), "")
		return
	}

	// 5. Audit record & update policy (creates new DRAFT version)
	actor, subject := "system", "system"
	if caller := auth.FromContext(r.Context()); caller != nil {
		subject = caller.Subject
		actor = caller.Subject
		if caller.Name != "" {
			actor = caller.Name + " (" + caller.Subject + ")"
		}
	}

	channel := "api"
	if ch := r.Header.Get("Strata-Channel"); ch == "ui" || ch == "gitops" {
		channel = ch
	}

	reqID := r.Header.Get("X-Request-Id")
	if len(reqID) > 128 {
		reqID = reqID[:128]
	}

	actionDesc := "QuickRule"
	if reason := strings.TrimSpace(req.Reason); reason != "" {
		if len(reason) > 200 {
			reason = reason[:200]
		}
		actionDesc = fmt.Sprintf("QuickRule: %s (action=%s, target=%s)", reason, action, rawTarget)
	}

	audit := store.Audit{
		Actor:     actor,
		Subject:   subject,
		Channel:   channel,
		Action:    actionDesc,
		Resource:  "policies/" + policyID,
		RequestID: reqID,
		Before:    p,
	}

	updated, err := h.store.UpdatePolicy(r.Context(), policyID, p.Etag, updatedSpecRaw, audit)
	if err != nil {
		if errors.Is(err, store.ErrEtagMismatch) {
			writeError(w, http.StatusConflict, "policy was updated concurrently; please retry", "")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to save policy draft: "+err.Error(), "")
		return
	}

	writeJSON(w, http.StatusOK, QuickRuleResponse{
		PolicyID: updated.ID,
		Version:  updated.CurrentVersion,
		Etag:     updated.Etag,
		Message:  fmt.Sprintf("Quick rule created draft version %d for policy %s", updated.CurrentVersion, updated.ID),
	})
}

func addToSliceUnique(slice []string, val string) []string {
	for _, s := range slice {
		if s == val {
			return slice
		}
	}
	return append(slice, val)
}

func removeFromSlice(slice []string, val string) []string {
	out := make([]string, 0, len(slice))
	for _, s := range slice {
		if s != val {
			out = append(out, s)
		}
	}
	return out
}

func addUint32Unique(slice []uint32, val uint32) []uint32 {
	for _, v := range slice {
		if v == val {
			return slice
		}
	}
	return append(slice, val)
}

func removeUint32(slice []uint32, val uint32) []uint32 {
	out := make([]uint32, 0, len(slice))
	for _, v := range slice {
		if v != val {
			out = append(out, v)
		}
	}
	return out
}
