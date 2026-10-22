package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/strata/strata/control-plane/auth"
	"github.com/strata/strata/control-plane/rulesets"
	"github.com/strata/strata/control-plane/store"
)

// RS-3c (docs/plan/rule-sets.md): rule sets made by operators, next to the
// built-in ones. A policy keeps a copy of a custom set's filter when it is
// saved (policy.RuleSetRef.Match): editing or deleting a set here changes
// no policy until the policy is saved, reviewed and deployed again.

// CustomRuleSetStore keeps the custom rule sets (store.Store).
type CustomRuleSetStore interface {
	ListCustomRuleSets(ctx context.Context) ([]store.CustomRuleSet, error)
	GetCustomRuleSet(ctx context.Context, name string) (store.CustomRuleSet, error)
	CreateCustomRuleSet(ctx context.Context, c store.CustomRuleSet, a store.Audit) (store.CustomRuleSet, error)
	UpdateCustomRuleSet(ctx context.Context, c store.CustomRuleSet, etag string, a store.Audit) (store.CustomRuleSet, error)
	DeleteCustomRuleSet(ctx context.Context, name, etag string, a store.Audit) error
}

// CustomRuleSetInput is the body of POST /v1/rule-sets and PUT
// /v1/rule-sets/{name}.
type CustomRuleSetInput struct {
	Name        string          `json:"name,omitempty"`
	Title       string          `json:"title"`
	Description string          `json:"description,omitempty"`
	Match       rulesets.Filter `json:"match"`
	// Etag: the version read, for PUT.
	Etag string `json:"etag,omitempty"`
}

// customSet: a custom set as the rule set functions take a set.
func customSet(c store.CustomRuleSet) rulesets.Set {
	return rulesets.Set{Name: c.Name, Group: "custom", Title: map[string]string{"vi": c.Title, "en": c.Title}, Match: c.Match}
}

// lookupSet: the built-in or custom set name; ok false when there is none.
func (s *Server) lookupSet(ctx context.Context, name string) (rulesets.Set, bool, error) {
	if set, ok := rulesets.Get(name); ok {
		return set, true, nil
	}
	if !rulesets.IsCustom(name) || s.cfg.CustomRuleSets == nil {
		return rulesets.Set{}, false, nil
	}
	c, err := s.cfg.CustomRuleSets.GetCustomRuleSet(ctx, name)
	if errors.Is(err, store.ErrNotFound) {
		return rulesets.Set{}, false, nil
	}
	if err != nil {
		return rulesets.Set{}, false, err
	}
	return customSet(c), true, nil
}

// customSetWriter: the caller may change custom sets (global objects:
// not for a principal scoped to applications); answers otherwise.
func customSetWriter(w http.ResponseWriter, r *http.Request) bool {
	p := auth.FromContext(r.Context())
	if !p.Can(auth.PermPoliciesWrite) || p.Access != nil {
		writeError(w, http.StatusForbidden, "permission denied: "+string(auth.PermPoliciesWrite), "")
		return false
	}
	return true
}

func customSetBody(w http.ResponseWriter, r *http.Request) (CustomRuleSetInput, bool) {
	var in CustomRuleSetInput
	r.Body = http.MaxBytesReader(w, r.Body, 128<<10)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil || dec.Decode(&struct{}{}) != io.EOF {
		writeError(w, http.StatusBadRequest, "invalid JSON", "")
		return in, false
	}
	return in, true
}

func customSetError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "rule set not found", "")
	case errors.Is(err, store.ErrCustomRuleSetConflict):
		writeError(w, http.StatusConflict, "the rule set changed or the name is taken: reload", "")
	case strings.HasPrefix(err.Error(), "custom rule set:"):
		writeError(w, http.StatusBadRequest, err.Error(), "")
	default:
		log.Printf("[ERROR] custom rule sets: %v", err)
		writeError(w, http.StatusServiceUnavailable, "rule set store unavailable", "")
	}
}

// createCustomSet: POST /v1/rule-sets.
func (s *Server) createCustomSet(w http.ResponseWriter, r *http.Request) {
	if s.cfg.CustomRuleSets == nil {
		writeError(w, http.StatusNotImplemented, "custom rule sets need the PostgreSQL store", "")
		return
	}
	if !customSetWriter(w, r) {
		return
	}
	in, ok := customSetBody(w, r)
	if !ok {
		return
	}
	if _, builtIn := rulesets.Get(in.Name); builtIn {
		writeError(w, http.StatusConflict, "the name of a built-in rule set", "")
		return
	}
	out, err := s.cfg.CustomRuleSets.CreateCustomRuleSet(r.Context(), store.CustomRuleSet{Name: in.Name, Title: in.Title, Description: in.Description, Match: in.Match}, applicationAudit(r))
	if err != nil {
		customSetError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

// customSetItem: GET, PUT and DELETE /v1/rule-sets/{name}.
func (s *Server) customSetItem(w http.ResponseWriter, r *http.Request, name string) {
	if !rulesets.IsCustom(name) {
		if _, builtIn := rulesets.Get(name); builtIn && r.Method != http.MethodGet {
			writeError(w, http.StatusForbidden, "a built-in rule set cannot be changed", "")
			return
		}
		if r.Method == http.MethodGet {
			if set, builtIn := rulesets.Get(name); builtIn {
				writeJSON(w, http.StatusOK, RuleSetInfo{Name: set.Name, Group: set.Group, Class: set.Class, Title: set.Title, Match: set.Match})
				return
			}
		}
		writeError(w, http.StatusNotFound, "rule set not found", "")
		return
	}
	if s.cfg.CustomRuleSets == nil {
		writeError(w, http.StatusNotFound, "rule set not found", "")
		return
	}
	switch r.Method {
	case http.MethodGet:
		c, err := s.cfg.CustomRuleSets.GetCustomRuleSet(r.Context(), name)
		if err != nil {
			customSetError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, c)
	case http.MethodPut:
		if !customSetWriter(w, r) {
			return
		}
		in, ok := customSetBody(w, r)
		if !ok {
			return
		}
		if in.Name != "" && in.Name != name {
			writeError(w, http.StatusBadRequest, "a rule set cannot be renamed", "")
			return
		}
		out, err := s.cfg.CustomRuleSets.UpdateCustomRuleSet(r.Context(), store.CustomRuleSet{Name: name, Title: in.Title, Description: in.Description, Match: in.Match}, in.Etag, applicationAudit(r))
		if err != nil {
			customSetError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, out)
	case http.MethodDelete:
		if !customSetWriter(w, r) {
			return
		}
		if err := s.cfg.CustomRuleSets.DeleteCustomRuleSet(r.Context(), name, r.URL.Query().Get("etag"), applicationAudit(r)); err != nil {
			customSetError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}
