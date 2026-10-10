// Package policy turns policies into signed bundles: it validates specs,
// runs the bundle compiler (strata-compile) over the current version of
// every policy, checks the result's signature and stores it in object
// storage (nginx-module.md › Kiến trúc control plane: Policy service,
// Compiler + signer).
package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
)

// Spec mirrors one policy of docs/spec/policies.schema.json without its
// name; it is stored as each version's JSON.
type Spec struct {
	Mode     string    `json:"mode"`               // shadow | enforce
	Oversize string    `json:"oversize,omitempty"` // pass | block
	Response *Response `json:"response,omitempty"`
}

// Response is the policy's response layer.
type Response struct {
	AllowedCodesCheck bool     `json:"allowed_codes_check,omitempty"`
	DBErrors          bool     `json:"db_errors,omitempty"`
	DataGuard         []string `json:"data_guard,omitempty"`
}

var (
	// IDPattern for policy ids (API resource names).
	IDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	// NamePattern for names in the bundle (policies.schema.json).
	NamePattern = regexp.MustCompile(`^[a-z0-9._-]{1,55}$`)
)

// Validate checks a spec like the compiler's schema does.
func (s Spec) Validate() error {
	switch s.Mode {
	case "shadow", "enforce":
	default:
		return fmt.Errorf("mode must be shadow or enforce, got %q", s.Mode)
	}
	switch s.Oversize {
	case "", "pass", "block":
	default:
		return fmt.Errorf("oversize must be pass or block, got %q", s.Oversize)
	}
	if s.Response != nil {
		seen := map[string]bool{}
		for _, g := range s.Response.DataGuard {
			if g != "cccd" && g != "jwt" {
				return fmt.Errorf("data_guard accepts cccd and jwt, got %q", g)
			}
			if seen[g] {
				return fmt.Errorf("data_guard lists %q twice", g)
			}
			seen[g] = true
		}
	}
	return nil
}

// Parse reads a stored spec.
func Parse(raw json.RawMessage) (Spec, error) {
	var s Spec
	if err := json.Unmarshal(raw, &s); err != nil {
		return Spec{}, err
	}
	if err := s.Validate(); err != nil {
		return Spec{}, err
	}
	return s, nil
}

// ErrNoPolicies: a bundle needs at least one policy.
var ErrNoPolicies = errors.New("policy: no policies to build")
