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
	"math"
	"regexp"
)

// Spec mirrors one policy of docs/spec/policies.schema.json without its
// name; it is stored as each version's JSON.
type Spec struct {
	Mode     string    `json:"mode"`               // shadow | enforce
	Oversize string    `json:"oversize,omitempty"` // pass | block
	Response *Response `json:"response,omitempty"`
	// MaxSnippetSize: 0 (128 bytes), 128, 2048 or 4096 (P-01 §1b).
	MaxSnippetSize int `json:"max_snippet_size,omitempty"`
	// Privacy settings (P-01 §1).
	Privacy *Privacy `json:"privacy,omitempty"`
	// CanaryPercent: enforce canary, share of clients whose requests this
	// enforce policy blocks (0.01..99.99, two decimals); 0 = every client
	// (W12-G2-01; policies.schema.json canary_percent).
	CanaryPercent float64 `json:"canary_percent,omitempty"`
	// MaxArgs: arguments inspected, 1..1020 (rounded up to four by the
	// compiler); 0 = the engine's 1024. More go by Oversize (rule 100021, #28).
	MaxArgs int `json:"max_args,omitempty"`
	// FailOnFindings: "pass" (default) or "block": the CPU budget runs out
	// on a request that already has findings, block fails closed (#98).
	FailOnFindings string `json:"fail_on_findings,omitempty"`
}

// CanaryBasisPoints of the spec's canary (0: none).
func (s Spec) CanaryBasisPoints() int { return int(math.Round(s.CanaryPercent * 100)) }

// Privacy settings of a policy: more names that keep no snippet, and
// patterns masked in events. strata-compile checks the patterns again with
// the engine's regex syntax.
type Privacy struct {
	SensitiveFields []string `json:"sensitive_fields,omitempty"`
	MaskPatterns    []string `json:"mask_patterns,omitempty"`
	// Identity: "" or "plain" (as it is) or "hmac" (pseudonymized with the
	// installation's identity key).
	Identity string `json:"identity,omitempty"`
}

var fieldPattern = regexp.MustCompile(`^[!-~]{1,64}$`)

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
	switch s.FailOnFindings {
	case "", "pass", "block":
	default:
		return fmt.Errorf("fail_on_findings must be pass or block, got %q", s.FailOnFindings)
	}
	if s.MaxArgs < 0 || s.MaxArgs > 1020 {
		return fmt.Errorf("max_args must be 1..1020, got %d", s.MaxArgs)
	}
	switch s.MaxSnippetSize {
	case 0, 128, 2048, 4096:
	default:
		return fmt.Errorf("max_snippet_size must be 128, 2048 or 4096, got %d", s.MaxSnippetSize)
	}
	if p := s.Privacy; p != nil {
		if len(p.SensitiveFields) > 64 || len(p.MaskPatterns) > 16 {
			return errors.New("privacy: at most 64 sensitive_fields and 16 mask_patterns")
		}
		switch p.Identity {
		case "", "plain", "hmac":
		default:
			return fmt.Errorf("privacy: identity must be plain or hmac, got %q", p.Identity)
		}
		for _, f := range p.SensitiveFields {
			if !fieldPattern.MatchString(f) {
				return fmt.Errorf("privacy: sensitive field %q: 1 to 64 printable characters, no space", f)
			}
		}
		for _, m := range p.MaskPatterns {
			if m == "" || len(m) > 256 {
				return fmt.Errorf("privacy: mask pattern %q: 1 to 256 bytes", m)
			}
			re, err := regexp.Compile(m)
			if err != nil {
				return fmt.Errorf("privacy: mask pattern %q: %v", m, err)
			}
			if re.MatchString("") {
				return fmt.Errorf("privacy: mask pattern %q matches the empty string", m)
			}
		}
	}
	if s.CanaryPercent != 0 {
		bp := s.CanaryPercent * 100
		switch {
		case s.Mode != "enforce":
			return errors.New("canary_percent needs mode enforce")
		case s.CanaryPercent < 0.01 || s.CanaryPercent > 99.99 || math.Abs(bp-math.Round(bp)) > 1e-6:
			return fmt.Errorf("canary_percent must be 0.01 to 99.99 with at most two decimals, got %v", s.CanaryPercent)
		}
	}
	if s.Response != nil {
		seen := map[string]bool{}
		for _, g := range s.Response.DataGuard {
			if g != "cccd" && g != "jwt" && g != "pan" {
				return fmt.Errorf("data_guard accepts cccd, jwt and pan, got %q", g)
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
