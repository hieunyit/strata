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
	"net/netip"
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
	// GeoRestrictions: geographical and ASN access control (W19-G2-01).
	GeoRestrictions *GeoRestrictions `json:"geo_restrictions,omitempty"`
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

var (
	fieldPattern   = regexp.MustCompile(`^[!-~]{1,64}$`)
	countryPattern = regexp.MustCompile(`^[A-Z]{2}$`)
)

// GeoRestrictions configures geographical and ASN-based access controls (W19-G2-01).
type GeoRestrictions struct {
	Enabled             *bool    `json:"enabled,omitempty"`
	DefaultAction       string   `json:"default_action,omitempty"`
	BlockedCountries    []string `json:"blocked_countries,omitempty"`
	ChallengedCountries []string `json:"challenged_countries,omitempty"`
	BlockedASNs         []uint32 `json:"blocked_asns,omitempty"`
	ChallengedASNs      []uint32 `json:"challenged_asns,omitempty"`
	ExemptIPs           []string `json:"exempt_ips,omitempty"`
}

// IsEnabled reports whether geo restrictions are active (default true when struct is present).
func (g *GeoRestrictions) IsEnabled() bool {
	if g == nil {
		return false
	}
	return g.Enabled == nil || *g.Enabled
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
	if g := s.GeoRestrictions; g != nil {
		switch g.DefaultAction {
		case "", "pass", "monitor":
		default:
			return fmt.Errorf("geo_restrictions: default_action must be pass or monitor, got %q", g.DefaultAction)
		}
		if len(g.BlockedCountries)+len(g.ChallengedCountries) > 256 {
			return errors.New("geo_restrictions: too many countries specified (max 256)")
		}
		if len(g.BlockedASNs)+len(g.ChallengedASNs) > 1000 {
			return errors.New("geo_restrictions: too many asns specified (max 1000)")
		}
		if len(g.ExemptIPs) > 256 {
			return errors.New("geo_restrictions: too many exempt_ips (max 256)")
		}

		blockedCountries := make(map[string]bool, len(g.BlockedCountries))
		for _, c := range g.BlockedCountries {
			if !countryPattern.MatchString(c) {
				return fmt.Errorf("geo_restrictions: invalid country code %q (must be 2 uppercase ISO letters)", c)
			}
			if blockedCountries[c] {
				return fmt.Errorf("geo_restrictions: duplicate country code %q in blocked_countries", c)
			}
			blockedCountries[c] = true
		}

		for _, c := range g.ChallengedCountries {
			if !countryPattern.MatchString(c) {
				return fmt.Errorf("geo_restrictions: invalid country code %q (must be 2 uppercase ISO letters)", c)
			}
			if blockedCountries[c] {
				return fmt.Errorf("geo_restrictions: country %q cannot be in both blocked_countries and challenged_countries", c)
			}
		}

		blockedASNs := make(map[uint32]bool, len(g.BlockedASNs))
		for _, a := range g.BlockedASNs {
			if a == 0 {
				return errors.New("geo_restrictions: ASN must be greater than 0")
			}
			if blockedASNs[a] {
				return fmt.Errorf("geo_restrictions: duplicate ASN %d in blocked_asns", a)
			}
			blockedASNs[a] = true
		}

		challengedASNs := make(map[uint32]bool, len(g.ChallengedASNs))
		for _, a := range g.ChallengedASNs {
			if a == 0 {
				return errors.New("geo_restrictions: ASN must be greater than 0")
			}
			if challengedASNs[a] {
				return fmt.Errorf("geo_restrictions: duplicate ASN %d in challenged_asns", a)
			}
			if blockedASNs[a] {
				return fmt.Errorf("geo_restrictions: ASN %d cannot be in both blocked_asns and challenged_asns", a)
			}
			challengedASNs[a] = true
		}

		seenIPs := make(map[string]bool, len(g.ExemptIPs))
		for _, ipStr := range g.ExemptIPs {
			if seenIPs[ipStr] {
				return fmt.Errorf("geo_restrictions: duplicate exempt IP/CIDR %q", ipStr)
			}
			seenIPs[ipStr] = true
			if _, err := netip.ParseAddr(ipStr); err != nil {
				if _, err2 := netip.ParsePrefix(ipStr); err2 != nil {
					return fmt.Errorf("geo_restrictions: invalid exempt IP or CIDR %q", ipStr)
				}
			}
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

// Template represents a policy template (W20-S-01).
type Template struct {
	Name        string `json:"name" yaml:"name"`
	Description string `json:"description" yaml:"description"`
	Version     string `json:"version" yaml:"version"`
	Spec        Spec   `json:"spec" yaml:"spec"`
}

// InheritFrom applies the template's defaults onto a policy spec
// without overwriting explicitly set fields in s (W20-S-01).
func (s *Spec) InheritFrom(t *Template) {
	if t == nil {
		return
	}
	ts := t.Spec
	if s.Mode == "" {
		s.Mode = ts.Mode
	}
	if s.Oversize == "" {
		s.Oversize = ts.Oversize
	}
	if s.FailOnFindings == "" {
		s.FailOnFindings = ts.FailOnFindings
	}
	if s.MaxArgs == 0 {
		s.MaxArgs = ts.MaxArgs
	}
	if s.MaxSnippetSize == 0 {
		s.MaxSnippetSize = ts.MaxSnippetSize
	}
	if s.Privacy == nil && ts.Privacy != nil {
		s.Privacy = &Privacy{
			SensitiveFields: append([]string(nil), ts.Privacy.SensitiveFields...),
			MaskPatterns:    append([]string(nil), ts.Privacy.MaskPatterns...),
			Identity:        ts.Privacy.Identity,
		}
	}
	if s.Response == nil && ts.Response != nil {
		s.Response = &Response{
			AllowedCodesCheck: ts.Response.AllowedCodesCheck,
			DBErrors:          ts.Response.DBErrors,
			DataGuard:         append([]string(nil), ts.Response.DataGuard...),
		}
	}
	if s.GeoRestrictions == nil && ts.GeoRestrictions != nil {
		enabled := ts.GeoRestrictions.IsEnabled()
		s.GeoRestrictions = &GeoRestrictions{
			Enabled:             &enabled,
			DefaultAction:       ts.GeoRestrictions.DefaultAction,
			BlockedCountries:    append([]string(nil), ts.GeoRestrictions.BlockedCountries...),
			ChallengedCountries: append([]string(nil), ts.GeoRestrictions.ChallengedCountries...),
			BlockedASNs:         append([]uint32(nil), ts.GeoRestrictions.BlockedASNs...),
			ChallengedASNs:      append([]uint32(nil), ts.GeoRestrictions.ChallengedASNs...),
			ExemptIPs:           append([]string(nil), ts.GeoRestrictions.ExemptIPs...),
		}
	}
}

