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
	"slices"
	"sort"
	"strings"
)

// Spec mirrors one policy of docs/spec/policies.schema.json without its
// name; it is stored as each version's JSON.
type Spec struct {
	// AutoStaging delegates only reduction to log-only for an explicit rule set.
	// It is versioned and included in the replay digest like the rest of Spec.
	AutoStaging *AutoStaging `json:"auto_staging,omitempty"`
	Exceptions  []Exception  `json:"exceptions,omitempty"`
	Mode        string       `json:"mode"`               // shadow | enforce
	Oversize    string       `json:"oversize,omitempty"` // pass | block
	Response    *Response    `json:"response,omitempty"`
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
	// CRSParanoia: CRS paranoia level enforced, 1..4; 0 = 1 (W17-S-01).
	CRSParanoia int `json:"crs_paranoia,omitempty"`
	// CRSParanoiaShadow: CRS paranoia level run and reported without
	// blocking, CRSParanoia..4; 0 = the enforced level.
	CRSParanoiaShadow int `json:"crs_paranoia_shadow,omitempty"`
	// CRSPlugins: the CRS plugins (rule exclusions) the policy runs,
	// sorted (W17-S-01, policies.schema.json crs_plugins).
	CRSPlugins []string `json:"crs_plugins,omitempty"`
	// GeoRules: the policy's own rules on the country and ASN of the
	// client address (W19-G2-01, policies.schema.json geo_rules).
	GeoRules []GeoRule `json:"geo_rules,omitempty"`
}

// GeoRule is one geo rule of a policy (W19-G2-01).
type GeoRule struct {
	// ID: GeoRuleIDMin..GeoRuleIDMax, unique across policies (the control
	// plane assigns it).
	ID        uint32   `json:"id"`
	Countries []string `json:"countries,omitempty"`
	ASNs      []uint32 `json:"asns,omitempty"`
	// Not: the addresses outside the countries and ASNs (local excepted).
	Not bool `json:"not,omitempty"`
	// Action: block or log.
	Action string `json:"action"`
}

// Geo rule ids and limits (the compiler's POLICY_RULE_IDS, MAX_GEO_RULES).
const (
	GeoRuleIDMin = 190000
	GeoRuleIDMax = 199999
	MaxGeoRules  = 16
)

var countryPattern = regexp.MustCompile(`^[A-Z]{2}$`)

// GeoKeys are the countries and ASNs the specs' geo rules name, sorted.
func GeoKeys(specs ...Spec) ([]string, []uint32) {
	var cs []string
	var as []uint32
	for _, s := range specs {
		for _, g := range s.GeoRules {
			cs = append(cs, g.Countries...)
			as = append(as, g.ASNs...)
		}
	}
	slices.Sort(cs)
	slices.Sort(as)
	return slices.Compact(cs), slices.Compact(as)
}

// ParanoiaLevels of the spec, defaults applied: (enforced, shadow).
func (s Spec) ParanoiaLevels() (int, int) {
	enforce := max(s.CRSParanoia, 1)
	return enforce, max(s.CRSParanoiaShadow, enforce)
}

// Normalize stores default values as absent, so an unchanged policy keeps
// its JSON (and its replay digest). Call it on a valid spec.
func (s *Spec) Normalize() {
	if s.CRSParanoia == 1 {
		s.CRSParanoia = 0
	}
	if enforce, _ := s.ParanoiaLevels(); s.CRSParanoiaShadow == enforce {
		s.CRSParanoiaShadow = 0
	}
	for i := range s.GeoRules {
		g := &s.GeoRules[i]
		g.Countries = slices.Sorted(slices.Values(g.Countries))
		g.ASNs = slices.Sorted(slices.Values(g.ASNs))
		if len(g.Countries) == 0 {
			g.Countries = nil
		}
		if len(g.ASNs) == 0 {
			g.ASNs = nil
		}
	}
	if len(s.GeoRules) == 0 {
		s.GeoRules = nil
	}
	if len(s.CRSPlugins) == 0 {
		s.CRSPlugins = nil
	} else {
		s.CRSPlugins = append([]string(nil), s.CRSPlugins...)
		sort.Strings(s.CRSPlugins)
	}
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

// pluginPattern: a CRS plugin name (policies.schema.json crs_plugins).
var pluginPattern = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)

// Response is the policy's response layer.
type Response struct {
	AllowedCodesCheck bool     `json:"allowed_codes_check,omitempty"`
	DBErrors          bool     `json:"db_errors,omitempty"`
	DataGuard         []string `json:"data_guard,omitempty"`
}

var (
	// IDPattern for policy ids (API resource names).
	IDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	// NamePattern for names in the bundle (policies.schema.json). Check
	// names with ValidName, which also refuses names made only of dots.
	NamePattern = regexp.MustCompile(`^[a-z0-9._-]{1,55}$`)
)

// ValidName reports whether name may name a policy: NamePattern, and not
// only dots (CP-SEC-02). Policy names go into object keys and paths
// (replay/v1/<policy>/…); "." and ".." would leave their directory on a
// filesystem store.
func ValidName(name string) bool {
	return NamePattern.MatchString(name) && strings.Trim(name, ".") != ""
}

// Validate checks a spec like the compiler's schema does.
func (s Spec) Validate() error {
	if err := s.AutoStaging.Validate(); err != nil {
		return err
	}
	if len(s.Exceptions) > 128 {
		return errors.New("at most 128 policy exceptions")
	}
	seenExceptions := make(map[string]bool, len(s.Exceptions))
	for _, e := range s.Exceptions {
		if err := e.Validate(); err != nil {
			return err
		}
		if seenExceptions[e.ID] {
			return errors.New("duplicate exception id")
		}
		seenExceptions[e.ID] = true
	}

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
	if s.CRSParanoia < 0 || s.CRSParanoia > 4 {
		return fmt.Errorf("crs_paranoia must be 1..4, got %d", s.CRSParanoia)
	}
	if enforce, _ := s.ParanoiaLevels(); s.CRSParanoiaShadow != 0 && (s.CRSParanoiaShadow < enforce || s.CRSParanoiaShadow > 4) {
		return fmt.Errorf("crs_paranoia_shadow must be crs_paranoia (%d)..4, got %d", enforce, s.CRSParanoiaShadow)
	}
	if len(s.GeoRules) > MaxGeoRules {
		return fmt.Errorf("geo_rules: at most %d", MaxGeoRules)
	}
	geoIDs := map[uint32]bool{}
	for _, g := range s.GeoRules {
		if g.ID < GeoRuleIDMin || g.ID > GeoRuleIDMax || geoIDs[g.ID] {
			return fmt.Errorf("geo_rules: id %d is not %d..%d or is listed twice", g.ID, GeoRuleIDMin, GeoRuleIDMax)
		}
		geoIDs[g.ID] = true
		if len(g.Countries) == 0 && len(g.ASNs) == 0 {
			return fmt.Errorf("geo_rules: rule %d names no country and no ASN", g.ID)
		}
		if len(g.Countries) > 300 || len(g.ASNs) > 1000 {
			return fmt.Errorf("geo_rules: rule %d: at most 300 countries and 1000 ASNs", g.ID)
		}
		seen := map[string]bool{}
		for _, c := range g.Countries {
			if !countryPattern.MatchString(c) || seen[c] {
				return fmt.Errorf("geo_rules: rule %d: country %q is not an ISO code (VN) or is listed twice", g.ID, c)
			}
			seen[c] = true
		}
		seenASN := map[uint32]bool{}
		for _, a := range g.ASNs {
			if a == 0 || seenASN[a] {
				return fmt.Errorf("geo_rules: rule %d: ASN %d is 0 or listed twice", g.ID, a)
			}
			seenASN[a] = true
		}
		switch g.Action {
		case "block", "log":
		default:
			return fmt.Errorf("geo_rules: rule %d: action must be block or log, got %q", g.ID, g.Action)
		}
	}
	if len(s.CRSPlugins) > 16 {
		return errors.New("crs_plugins: at most 16")
	}
	seenPlugins := map[string]bool{}
	for _, p := range s.CRSPlugins {
		if !pluginPattern.MatchString(p) || seenPlugins[p] {
			return fmt.Errorf("crs_plugins: %q is invalid or listed twice (1 to 32 of a-z, 0-9, -)", p)
		}
		seenPlugins[p] = true
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
