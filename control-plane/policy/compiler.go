package policy

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/strata/strata/control-plane/rulesets"
)

// Named is a policy as it goes into a bundle.
type Named struct {
	// Resource identity selects durable state; Gate separately binds versions.
	ResourceID string `json:"-"`
	Version    int    `json:"-"`
	Name       string
	Spec       Spec
}

// Compiler runs strata-compile.
type Compiler struct {
	StagingStore StagingReader

	// StagedRules is an internal, explicit effective overlay. It is never a
	// public policy API input. Approval/provenance remain the deployer's duty.
	StagedRules map[string][]uint32
	Binary      string // default "strata-compile" from PATH
	// Signer signs bundles (KMS): strata-compile then writes the unsigned
	// bytes and never sees a key. Without it, KeyFile (an Ed25519 seed,
	// lab and development only) is passed to strata-compile.
	Signer         Signer
	KeyFile        string
	Rules          []string // IR files (docs/spec/ir.schema.json)
	BlockPage      string   // HTML file of the default block page; optional
	SupportContact string
	Timeout        time.Duration // default 2 min
	// CostBudget: a bundle whose rules cost more cost units is refused
	// (CostError); 0: no limit.
	CostBudget uint64
	// IdentityKey gives the installation's identity key, asked only when
	// a policy has privacy.identity hmac; nil: such policies fail to build.
	IdentityKey func(context.Context) ([]byte, error)
	// GoodBots gives the crawler ranges every bundle carries (W18-G2-02,
	// goodbots.ForCompiler): nil data without a stored list; an error
	// fails the build rather than drop the ranges silently.
	GoodBots func(context.Context) ([]byte, error)
	// Geo gives the networks of countries and ASNs (W19-R-01,
	// ingest.GeoIPEnricher.Networks as JSON), asked only when a policy has
	// geo rules; nil: such policies fail to build.
	Geo func(ctx context.Context, countries []string, asns []uint32) ([]byte, error)
}

// DefaultCostBudget: CRS 4.25 PL1 as imported costs about 15 000 units
// (W07-G2-01 report); room for three times that.
const DefaultCostBudget = 50000

// RuleCost is one rule of strata-compile's cost report.
type RuleCost struct {
	ID   uint32 `json:"id"`
	Name string `json:"name"`
	Cost uint64 `json:"cost"`
}

// CostError: the rules of the bundle cost more than the budget.
type CostError struct {
	Total, Budget uint64
	Top           []RuleCost // costliest first, at most 3
}

func (e *CostError) Error() string {
	var names []string
	for _, r := range e.Top {
		names = append(names, fmt.Sprintf("%d %q (%d)", r.ID, r.Name, r.Cost))
	}
	return fmt.Sprintf("the rules cost %d units, over the budget of %d; costliest: %s", e.Total, e.Budget, strings.Join(names, ", "))
}

func needsIdentityKey(policies []Named) bool {
	for _, p := range policies {
		if p.Spec.Privacy != nil && p.Spec.Privacy.Identity == "hmac" {
			return true
		}
	}
	return false
}

// Build compiles and signs a bundle of version holding policies.
func (c *Compiler) Build(ctx context.Context, version uint64, policies []Named) ([]byte, error) {
	if c.StagingStore != nil {
		next, err := c.withStaging(ctx, policies)
		if err != nil {
			return nil, err
		}
		return next.Build(ctx, version, policies)
	}
	if len(policies) == 0 {
		return nil, ErrNoPolicies
	}
	staged, err := c.stagingFor(policies)
	if err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp("", "strata-bundle-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)

	type item struct {
		StagedRules []uint32    `json:"staged_rules,omitempty"`
		Exceptions  []Exception `json:"exceptions,omitempty"`
		Name        string      `json:"name"`
		Mode        string      `json:"mode"`
		Oversize    string      `json:"oversize,omitempty"`
		Response    *Response   `json:"response,omitempty"`
		Snippet     int         `json:"max_snippet_size,omitempty"`
		Privacy     *Privacy    `json:"privacy,omitempty"`
		Canary      float64     `json:"canary_percent,omitempty"`
		MaxArgs     int         `json:"max_args,omitempty"`
		FailOn      string      `json:"fail_on_findings,omitempty"`
		ParseError  string      `json:"parse_error,omitempty"`
		Paranoia    int         `json:"crs_paranoia,omitempty"`
		ParaShadow  int         `json:"crs_paranoia_shadow,omitempty"`
		Plugins     []string    `json:"crs_plugins,omitempty"`
		GeoRules    []GeoRule   `json:"geo_rules,omitempty"`
		// RS-3: named sets expanded into the filters the compiler takes
		RuleSets      []compiledRuleSet `json:"rule_sets,omitempty"`
		RuleOverrides []RuleOverride    `json:"rule_overrides,omitempty"`
	}
	doc := map[string]any{}
	items := make([]item, 0, len(policies))
	for _, p := range policies {
		items = append(items, item{StagedRules: staged[p.Name], Exceptions: p.Spec.Exceptions, Name: p.Name, Mode: p.Spec.Mode, Oversize: p.Spec.Oversize, Response: p.Spec.Response, Snippet: p.Spec.MaxSnippetSize, Privacy: p.Spec.Privacy,
			Canary: p.Spec.CanaryPercent, MaxArgs: p.Spec.MaxArgs, FailOn: p.Spec.FailOnFindings, ParseError: p.Spec.ParseError,
			Paranoia: p.Spec.CRSParanoia, ParaShadow: p.Spec.CRSParanoiaShadow, Plugins: p.Spec.CRSPlugins, GeoRules: p.Spec.GeoRules,
			RuleSets: expandRuleSets(p.Spec.RuleSets), RuleOverrides: p.Spec.RuleOverrides})
	}
	doc["policies"] = items
	if c.BlockPage != "" {
		html, err := os.ReadFile(c.BlockPage)
		if err != nil {
			return nil, fmt.Errorf("policy: block page: %w", err)
		}
		bp := map[string]any{"html": string(html)}
		if c.SupportContact != "" {
			bp["support_contact"] = c.SupportContact
		}
		doc["block_page"] = bp
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	polFile := filepath.Join(dir, "policies.json")
	if err := os.WriteFile(polFile, raw, 0o600); err != nil {
		return nil, err
	}
	out := filepath.Join(dir, "bundle.sbn")
	costFile := filepath.Join(dir, "cost.json")
	args := []string{"--policies", polFile, "--version", strconv.FormatUint(version, 10), "--out", out, "--cost-report", costFile}
	if c.Signer != nil {
		args = append(args, "--unsigned")
	} else {
		args = append(args, "--key", c.KeyFile)
	}
	for _, r := range c.Rules {
		args = append(args, "--rules", r)
	}
	if needsIdentityKey(policies) {
		if c.IdentityKey == nil {
			return nil, errors.New("policy: privacy.identity hmac needs the identity key (STRATA_IDENTITY_HMAC_KEY or PostgreSQL)")
		}
		key, err := c.IdentityKey(ctx)
		if err != nil {
			return nil, fmt.Errorf("policy: %w", err)
		}
		keyFile := filepath.Join(dir, "identity.key")
		if err := os.WriteFile(keyFile, []byte(hex.EncodeToString(key)), 0o600); err != nil {
			return nil, err
		}
		args = append(args, "--identity-key", keyFile)
	}
	if c.GoodBots != nil {
		ranges, err := c.GoodBots(ctx)
		if err != nil {
			return nil, fmt.Errorf("policy: %w", err)
		}
		if ranges != nil {
			f := filepath.Join(dir, "good-bots.json")
			if err := os.WriteFile(f, ranges, 0o600); err != nil {
				return nil, err
			}
			args = append(args, "--good-bots", f)
		}
	}
	// W19-G2-01: the networks of the countries and ASNs geo rules name
	specs := make([]Spec, 0, len(policies))
	for _, p := range policies {
		specs = append(specs, p.Spec)
	}
	if countries, asns := GeoKeys(specs...); len(countries)+len(asns) > 0 {
		if c.Geo == nil {
			return nil, errors.New("policy: geo rules need a GeoIP database (-geoip-city / -geoip-asn or STRATA_GEOIP_*_URL)")
		}
		networks, err := c.Geo(ctx, countries, asns)
		if err != nil {
			return nil, fmt.Errorf("policy: geo networks: %w", err)
		}
		f := filepath.Join(dir, "geo.json")
		if err := os.WriteFile(f, networks, 0o600); err != nil {
			return nil, err
		}
		args = append(args, "--geo", f)
	}
	bin := c.Binary
	if bin == "" {
		bin = "strata-compile"
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, bin, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := stderr.String()
		if len(msg) > 2000 {
			msg = msg[:2000]
		}
		return nil, fmt.Errorf("policy: strata-compile: %v: %s", err, msg)
	}
	if c.CostBudget > 0 {
		raw, err := os.ReadFile(costFile)
		if err != nil {
			return nil, fmt.Errorf("policy: cost report: %w", err)
		}
		var rep struct {
			Total uint64     `json:"total"`
			Rules []RuleCost `json:"rules"`
		}
		if err := json.Unmarshal(raw, &rep); err != nil {
			return nil, fmt.Errorf("policy: cost report: %w", err)
		}
		if rep.Total > c.CostBudget {
			top := rep.Rules[:min(3, len(rep.Rules))]
			return nil, &CostError{Total: rep.Total, Budget: c.CostBudget, Top: top}
		}
	}
	data, err := os.ReadFile(out)
	if err != nil || c.Signer == nil {
		return data, err
	}
	sig, err := c.Signer.Sign(ctx, data)
	if err != nil {
		return nil, fmt.Errorf("policy: sign: %w", err)
	}
	return append(data, sig...), nil
}

// compiledRuleSet is a rule set as the compiler reads it
// (policies.schema.json rule_sets): the filter, not the name.
type compiledRuleSet struct {
	Name   string          `json:"name"`
	Match  rulesets.Filter `json:"match"`
	Action string          `json:"action"`
}

// expandRuleSets turns a spec's set names into filters: a custom set's
// copy, a built-in set's filter; Validate has checked every name exists.
func expandRuleSets(refs []RuleSetRef) []compiledRuleSet {
	var out []compiledRuleSet
	for _, r := range refs {
		if r.Match != nil {
			out = append(out, compiledRuleSet{Name: r.Set, Match: *r.Match, Action: r.Action})
		} else if set, ok := rulesets.Get(r.Set); ok {
			out = append(out, compiledRuleSet{Name: r.Set, Match: set.Match, Action: r.Action})
		}
	}
	return out
}
