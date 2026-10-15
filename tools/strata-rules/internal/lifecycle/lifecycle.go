// Package lifecycle is the weekly rule review of RV-S-02: from the shadow
// false positives by Rule ID (W10-S-01), the requests of each policy
// (RV-N-01, ClickHouse policy_requests) and the rules of the repository,
// it lists the rules to review (false positives in shadow above the RV-S-01
// threshold, with a time-bound exception to consider), the old rules (no
// match in 90 days), the rules past their review date, and the upstream
// versions the importers pin.
package lifecycle

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/strata/strata/tools/strata-rules/internal/release"
	"github.com/strata/strata/tools/strata-rules/internal/report"
)

// Rule: what the review needs of a rule of the repository.
type Rule struct {
	ID       uint32
	Name     string
	Source   string
	Pack     string // core or signature
	Owner    string // metadata.owner, "" when unset
	ReviewBy string // metadata.review_by (YYYY-MM-DD), "" when unset
}

// Stats: what the event store says, over the review window.
type Stats struct {
	// suspected false positives in shadow, per rule and policy
	FP map[uint32]map[string]FP
	// requests per policy over the window; nil when the store has no
	// per-policy counters (modules before RV-N-01)
	Requests map[string]uint64
	// events per rule over the last OldAfter
	Matches map[uint32]uint64
	// how far back the event store goes
	DataSince time.Time
}

// FP: suspected false positives of one rule on one policy.
type FP struct {
	Events  uint64
	Sources uint64
	TopPath string
}

// Options of the classification.
type Options struct {
	// Window of the false-positive count (7 days).
	Window time.Duration
	// Threshold: a rule needs a review when its suspected false positives
	// reach this share of a policy's requests (RV-S-01: 0.05%).
	Threshold float64
	// OldAfter: a rule with no event in this long is old (90 days).
	OldAfter time.Duration
	// ExceptionFor: how long a suggested exception lasts (14 days).
	ExceptionFor time.Duration
}

func (o Options) withDefaults() Options {
	if o.Window <= 0 {
		o.Window = 7 * 24 * time.Hour
	}
	if o.Threshold <= 0 {
		o.Threshold = 0.0005
	}
	if o.OldAfter <= 0 {
		o.OldAfter = 90 * 24 * time.Hour
	}
	if o.ExceptionFor <= 0 {
		o.ExceptionFor = 14 * 24 * time.Hour
	}
	return o
}

// Review: a rule whose false positives on a policy reach the threshold.
type Review struct {
	Rule     Rule
	Policy   string
	FP       FP
	Requests uint64 // 0: unknown
	Share    float64
	// a time-bound exception to consider: rule, policy, path, until
	Until string
}

// Report of one run.
type Report struct {
	Now       time.Time
	Opts      Options
	Rules     int
	Review    []Review
	Old       []Rule
	OldKnown  bool    // the store covers OldAfter: Old is meaningful
	DataDays  float64 // days of events in the store
	Due       []Rule  // review_by passed
	NoOwner   map[string]int
	NoReview  map[string]int
	Upstreams []Pin
}

// Classify sorts the rules into the report.
func Classify(rules []Rule, st Stats, now time.Time, opt Options) Report {
	opt = opt.withDefaults()
	r := Report{Now: now, Opts: opt, Rules: len(rules), NoOwner: map[string]int{}, NoReview: map[string]int{}}
	if !st.DataSince.IsZero() {
		r.DataDays = now.Sub(st.DataSince).Hours() / 24
	}
	r.OldKnown = !st.DataSince.IsZero() && now.Sub(st.DataSince) >= opt.OldAfter
	byID := map[uint32]Rule{}
	for _, rl := range rules {
		byID[rl.ID] = rl
		if rl.Owner == "" {
			r.NoOwner[rl.Source]++
		}
		if rl.ReviewBy == "" {
			r.NoReview[rl.Source]++
		} else if d, err := time.Parse("2006-01-02", rl.ReviewBy); err == nil && d.Before(now) {
			r.Due = append(r.Due, rl)
		}
		if r.OldKnown && st.Matches[rl.ID] == 0 {
			r.Old = append(r.Old, rl)
		}
	}
	until := now.Add(opt.ExceptionFor).Format("2006-01-02")
	for id, byPolicy := range st.FP {
		rl, ok := byID[id]
		if !ok {
			rl = Rule{ID: id, Name: "(not in the repository)"}
		}
		for policy, fp := range byPolicy {
			req := st.Requests[policy]
			share := 0.0
			if req > 0 {
				share = float64(fp.Events) / float64(req)
			}
			// without a denominator every suspected false positive is listed
			if req > 0 && share < opt.Threshold {
				continue
			}
			r.Review = append(r.Review, Review{Rule: rl, Policy: policy, FP: fp, Requests: req, Share: share, Until: until})
		}
	}
	sort.Slice(r.Review, func(i, j int) bool {
		a, b := r.Review[i], r.Review[j]
		if a.FP.Events != b.FP.Events {
			return a.FP.Events > b.FP.Events
		}
		return a.Rule.ID < b.Rule.ID
	})
	sort.Slice(r.Old, func(i, j int) bool { return r.Old[i].ID < r.Old[j].ID })
	sort.Slice(r.Due, func(i, j int) bool { return r.Due[i].ReviewBy < r.Due[j].ReviewBy })
	return r
}

// LoadRules reads the rules of the repository (every rule file and IR
// ruleset under rules/).
func LoadRules(rulesDir string) ([]Rule, error) {
	docs, err := report.RulesUnder(rulesDir)
	if err != nil {
		return nil, err
	}
	var out []Rule
	for _, d := range docs {
		id, ok := num(d["id"])
		if !ok {
			continue
		}
		md, _ := d["metadata"].(map[string]any)
		src, _ := md["source"].(string)
		r := Rule{ID: id, Source: src, Pack: release.PackCore}
		if !release.InPack(release.PackCore, src) {
			r.Pack = release.PackSignature
		}
		r.Name, _ = d["name"].(string)
		r.Owner, _ = md["owner"].(string)
		r.ReviewBy = dateString(md["review_by"])
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func num(v any) (uint32, bool) {
	switch n := v.(type) {
	case int:
		return uint32(n), n > 0
	case int64:
		return uint32(n), n > 0
	case uint64:
		return uint32(n), n > 0
	case float64:
		return uint32(n), n > 0
	}
	return 0, false
}

// dateString: YAML reads an unquoted date as a time.Time.
func dateString(v any) string {
	switch d := v.(type) {
	case string:
		return d
	case time.Time:
		return d.Format("2006-01-02")
	}
	return ""
}

// Pin: an upstream source and the version the importer pins.
type Pin struct {
	Source  string
	Version string
	File    string
}

// Pins reads the versions the importers pin (`*version=` lines of their
// lock files): what a re-import starts from. Comparing with the latest
// upstream releases is left to the weekly job (network).
func Pins(repo string) []Pin {
	names := map[string]string{"version": "OWASP CRS", "sigma_version": "Sigma", "et_version": "ET Open", "bots_version": "crawler-user-agents"}
	var out []Pin
	for _, f := range []string{"tools/strata-import-crs/crs.lock", "tools/strata-import-signatures/sources.lock"} {
		fh, err := os.Open(filepath.Join(repo, f))
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(fh)
		for sc.Scan() {
			k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
			if !ok || strings.HasPrefix(k, "#") || !strings.HasSuffix(k, "version") {
				continue
			}
			name := names[k]
			if name == "" {
				name = k
			}
			out = append(out, Pin{Source: name, Version: v, File: f})
		}
		fh.Close()
	}
	return out
}

// Markdown writes the report.
func Markdown(w io.Writer, r Report) {
	p := func(format string, a ...any) { fmt.Fprintf(w, format, a...) }
	p("# Rule review, %s\n\n", r.Now.UTC().Format("2006-01-02"))
	p("RV-S-02: `strata-rules lifecycle`. %d rules. False positives over the last %s, threshold %.2f%% of a policy's requests (RV-S-01).\n\n",
		r.Rules, days(r.Opts.Window), 100*r.Opts.Threshold)

	p("## Rules to review (%d)\n\n", len(r.Review))
	if len(r.Review) == 0 {
		p("No rule reaches the threshold.\n\n")
	} else {
		p("Suspected false positives in shadow (attack sources excluded). Each line suggests a time-bound exception to consider (rule + policy + path, until the date); tuning the rule is preferred when the path is not the only one.\n\n")
		p("| Rule | Name | Pack | Policy | Events | Sources | Requests | Share | Top path | Exception until |\n| ---: | --- | --- | --- | ---: | ---: | ---: | ---: | --- | --- |\n")
		for _, v := range r.Review {
			req, share := "unknown", "-"
			if v.Requests > 0 {
				req, share = fmt.Sprint(v.Requests), fmt.Sprintf("%.3f%%", 100*v.Share)
			}
			p("| %d | %s | %s | %s | %d | %d | %s | %s | `%s` | %s |\n", v.Rule.ID, cell(v.Rule.Name), v.Rule.Pack, v.Policy, v.FP.Events, v.FP.Sources, req, share, cell(v.FP.TopPath), v.Until)
		}
		p("\n")
	}

	p("## Old rules: no event in %s\n\n", days(r.Opts.OldAfter))
	switch {
	case !r.OldKnown:
		p("Not judged yet: the event store holds %.1f days, under %s.\n\n", r.DataDays, days(r.Opts.OldAfter))
	case len(r.Old) == 0:
		p("None.\n\n")
	default:
		p("%d rules. Only events count: a rule that matched below the threshold without making an event is not seen.\n\n", len(r.Old))
		p("| Rule | Name | Source |\n| ---: | --- | --- |\n")
		for _, o := range r.Old {
			p("| %d | %s | %s |\n", o.ID, cell(o.Name), o.Source)
		}
		p("\n")
	}

	p("## Review dates\n\n")
	if len(r.Due) == 0 {
		p("No rule is past its review date.\n\n")
	} else {
		p("| Rule | Name | Owner | Review by |\n| ---: | --- | --- | --- |\n")
		for _, d := range r.Due {
			p("| %d | %s | %s | %s |\n", d.ID, cell(d.Name), cell(d.Owner), d.ReviewBy)
		}
		p("\n")
	}
	p("Rules without an owner or a review date, by source:\n\n| Source | No owner | No review date |\n| --- | ---: | ---: |\n")
	var srcs []string
	seen := map[string]bool{}
	for s := range r.NoOwner {
		seen[s] = true
	}
	for s := range r.NoReview {
		seen[s] = true
	}
	for s := range seen {
		srcs = append(srcs, s)
	}
	sort.Strings(srcs)
	for _, s := range srcs {
		p("| %s | %d | %d |\n", s, r.NoOwner[s], r.NoReview[s])
	}
	p("\n## Upstream\n\nPinned by the importers; a re-import starts from these (then `make test-crs-ftw` and the benign corpus, before any release).\n\n")
	if len(r.Upstreams) == 0 {
		p("No lock file found.\n")
	}
	for _, u := range r.Upstreams {
		p("- %s (`%s`): `%s`\n", u.Source, u.File, u.Version)
	}
}

func days(d time.Duration) string {
	return fmt.Sprintf("%d days", int(d.Hours()/24))
}

func cell(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "|", "\\|"), "\n", " ")
}
