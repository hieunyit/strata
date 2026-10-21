// Package release builds a signature package from the rule repository
// (W08-S-01): every rule compiled into one signed bundle, with a version, a
// changelog and the NOTICE that records each source and its license.
//
// RV-S-01 splits the rules in two packs by metadata.source: core (CRS, the
// protocol layer, virtual patches, the organization's rules), enforced by
// default, and signature (Sigma, ET Open, bot lists), which a policy runs in
// shadow unless it says otherwise (policies.schema.json, signatures). Pack
// "" keeps every rule in one package, as before.
package release

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/strata/strata/tools/strata-rules/internal/report"
	"github.com/strata/strata/tools/strata-rules/internal/runner"
)

// Manifest describes a built package; it is written to manifest.json and can
// be passed back as the baseline of the next release for the changelog.
type Manifest struct {
	RuleDigests   map[string]string `json:"rule_digests,omitempty"`
	Version       string            `json:"version"`
	Pack          string            `json:"pack,omitempty"` // core, signature; "": both
	BundleVersion uint64            `json:"bundle_version"`
	CreatedAt     string            `json:"created_at"`
	Bundle        string            `json:"bundle"`
	SHA256        string            `json:"sha256"`
	Rules         int               `json:"rules"`
	BySource      map[string]int    `json:"by_source"`
	ByLicense     map[string]int    `json:"by_license"`
	ByActionMode  map[string]int    `json:"by_action_mode"`
	RuleIDs       []int             `json:"rule_ids"`
	// sha256 of every other file of the package (public key, NOTICE,
	// CHANGELOG.md): manifest.json.sig signs the manifest, so the whole
	// package is covered, not only the bundle (W08 review)
	Files map[string]string `json:"files"`
}

// SigFile is the detached Ed25519 signature of manifest.json, made with the
// bundle's signing key.
const SigFile = "manifest.json.sig"

// Options for Build.
type Options struct {
	Repo          string
	RulesDir      string // default <repo>/rules
	Version       string // package label, e.g. 2026.w42
	BundleVersion uint64 // numeric bundle version (monotonic); default 1
	KeyFile       string // ed25519 seed (32 bytes), as strata-compile --key
	Out           string // output directory
	Baseline      string // previous manifest.json for the changelog (optional)
	Policies      string // policies file compiled in (optional; default none)
	Pack          string // PackCore, PackSignature, or "" for every rule
	NoHSBlock     bool   // strata-compile --no-hs-block: leave out the block-mode copy of the Hyperscan database (on by default)
}

// Packs (RV-S-01).
const (
	PackCore      = "core"
	PackSignature = "signature"
)

// SignatureSources are the metadata.source values of the signature pack.
// libstrata flags the same rules (engine/src/rules.rs SIGNATURE_SOURCES;
// TestSignatureSourcesMatchTheEngine keeps the two lists equal).
var SignatureSources = []string{"sigma", "et-open", "crawler-user-agents"}

// InPack reports whether a rule of source belongs to pack ("" = any).
func InPack(pack, source string) bool {
	sig := false
	for _, s := range SignatureSources {
		sig = sig || s == source
	}
	switch pack {
	case PackCore:
		return !sig
	case PackSignature:
		return sig
	}
	return true
}

// PackName is the file name prefix of a package of pack.
func PackName(pack, version string) string {
	if pack == PackCore {
		return "strata-core-" + version
	}
	return "strata-signatures-" + version
}

// Build writes the package to Options.Out and returns its manifest.
func Build(o Options) (*Manifest, error) {
	if o.RulesDir == "" {
		o.RulesDir = filepath.Join(o.Repo, "rules")
	}
	if o.Version == "" {
		return nil, fmt.Errorf("a --version is required")
	}
	if o.BundleVersion == 0 {
		o.BundleVersion = 1
	}
	if o.KeyFile == "" {
		return nil, fmt.Errorf("a --key (ed25519 seed) is required")
	}
	if o.Pack != "" && o.Pack != PackCore && o.Pack != PackSignature {
		return nil, fmt.Errorf("--pack is %s or %s, got %q", PackCore, PackSignature, o.Pack)
	}
	tools, err := runner.Find(o.Repo)
	if err != nil {
		return nil, err
	}
	all, err := report.RulesUnder(o.RulesDir)
	if err != nil {
		return nil, err
	}
	var rules []map[string]any
	for _, r := range all {
		meta, _ := r["metadata"].(map[string]any)
		if InPack(o.Pack, str(meta["source"])) {
			rules = append(rules, r)
		}
	}
	if len(rules) == 0 {
		return nil, fmt.Errorf("no rules of pack %q under %s", o.Pack, o.RulesDir)
	}

	if err := os.MkdirAll(o.Out, 0o755); err != nil {
		return nil, err
	}
	name := PackName(o.Pack, o.Version)
	bundlePath := filepath.Join(o.Out, name+".sbn")
	nowMS := time.Now().UnixMilli()

	if err := compile(tools.CompileBin, rules, o, bundlePath, nowMS); err != nil {
		return nil, err
	}

	// the public key beside the bundle, so a verifier does not need the seed
	seed, err := os.ReadFile(o.KeyFile)
	if err != nil {
		return nil, err
	}
	if len(seed) < ed25519.SeedSize {
		return nil, fmt.Errorf("%s: key is %d bytes, want %d", o.KeyFile, len(seed), ed25519.SeedSize)
	}
	pub := ed25519.NewKeyFromSeed(seed[:ed25519.SeedSize]).Public().(ed25519.PublicKey)
	if err := os.WriteFile(filepath.Join(o.Out, name+".pub"), pub, 0o644); err != nil {
		return nil, err
	}

	bundle, err := os.ReadFile(bundlePath)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(bundle)

	m := &Manifest{
		Version:       o.Version,
		Pack:          o.Pack,
		BundleVersion: o.BundleVersion,
		CreatedAt:     time.UnixMilli(nowMS).UTC().Format(time.RFC3339),
		Bundle:        filepath.Base(bundlePath),
		SHA256:        hex.EncodeToString(sum[:]),
		Rules:         len(rules),
		BySource:      map[string]int{},
		ByLicense:     map[string]int{},
		ByActionMode:  map[string]int{},
		RuleDigests:   map[string]string{},
	}
	for _, r := range rules {
		if id, ok := asInt(r["id"]); ok {
			m.RuleIDs = append(m.RuleIDs, id)
			raw, err := json.Marshal(r)
			if err != nil {
				return nil, fmt.Errorf("rule digest: %w", err)
			}
			sum := sha256.Sum256(raw)
			m.RuleDigests[strconv.Itoa(id)] = hex.EncodeToString(sum[:])
		}
		meta, _ := r["metadata"].(map[string]any)
		m.BySource[str(meta["source"])]++
		m.ByLicense[str(meta["license"])]++
		mode := str(r["action_mode"])
		if mode == "" {
			mode = "score" // the IR default
		}
		m.ByActionMode[mode]++
	}
	sort.Ints(m.RuleIDs)

	if err := copyFile(filepath.Join(o.Repo, "NOTICE"), filepath.Join(o.Out, "NOTICE")); err != nil {
		return nil, err
	}
	if err := writeChangelog(filepath.Join(o.Out, "CHANGELOG.md"), m, o.Baseline); err != nil {
		return nil, err
	}
	m.Files = map[string]string{}
	for _, f := range []string{name + ".pub", name + ".rules.json", "cost.json", "NOTICE", "CHANGELOG.md"} {
		b, err := os.ReadFile(filepath.Join(o.Out, f))
		if err != nil {
			return nil, err
		}
		h := sha256.Sum256(b)
		m.Files[f] = hex.EncodeToString(h[:])
	}
	if err := writeJSON(filepath.Join(o.Out, "manifest.json"), m); err != nil {
		return nil, err
	}
	mb, err := os.ReadFile(filepath.Join(o.Out, "manifest.json"))
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(ed25519.NewKeyFromSeed(seed[:ed25519.SeedSize]), mb)
	if err := os.WriteFile(filepath.Join(o.Out, SigFile), sig, 0o644); err != nil {
		return nil, err
	}
	return m, nil
}

// Verify checks a package directory against a trusted public key: the
// manifest signature, then the sha256 of the bundle and of every file the
// manifest lists. The bundle's own signature is checked again by libstrata
// when it is loaded.
func Verify(dir string, pub ed25519.PublicKey) (*Manifest, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key is %d bytes, want %d", len(pub), ed25519.PublicKeySize)
	}
	mb, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return nil, err
	}
	sig, err := os.ReadFile(filepath.Join(dir, SigFile))
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(pub, mb, sig) {
		return nil, fmt.Errorf("%s: signature does not match manifest.json", SigFile)
	}
	var m Manifest
	if err := json.Unmarshal(mb, &m); err != nil {
		return nil, err
	}
	want := map[string]string{m.Bundle: m.SHA256}
	for f, h := range m.Files {
		want[f] = h
	}
	for f, h := range want {
		if f != filepath.Base(f) {
			return nil, fmt.Errorf("manifest names a file outside the package: %q", f)
		}
		b, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			return nil, err
		}
		got := sha256.Sum256(b)
		if hex.EncodeToString(got[:]) != h {
			return nil, fmt.Errorf("%s: sha256 does not match the manifest", f)
		}
	}
	return &m, nil
}

func compile(bin string, rules []map[string]any, o Options, out string, createdMS int64) error {
	tmp, err := os.MkdirTemp("", "strata-release-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	doc := map[string]any{
		"ir_version": 1,
		"ruleset":    map[string]any{"name": strings.TrimSuffix(filepath.Base(out), "-"+o.Version+".sbn"), "version": o.Version},
		"rules":      rules,
	}
	// the IR goes into the package: a control plane compiles it with its
	// own policies (-rules), as staging does with the v0 package
	irFile := strings.TrimSuffix(out, ".sbn") + ".rules.json"
	if err := writeJSON(irFile, doc); err != nil {
		return err
	}
	pol := o.Policies
	if pol == "" {
		pol = filepath.Join(tmp, "policies.json")
		if err := os.WriteFile(pol, []byte(`{"policies":[]}`), 0o644); err != nil {
			return err
		}
	}
	args := []string{
		"--policies", pol, "--rules", irFile, "--key", o.KeyFile,
		"--version", strconv.FormatUint(o.BundleVersion, 10),
		"--created-at", strconv.FormatInt(createdMS, 10),
		"--out", out,
		"--cost-report", filepath.Join(filepath.Dir(out), "cost.json"),
	}
	if o.NoHSBlock {
		args = append(args, "--no-hs-block")
	}
	cmd := exec.Command(bin, args...)
	if b, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("strata-compile: %v: %s", err, strings.TrimSpace(string(b)))
	}
	return nil
}

func writeChangelog(path string, m *Manifest, baseline string) error {
	var b strings.Builder
	title := "Strata signatures"
	switch m.Pack {
	case PackCore:
		title = "Strata core pack"
	case PackSignature:
		title = "Strata signature pack"
	}
	fmt.Fprintf(&b, "# %s %s\n\n", title, m.Version)
	fmt.Fprintf(&b, "- Built: %s\n- Bundle version: %d\n- SHA-256: `%s`\n- Rules: %d\n\n",
		m.CreatedAt, m.BundleVersion, m.SHA256, m.Rules)

	fmt.Fprintf(&b, "## By source\n\n| Source | Rules |\n| --- | ---: |\n")
	for _, k := range sortedKeys(m.BySource) {
		fmt.Fprintf(&b, "| %s | %d |\n", k, m.BySource[k])
	}
	fmt.Fprintf(&b, "\n## By action mode\n\n| action_mode | Rules |\n| --- | ---: |\n")
	for _, k := range sortedKeys(m.ByActionMode) {
		fmt.Fprintf(&b, "| %s | %d |\n", k, m.ByActionMode[k])
	}

	if baseline != "" {
		prev, err := loadManifest(baseline)
		if err != nil {
			return err
		}
		added, removed := diffIDs(prev.RuleIDs, m.RuleIDs)
		fmt.Fprintf(&b, "\n## Changes since %s\n\n- Added: %d rules %s\n- Removed: %d rules %s\n",
			prev.Version, len(added), idList(added), len(removed), idList(removed))
		changed, unknown := changedIDs(prev, m)
		fmt.Fprintf(&b, "- Modified: %d rules %s\n", len(changed), idList(changed))
		if unknown > 0 {
			fmt.Fprintf(&b, "- Content comparison unavailable for %d retained rules (legacy manifest without per-rule digests).\n", unknown)
		}
	}
	fmt.Fprintf(&b, "\nLicenses and sources: see NOTICE in this package.\n")
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func diffIDs(prev, cur []int) (added, removed []int) {
	in := func(xs []int, v int) bool {
		i := sort.SearchInts(xs, v)
		return i < len(xs) && xs[i] == v
	}
	for _, v := range cur {
		if !in(prev, v) {
			added = append(added, v)
		}
	}
	for _, v := range prev {
		if !in(cur, v) {
			removed = append(removed, v)
		}
	}
	return
}

func idList(ids []int) string {
	if len(ids) == 0 {
		return ""
	}
	parts := make([]string, len(ids))
	for i, v := range ids {
		parts[i] = strconv.Itoa(v)
	}
	return "(" + strings.Join(parts, ", ") + ")"
}

func sortedKeys(m map[string]int) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func loadManifest(path string) (*Manifest, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	sort.Ints(m.RuleIDs)
	return &m, nil
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

func copyFile(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, b, 0o644)
}

func asInt(v any) (int, bool) {
	switch n := v.(type) {
	case float64:
		return int(n), true
	case int:
		return n, true
	case json.Number:
		i, err := n.Int64()
		return int(i), err == nil
	}
	return 0, false
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func changedIDs(before, after *Manifest) (changed []int, unknown int) {
	present := map[int]bool{}
	for _, id := range before.RuleIDs {
		present[id] = true
	}
	for _, id := range after.RuleIDs {
		if !present[id] {
			continue
		}
		key := strconv.Itoa(id)
		a, aOK := before.RuleDigests[key]
		b, bOK := after.RuleDigests[key]
		if !aOK || !bOK {
			unknown++
			continue
		}
		if a != b {
			changed = append(changed, id)
		}
	}
	sort.Ints(changed)
	return
}
