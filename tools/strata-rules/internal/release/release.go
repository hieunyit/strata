// Package release builds a signature package from the rule repository
// (W08-S-01): every rule compiled into one signed bundle, with a version, a
// changelog and the NOTICE that records each source and its license.
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
	Version       string         `json:"version"`
	BundleVersion uint64         `json:"bundle_version"`
	CreatedAt     string         `json:"created_at"`
	Bundle        string         `json:"bundle"`
	SHA256        string         `json:"sha256"`
	Rules         int            `json:"rules"`
	BySource      map[string]int `json:"by_source"`
	ByLicense     map[string]int `json:"by_license"`
	ByActionMode  map[string]int `json:"by_action_mode"`
	RuleIDs       []int          `json:"rule_ids"`
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
	tools, err := runner.Find(o.Repo)
	if err != nil {
		return nil, err
	}
	rules, err := report.RulesUnder(o.RulesDir)
	if err != nil {
		return nil, err
	}
	if len(rules) == 0 {
		return nil, fmt.Errorf("no rules under %s", o.RulesDir)
	}

	if err := os.MkdirAll(o.Out, 0o755); err != nil {
		return nil, err
	}
	name := "strata-signatures-" + o.Version
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
		BundleVersion: o.BundleVersion,
		CreatedAt:     time.UnixMilli(nowMS).UTC().Format(time.RFC3339),
		Bundle:        filepath.Base(bundlePath),
		SHA256:        hex.EncodeToString(sum[:]),
		Rules:         len(rules),
		BySource:      map[string]int{},
		ByLicense:     map[string]int{},
		ByActionMode:  map[string]int{},
	}
	for _, r := range rules {
		if id, ok := asInt(r["id"]); ok {
			m.RuleIDs = append(m.RuleIDs, id)
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
	for _, f := range []string{name + ".pub", "NOTICE", "CHANGELOG.md"} {
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
		"ruleset":    map[string]any{"name": "strata-signatures", "version": o.Version},
		"rules":      rules,
	}
	irFile := filepath.Join(tmp, "rules.json")
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
	}
	cmd := exec.Command(bin, args...)
	if b, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("strata-compile: %v: %s", err, strings.TrimSpace(string(b)))
	}
	return nil
}

func writeChangelog(path string, m *Manifest, baseline string) error {
	var b strings.Builder
	fmt.Fprintf(&b, "# Strata signatures %s\n\n", m.Version)
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
