package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"
)

// Named is a policy as it goes into a bundle.
type Named struct {
	Name string
	Spec Spec
}

// Compiler runs strata-compile.
type Compiler struct {
	Binary         string   // default "strata-compile" from PATH
	KeyFile        string   // Ed25519 seed (32 bytes) that signs bundles
	Rules          []string // IR files (docs/spec/ir.schema.json)
	BlockPage      string   // HTML file of the default block page; optional
	SupportContact string
	Timeout        time.Duration // default 2 min
}

// Build compiles and signs a bundle of version holding policies.
func (c *Compiler) Build(ctx context.Context, version uint64, policies []Named) ([]byte, error) {
	if len(policies) == 0 {
		return nil, ErrNoPolicies
	}
	dir, err := os.MkdirTemp("", "strata-bundle-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)

	type item struct {
		Name     string    `json:"name"`
		Mode     string    `json:"mode"`
		Oversize string    `json:"oversize,omitempty"`
		Response *Response `json:"response,omitempty"`
	}
	doc := map[string]any{}
	items := make([]item, 0, len(policies))
	for _, p := range policies {
		items = append(items, item{Name: p.Name, Mode: p.Spec.Mode, Oversize: p.Spec.Oversize, Response: p.Spec.Response})
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
	args := []string{"--policies", polFile, "--key", c.KeyFile, "--version", strconv.FormatUint(version, 10), "--out", out}
	for _, r := range c.Rules {
		args = append(args, "--rules", r)
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
	return os.ReadFile(out)
}
