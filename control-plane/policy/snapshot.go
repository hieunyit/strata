package policy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
)

// Prepared compiles from private copies of the exact inputs committed by Digest.
// The caller must Close it. Signing keys and the bundle version are deliberately
// excluded: replay uses its own signing key and the deploy's version is allocated later.
type Prepared struct {
	Digest   string
	compiler Compiler
	policies []Named
	dir      string
}

func (p *Prepared) Close() { _ = os.RemoveAll(p.dir) }
func (p *Prepared) Build(ctx context.Context, version uint64) ([]byte, error) {
	return p.compiler.Build(ctx, version, p.policies)
}
func (p *Prepared) ReplayBuild(ctx context.Context, key string) ([]byte, error) {
	c := p.compiler
	c.Signer = nil
	c.KeyFile = key
	return c.Build(ctx, 1, p.policies)
}

// Prepare snapshots compiler binary, ordered rule files, block page, policies
// and privacy identity key before either replay or deploy starts compiling.
func (c *Compiler) Prepare(ctx context.Context, policies []Named) (prepared *Prepared, err error) {
	if len(policies) == 0 {
		return nil, ErrNoPolicies
	}
	dir, err := os.MkdirTemp("", "strata-inputs-")
	if err != nil {
		return nil, err
	}
	p := &Prepared{dir: dir, compiler: *c}
	defer func() {
		if err != nil {
			p.Close()
		}
	}()
	// Deep-copy policies so a caller cannot mutate a privacy slice after hashing it.
	raw, err := json.Marshal(policies)
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(raw, &p.policies); err != nil {
		return nil, err
	}
	type manifest struct {
		Format         int
		Compiler       string
		Rules          []string
		BlockPage      string
		Policies       []Named
		SupportContact string
		CostBudget     uint64
		IdentityKey    string
	}
	m := manifest{Format: 1, Policies: p.policies, SupportContact: c.SupportContact, CostBudget: c.CostBudget}
	remaining := int64(512 << 20)
	snapshot := func(src, label string, mode os.FileMode) (string, string, error) {
		in, err := os.Open(src)
		if err != nil {
			return "", "", fmt.Errorf("snapshot %s: %w", label, err)
		}
		defer in.Close()
		info, err := in.Stat()
		if err != nil {
			return "", "", err
		}
		if !info.Mode().IsRegular() || info.Size() > remaining {
			return "", "", fmt.Errorf("snapshot %s: not a bounded regular file", label)
		}
		dst := filepath.Join(dir, label)
		out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
		if err != nil {
			return "", "", err
		}
		h := sha256.New()
		limited := io.LimitReader(in, remaining+1)
		buf := make([]byte, 64<<10)
		var total int64
		for {
			if err = ctx.Err(); err != nil {
				break
			}
			n, readErr := limited.Read(buf)
			if n > 0 {
				written, writeErr := io.MultiWriter(out, h).Write(buf[:n])
				total += int64(written)
				if writeErr != nil {
					err = writeErr
					break
				}
			}
			if readErr != nil {
				err = readErr
				break
			}
			if n == 0 {
				err = io.ErrNoProgress
				break
			}
		}
		closeErr := out.Close()
		if err != nil && err != io.EOF {
			return "", "", fmt.Errorf("snapshot %s: %w", label, err)
		}
		if closeErr != nil {
			return "", "", closeErr
		}
		if total > remaining {
			return "", "", fmt.Errorf("snapshot exceeds 512 MiB")
		}
		remaining -= total
		return dst, hex.EncodeToString(h.Sum(nil)), nil
	}
	bin := c.Binary
	if bin == "" {
		bin = "strata-compile"
	}
	bin, err = exec.LookPath(bin)
	if err != nil {
		return nil, err
	}
	p.compiler.Binary, m.Compiler, err = snapshot(bin, "compiler", 0700)
	if err != nil {
		return nil, err
	}
	p.compiler.Rules = nil
	for i, r := range c.Rules {
		file, sum, e := snapshot(r, "rules-"+strconv.Itoa(i), 0600)
		if e != nil {
			return nil, e
		}
		p.compiler.Rules = append(p.compiler.Rules, file)
		m.Rules = append(m.Rules, sum)
	}
	if c.BlockPage != "" {
		p.compiler.BlockPage, m.BlockPage, err = snapshot(c.BlockPage, "block-page", 0600)
		if err != nil {
			return nil, err
		}
	}
	if needsIdentityKey(p.policies) {
		if c.IdentityKey == nil {
			return nil, fmt.Errorf("snapshot: identity key missing")
		}
		key, e := c.IdentityKey(ctx)
		if e != nil {
			return nil, e
		}
		key = append([]byte(nil), key...)
		sum := sha256.Sum256(key)
		m.IdentityKey = hex.EncodeToString(sum[:])
		p.compiler.IdentityKey = func(context.Context) ([]byte, error) { return append([]byte(nil), key...), nil }
	}
	raw, err = json.Marshal(m)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(raw)
	p.Digest = hex.EncodeToString(digest[:])
	return p, nil
}
