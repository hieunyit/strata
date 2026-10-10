// Package runner compiles rules into a bundle with strata-compile and runs
// requests through libstrata with strata-eval: rule tests and corpus
// reports use the real engine, never a model of it.
package runner

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
)

// Tools are the two binaries.
type Tools struct {
	CompileBin string // strata-compile
	EvalBin    string // strata-eval
}

// Find locates the binaries: $STRATA_COMPILE / $STRATA_EVAL, then
// <repo>/target/release, then PATH.
func Find(repo string) (Tools, error) {
	find := func(env, name string) (string, error) {
		if p := os.Getenv(env); p != "" {
			return p, nil
		}
		if p := filepath.Join(repo, "target", "release", name); isExec(p) {
			return p, nil
		}
		p, err := exec.LookPath(name)
		if err != nil {
			return "", fmt.Errorf("%s not found: build it (cargo build --release -p %s) or set %s", name, name, env)
		}
		return p, nil
	}
	c, err := find("STRATA_COMPILE", "strata-compile")
	if err != nil {
		return Tools{}, err
	}
	e, err := find("STRATA_EVAL", "strata-eval")
	if err != nil {
		return Tools{}, err
	}
	return Tools{CompileBin: c, EvalBin: e}, nil
}

func isExec(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir() && st.Mode()&0o111 != 0
}

// Capabilities of the engine (strata-eval --capabilities).
type Capabilities struct {
	Operators  []string `json:"operators"`
	Transforms []string `json:"transforms"`
	Vars       []string `json:"vars"`
}

// Has reports whether list contains s.
func Has(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// Capabilities asks the engine what it evaluates.
func (t Tools) Capabilities() (Capabilities, error) {
	out, err := exec.Command(t.EvalBin, "--capabilities").Output()
	if err != nil {
		return Capabilities{}, fmt.Errorf("strata-eval --capabilities: %w", err)
	}
	var c Capabilities
	return c, json.Unmarshal(out, &c)
}

// Bundle is a compiled, signed bundle and its public key.
type Bundle struct {
	Dir, Path, PubKey string
}

// PolicyName of the single enforcing policy test bundles carry.
const PolicyName = "strata-rules"

// Build compiles IR documents (JSON) into a bundle signed with a fresh
// key, in a temporary directory removed by Close.
func (t Tools) Build(irDocs [][]byte) (*Bundle, error) {
	dir, err := os.MkdirTemp("", "strata-rules-")
	if err != nil {
		return nil, err
	}
	b := &Bundle{Dir: dir, Path: filepath.Join(dir, "bundle.sbn"), PubKey: filepath.Join(dir, "bundle.pub")}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Close()
		return nil, err
	}
	keyFile := filepath.Join(dir, "bundle.key")
	if err := os.WriteFile(keyFile, priv.Seed(), 0o600); err != nil {
		b.Close()
		return nil, err
	}
	if err := os.WriteFile(b.PubKey, pub, 0o644); err != nil {
		b.Close()
		return nil, err
	}
	pol := filepath.Join(dir, "policies.json")
	if err := os.WriteFile(pol, []byte(`{"policies":[{"name":"`+PolicyName+`","mode":"enforce"}]}`), 0o644); err != nil {
		b.Close()
		return nil, err
	}
	args := []string{"--policies", pol, "--key", keyFile, "--version", "1", "--created-at", "1", "--out", b.Path}
	for i, doc := range irDocs {
		f := filepath.Join(dir, "rules-"+strconv.Itoa(i)+".json")
		if err := os.WriteFile(f, doc, 0o644); err != nil {
			b.Close()
			return nil, err
		}
		args = append(args, "--rules", f)
	}
	var stderr bytes.Buffer
	cmd := exec.Command(t.CompileBin, args...)
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		b.Close()
		return nil, fmt.Errorf("strata-compile: %v: %s", err, bytes.TrimSpace(stderr.Bytes()))
	}
	return b, nil
}

// Close removes the bundle's directory.
func (b *Bundle) Close() { _ = os.RemoveAll(b.Dir) }

// Request is one request for strata-eval.
type Request struct {
	ID         string         `json:"id"`
	Method     string         `json:"method,omitempty"`
	URI        string         `json:"uri"`
	Headers    map[string]any `json:"headers,omitempty"` // string or []string
	Body       string         `json:"body,omitempty"`
	RemoteAddr string         `json:"remote_addr,omitempty"`
	Protocol   string         `json:"protocol,omitempty"`
}

// Verdict is strata-eval's answer.
type Verdict struct {
	ID     string   `json:"id"`
	Action string   `json:"action"`
	Score  int      `json:"score"`
	Rules  []uint32 `json:"rules"`
	Error  int      `json:"error"`
}

// Matched reports whether rule id is among the verdict's rules.
func (v Verdict) Matched(id uint32) bool {
	for _, r := range v.Rules {
		if r == id {
			return true
		}
	}
	return false
}

// Eval runs reqs through the bundle under the test policy, in order.
func (t Tools) Eval(b *Bundle, reqs []Request) ([]Verdict, error) {
	var in bytes.Buffer
	enc := json.NewEncoder(&in)
	for _, r := range reqs {
		if err := enc.Encode(r); err != nil {
			return nil, err
		}
	}
	var stderr bytes.Buffer
	cmd := exec.Command(t.EvalBin, "--bundle", b.Path, "--pubkey", b.PubKey, "--policy", PolicyName)
	cmd.Stdin = &in
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("strata-eval: %v: %s", err, bytes.TrimSpace(stderr.Bytes()))
	}
	var vs []Verdict
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var v Verdict
		if err := json.Unmarshal(sc.Bytes(), &v); err != nil {
			return nil, fmt.Errorf("strata-eval output: %w", err)
		}
		vs = append(vs, v)
	}
	if len(vs) != len(reqs) {
		return nil, errors.New("strata-eval: one verdict per request expected")
	}
	return vs, sc.Err()
}
