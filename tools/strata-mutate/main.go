// Command strata-mutate measures how many variants of attack payloads get
// past Strata (W09-S-02). Every payload of corpus/attack is sent as the
// query parameter of a GET and as a field of a urlencoded POST (as
// `strata-rules report` sends it); each payload the bundle blocks is then
// mutated (internal/mutate: double URL encoding, case swap, SQL comments as
// spaces, unusual whitespace, Unicode NFC/NFD, parameter splitting, some
// combinations) and the variants are sent the same way. A variant
// "bypasses" when its payload was blocked and the variant is not.
//
//	strata-mutate --repo . --bundle <sbn> --pubkey <key> [--policy example-api]
//	              [--md docs/mutation-report.md] [--json build/mutate/summary.json]
//	              [--max-bypass PCT]
//
// The requests run through strata-eval (the engine, as the NGINX connector
// calls it): $STRATA_EVAL, <repo>/target/release/strata-eval, or PATH.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/strata/strata/tools/strata-mutate/internal/mutate"
)

type payload struct {
	Payload    string `json:"payload"`
	AttackType string `json:"attack_type"`
	Source     string `json:"source"`
}

type request struct {
	ID      string            `json:"id"`
	Method  string            `json:"method"`
	URI     string            `json:"uri"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body,omitempty"`
}

type verdict struct {
	ID     string `json:"id"`
	Action string `json:"action"`
}

// carriers: how a parameter value is sent
var carriers = []string{"query", "form"}

func build(id, carrier string, values []string, encoded bool) request {
	enc := make([]string, len(values))
	for i, v := range values {
		if encoded || preEncoded(v) {
			enc[i] = v
		} else {
			enc[i] = url.QueryEscape(v)
		}
	}
	h := map[string]string{"Host": "api.example.test"}
	if carrier == "query" {
		return request{ID: id, Method: "GET", URI: "/search?q=" + strings.Join(enc, "&q="), Headers: h}
	}
	body := "comment=" + strings.Join(enc, "&comment=")
	h["Content-Type"] = "application/x-www-form-urlencoded"
	h["Content-Length"] = strconv.Itoa(len(body))
	return request{ID: id, Method: "POST", URI: "/comments", Headers: h, Body: body}
}

// preEncoded: written URL-encoded already (%XX, no raw space), sent as it
// is, as `strata-rules report` does (corpus.Requests): escaping it again
// would turn every such payload into a double encoding.
func preEncoded(p string) bool {
	if strings.ContainsAny(p, " \t\r\n") {
		return false
	}
	for i := 0; i+2 < len(p); i++ {
		if p[i] == '%' && isHex(p[i+1]) && isHex(p[i+2]) {
			return true
		}
	}
	return false
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func find(repo string) string {
	if p := os.Getenv("STRATA_EVAL"); p != "" {
		return p
	}
	if p := filepath.Join(repo, "target", "release", "strata-eval"); fileExists(p) {
		return p
	}
	return "strata-eval"
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

func main() {
	repo := flag.String("repo", ".", "repository root (corpus/attack)")
	bundle := flag.String("bundle", "", "signed bundle (e.g. strata-rules release --policies)")
	pubkey := flag.String("pubkey", "", "its public key")
	policy := flag.String("policy", "example-api", "policy the requests run under")
	md := flag.String("md", "", "write the Markdown report there (default: stdout)")
	jsonOut := flag.String("json", "", "write the summary as JSON there")
	maxBypass := flag.Float64("max-bypass", -1, "fail when the overall bypass rate is above this percentage")
	flag.Parse()
	if *bundle == "" || *pubkey == "" {
		fmt.Fprintln(os.Stderr, "usage: strata-mutate --bundle <sbn> --pubkey <key> [--repo .] [--md file] [--json file]")
		os.Exit(2)
	}
	payloads, err := load(filepath.Join(*repo, "corpus", "attack"))
	if err != nil {
		die(err)
	}

	// 1. the payloads as they are
	var base []request
	for i, p := range payloads {
		for _, c := range carriers {
			base = append(base, build(fmt.Sprintf("%d/%s", i, c), c, []string{p.Payload}, false))
		}
	}
	bv, err := eval(find(*repo), *bundle, *pubkey, *policy, base)
	if err != nil {
		die(err)
	}

	// 2. the variants of each (payload, carrier) the bundle blocks
	var vars []request
	for i, p := range payloads {
		for _, c := range carriers {
			if bv[fmt.Sprintf("%d/%s", i, c)] != "block" {
				continue
			}
			for _, v := range mutate.Of(p.Payload) {
				values := []string{v.Value}
				if v.Split != "" {
					values = append(values, v.Split)
				}
				vars = append(vars, build(fmt.Sprintf("%d/%s/%s", i, c, v.Transform), c, values, v.Encoded))
			}
		}
	}
	vv, err := eval(find(*repo), *bundle, *pubkey, *policy, vars)
	if err != nil {
		die(err)
	}

	s := summarize(payloads, bv, vars, vv)
	out := os.Stdout
	if *md != "" {
		f, err := os.Create(*md)
		if err != nil {
			die(err)
		}
		defer f.Close()
		out = f
	}
	s.markdown(out)
	if *jsonOut != "" {
		b, _ := json.MarshalIndent(s, "", "  ")
		if err := os.WriteFile(*jsonOut, append(b, '\n'), 0o644); err != nil {
			die(err)
		}
	}
	fmt.Fprintf(os.Stderr, "strata-mutate: %d payloads, %d variants of blocked ones, %d bypass (%.1f%%)\n",
		len(payloads), s.Total.Tested, s.Total.Bypassed, s.Total.Rate())
	if *maxBypass >= 0 && s.Total.Rate() > *maxBypass {
		fmt.Fprintf(os.Stderr, "strata-mutate: bypass rate %.1f%% over %.1f%%\n", s.Total.Rate(), *maxBypass)
		os.Exit(1)
	}
}

func die(err error) {
	fmt.Fprintln(os.Stderr, "strata-mutate:", err)
	os.Exit(1)
}

func load(dir string) ([]payload, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	var out []payload
	for _, f := range files {
		fh, err := os.Open(f)
		if err != nil {
			return nil, err
		}
		sc := bufio.NewScanner(fh)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			var p payload
			if json.Unmarshal(sc.Bytes(), &p) == nil && p.Payload != "" {
				out = append(out, p)
			}
		}
		fh.Close()
		if err := sc.Err(); err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no payloads under %s", dir)
	}
	return out, nil
}

// eval runs reqs through strata-eval; id -> action.
func eval(bin, bundle, pubkey, policy string, reqs []request) (map[string]string, error) {
	cmd := exec.Command(bin, "--bundle", bundle, "--pubkey", pubkey, "--policy", policy)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("strata-eval: %w", err)
	}
	go func() {
		w := bufio.NewWriter(stdin)
		enc := json.NewEncoder(w)
		for _, r := range reqs {
			_ = enc.Encode(r)
		}
		_ = w.Flush()
		_ = stdin.Close()
	}()
	out := make(map[string]string, len(reqs))
	dec := json.NewDecoder(stdout)
	for {
		var v verdict
		if err := dec.Decode(&v); err == io.EOF {
			break
		} else if err != nil {
			return nil, fmt.Errorf("strata-eval output: %w", err)
		}
		out[v.ID] = v.Action
	}
	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("strata-eval: %w", err)
	}
	if len(out) != len(reqs) {
		return nil, fmt.Errorf("strata-eval answered %d of %d requests", len(out), len(reqs))
	}
	return out, nil
}

// Count is variants of blocked payloads tested and bypassing.
type Count struct {
	Tested   int `json:"tested"`
	Bypassed int `json:"bypassed"`
}

// Rate is the bypass percentage.
func (c Count) Rate() float64 {
	if c.Tested == 0 {
		return 0
	}
	return float64(c.Bypassed) * 100 / float64(c.Tested)
}

type Summary struct {
	Payloads    map[string]int              `json:"payloads"` // per attack type
	Blocked     map[string]int              `json:"blocked"`  // payload x carrier blocked, per attack type
	Sent        map[string]int              `json:"sent"`     // payload x carrier, per attack type
	ByType      map[string]Count            `json:"by_attack_type"`
	ByTransform map[string]Count            `json:"by_transform"`
	Cells       map[string]map[string]Count `json:"cells"` // attack type -> transform
	Total       Count                       `json:"total"`
	Examples    map[string][]string         `json:"examples"` // transform -> bypassing payloads
}

func summarize(payloads []payload, bv map[string]string, vars []request, vv map[string]string) *Summary {
	s := &Summary{Payloads: map[string]int{}, Blocked: map[string]int{}, Sent: map[string]int{},
		ByType: map[string]Count{}, ByTransform: map[string]Count{}, Cells: map[string]map[string]Count{},
		Examples: map[string][]string{}}
	for i, p := range payloads {
		s.Payloads[p.AttackType]++
		for _, c := range carriers {
			s.Sent[p.AttackType]++
			if bv[fmt.Sprintf("%d/%s", i, c)] == "block" {
				s.Blocked[p.AttackType]++
			}
		}
	}
	for _, r := range vars {
		parts := strings.SplitN(r.ID, "/", 3)
		i, _ := strconv.Atoi(parts[0])
		at, tr := payloads[i].AttackType, parts[2]
		by := vv[r.ID] != "block"
		inc := func(c Count) Count {
			c.Tested++
			if by {
				c.Bypassed++
			}
			return c
		}
		s.ByType[at] = inc(s.ByType[at])
		s.ByTransform[tr] = inc(s.ByTransform[tr])
		if s.Cells[at] == nil {
			s.Cells[at] = map[string]Count{}
		}
		s.Cells[at][tr] = inc(s.Cells[at][tr])
		s.Total = inc(s.Total)
		if by && len(s.Examples[tr]) < 3 {
			ex := payloads[i].Payload
			if len(ex) > 80 {
				ex = ex[:80] + "…"
			}
			s.Examples[tr] = append(s.Examples[tr], fmt.Sprintf("%s (%s, %s)", ex, at, parts[1]))
		}
	}
	return s
}

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (s *Summary) markdown(w io.Writer) {
	fmt.Fprintf(w, "## Payload variants against Strata\n\n")
	fmt.Fprintf(w, "Generated by `make mutate` (`tools/strata-mutate`, W09-S-02). Each payload of `corpus/attack` is sent in a query parameter and in a urlencoded form field; every one the bundle blocks is mutated and sent again the same way. A variant **bypasses** when its payload is blocked and the variant is not. Lower is better.\n\n")
	fmt.Fprintf(w, "| Attack type | Payloads | Blocked (query + form) | Variants tested | Bypassed | Bypass %% |\n| --- | ---: | ---: | ---: | ---: | ---: |\n")
	for _, at := range keys(s.Payloads) {
		c := s.ByType[at]
		fmt.Fprintf(w, "| %s | %d | %d / %d | %d | %d | %.1f |\n", at, s.Payloads[at], s.Blocked[at], s.Sent[at], c.Tested, c.Bypassed, c.Rate())
	}
	fmt.Fprintf(w, "| **all** | | | %d | %d | %.1f |\n", s.Total.Tested, s.Total.Bypassed, s.Total.Rate())

	fmt.Fprintf(w, "\n### Bypass %% by transform and attack type\n\n| Transform |")
	types := keys(s.Payloads)
	for _, at := range types {
		fmt.Fprintf(w, " %s |", at)
	}
	fmt.Fprintf(w, " all |\n| --- |%s ---: |\n", strings.Repeat(" ---: |", len(types)))
	for _, tr := range mutate.Transforms {
		if s.ByTransform[tr].Tested == 0 {
			continue
		}
		fmt.Fprintf(w, "| %s |", tr)
		for _, at := range types {
			if c, ok := s.Cells[at][tr]; ok && c.Tested > 0 {
				fmt.Fprintf(w, " %.1f (%d/%d) |", c.Rate(), c.Bypassed, c.Tested)
			} else {
				fmt.Fprintf(w, " — |")
			}
		}
		c := s.ByTransform[tr]
		fmt.Fprintf(w, " %.1f |\n", c.Rate())
	}
	if len(s.Examples) > 0 {
		fmt.Fprintf(w, "\n### Examples of bypassing variants (first payloads per transform)\n\n")
		for _, tr := range mutate.Transforms {
			for _, ex := range s.Examples[tr] {
				fmt.Fprintf(w, "- `%s`: `%s`\n", tr, strings.ReplaceAll(ex, "`", "'"))
			}
		}
	}
}
