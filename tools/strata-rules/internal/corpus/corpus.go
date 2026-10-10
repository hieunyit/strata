// Package corpus is the test corpus of corpus/ (W04-S-01): attack payloads
// with their attack type and origin (corpus/attack/<type>.jsonl, fetched
// from pinned commits of MIT-licensed lists), and benign requests
// (corpus/benign/*.jsonl, generated). Payloads become requests the way an
// attacker sends them: in a query parameter and in a form field (and in the
// path, for path traversal).
package corpus

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/strata/strata/tools/strata-rules/internal/runner"
)

// Payload is one attack string.
type Payload struct {
	Payload    string `json:"payload"`
	AttackType string `json:"attack_type"`
	Source     string `json:"source"` // repo@commit:path:line
	License    string `json:"license"`
}

// Sources is corpus/sources.yaml.
type Sources struct {
	MaxPerFile int `yaml:"max_per_file"`
	MaxLength  int `yaml:"max_length"`
	Sources    []struct {
		Repo   string `yaml:"repo"`
		Commit string `yaml:"commit"`
		Files  []struct {
			Path string `yaml:"path"`
			Type string `yaml:"type"`
		} `yaml:"files"`
	} `yaml:"sources"`
}

// Fetch downloads the payload files of sources and writes
// <out>/<attack type>.jsonl, deduplicated and sorted, so a rerun at the
// same commits gives the same files.
func Fetch(sourcesFile, out string) (map[string]int, error) {
	raw, err := os.ReadFile(sourcesFile)
	if err != nil {
		return nil, err
	}
	var src Sources
	if err := yaml.Unmarshal(raw, &src); err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: time.Minute}
	byType := map[string][]Payload{}
	seen := map[string]bool{}
	for _, s := range src.Sources {
		for _, f := range s.Files {
			u := "https://raw.githubusercontent.com/" + s.Repo + "/" + s.Commit + "/" + (&url.URL{Path: f.Path}).EscapedPath()
			resp, err := client.Get(u)
			if err != nil {
				return nil, err
			}
			body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
			resp.Body.Close()
			if err != nil {
				return nil, err
			}
			if resp.StatusCode != http.StatusOK {
				return nil, fmt.Errorf("%s: %s", u, resp.Status)
			}
			var list []Payload
			for i, line := range strings.Split(string(body), "\n") {
				line = strings.TrimRight(line, "\r")
				if strings.TrimSpace(line) == "" || len(line) > src.MaxLength {
					continue
				}
				key := f.Type + "\x00" + line
				if seen[key] {
					continue
				}
				seen[key] = true
				list = append(list, Payload{Payload: line, AttackType: f.Type, License: "MIT",
					Source: fmt.Sprintf("%s@%s:%s:%d", s.Repo, s.Commit[:12], f.Path, i+1)})
			}
			if src.MaxPerFile > 0 && len(list) > src.MaxPerFile {
				r := rand.New(rand.NewPCG(1, uint64(len(f.Path))))
				r.Shuffle(len(list), func(i, j int) { list[i], list[j] = list[j], list[i] })
				list = list[:src.MaxPerFile]
			}
			byType[f.Type] = append(byType[f.Type], list...)
		}
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		return nil, err
	}
	counts := map[string]int{}
	for t, list := range byType {
		sort.Slice(list, func(i, j int) bool { return list[i].Source < list[j].Source })
		f, err := os.Create(filepath.Join(out, t+".jsonl"))
		if err != nil {
			return nil, err
		}
		enc := json.NewEncoder(f)
		enc.SetEscapeHTML(false)
		for _, p := range list {
			if err := enc.Encode(p); err != nil {
				f.Close()
				return nil, err
			}
		}
		if err := f.Close(); err != nil {
			return nil, err
		}
		counts[t] = len(list)
	}
	return counts, nil
}

// Corpus is what Load read.
type Corpus struct {
	Attacks []Payload
	Benign  []runner.Request
}

// Load reads dir/attack/*.jsonl and dir/benign/*.jsonl.
func Load(dir string) (*Corpus, error) {
	c := &Corpus{}
	read := func(glob string, each func([]byte) error) error {
		files, err := filepath.Glob(filepath.Join(dir, glob))
		if err != nil {
			return err
		}
		sort.Strings(files)
		for _, p := range files {
			f, err := os.Open(p)
			if err != nil {
				return err
			}
			sc := bufio.NewScanner(f)
			sc.Buffer(make([]byte, 1<<20), 1<<20)
			for n := 1; sc.Scan(); n++ {
				if len(strings.TrimSpace(sc.Text())) == 0 {
					continue
				}
				if err := each(sc.Bytes()); err != nil {
					f.Close()
					return fmt.Errorf("%s:%d: %w", p, n, err)
				}
			}
			f.Close()
			if err := sc.Err(); err != nil {
				return err
			}
		}
		return nil
	}
	if err := read("attack/*.jsonl", func(b []byte) error {
		var p Payload
		if err := json.Unmarshal(b, &p); err != nil {
			return err
		}
		c.Attacks = append(c.Attacks, p)
		return nil
	}); err != nil {
		return nil, err
	}
	err := read("benign/*.jsonl", func(b []byte) error {
		var r runner.Request
		if err := json.Unmarshal(b, &r); err != nil {
			return err
		}
		c.Benign = append(c.Benign, r)
		return nil
	})
	return c, err
}

// Requests turns a payload into the requests that carry it.
func Requests(p Payload, id string) []runner.Request {
	q := url.QueryEscape(p.Payload)
	reqs := []runner.Request{
		{ID: id + "/query", URI: "/search?q=" + q, Headers: map[string]any{"Host": "api.example.test"}},
		{ID: id + "/form", Method: "POST", URI: "/comments", Body: "comment=" + q,
			Headers: map[string]any{"Host": "api.example.test", "Content-Type": "application/x-www-form-urlencoded"}},
	}
	if p.AttackType == "path-traversal" {
		// in the path as sent: the payload carries its own encoding
		path := strings.TrimLeft(p.Payload, "/")
		if !strings.ContainsAny(path, " \t#?") {
			reqs = append(reqs, runner.Request{ID: id + "/path", URI: "/static/" + path, Headers: map[string]any{"Host": "api.example.test"}})
		}
	}
	return reqs
}
