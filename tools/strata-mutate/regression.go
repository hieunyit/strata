package main

// Regression mode (22/10/2026): payloads that once passed Strata and were
// fixed (corpus/regression/*.jsonl) are sent where they passed (query,
// form, URL path; base64url-encoded when they passed that way), with every
// variant of internal/mutate. A fix covers the family, not one string:
//   - each seed must be blocked;
//   - each variant the baseline records as blocked must stay blocked;
//   - variants blocked now and not in the baseline are reported, and
//     --write-baseline records them.

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/strata/strata/tools/strata-mutate/internal/mutate"
)

type seed struct {
	ID         string `json:"id"`
	Payload    string `json:"payload"`
	AttackType string `json:"attack_type"`
	// query, form or path
	Carrier string `json:"carrier"`
	// "" or base64url (the payload, after the variant, is sent encoded)
	Encoding string `json:"encoding,omitempty"`
	Source   string `json:"source"`
}

func loadSeeds(dir string) ([]seed, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	var out []seed
	ids := map[string]bool{}
	for _, f := range files {
		fh, err := os.Open(f)
		if err != nil {
			return nil, err
		}
		sc := bufio.NewScanner(fh)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for n := 1; sc.Scan(); n++ {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			var s seed
			if err := json.Unmarshal([]byte(line), &s); err != nil {
				fh.Close()
				return nil, fmt.Errorf("%s:%d: %w", f, n, err)
			}
			switch {
			case s.ID == "" || s.Payload == "":
				err = fmt.Errorf("id and payload are required")
			case ids[s.ID]:
				err = fmt.Errorf("id %q twice", s.ID)
			case s.Carrier != "query" && s.Carrier != "form" && s.Carrier != "path":
				err = fmt.Errorf("carrier %q: query, form or path", s.Carrier)
			case s.Encoding != "" && s.Encoding != "base64url":
				err = fmt.Errorf("encoding %q: empty or base64url", s.Encoding)
			}
			if err != nil {
				fh.Close()
				return nil, fmt.Errorf("%s:%d: %w", f, n, err)
			}
			ids[s.ID] = true
			out = append(out, s)
		}
		fh.Close()
		if err := sc.Err(); err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no seeds under %s", dir)
	}
	return out, nil
}

// seedRequest: the request carrying value (a variant of s's payload).
func seedRequest(id string, s seed, v mutate.Variant) (request, bool) {
	if s.Encoding == "base64url" {
		// the target decodes base64 itself: URL encodings of the text do
		// not apply, and it is one value
		if v.Encoded || v.Split != "" {
			return request{}, false
		}
		v.Value = base64.RawURLEncoding.EncodeToString([]byte(v.Value))
		v.Encoded = true
	}
	if s.Carrier != "path" {
		values := []string{v.Value}
		if v.Split != "" {
			values = append(values, v.Split)
		}
		return build(id, s.Carrier, values, v.Encoded), true
	}
	if v.Split != "" {
		return request{}, false
	}
	seg := v.Value
	if !v.Encoded {
		seg = url.PathEscape(seg)
	}
	return request{ID: id, Method: "GET", URI: "/v1/items/" + seg,
		Headers: map[string]string{"Host": "api.example.test"}}, true
}

func runRegression(dir, baselinePath string, write bool, evalBin, bundle, pubkey, policy string) error {
	seeds, err := loadSeeds(dir)
	if err != nil {
		return err
	}
	var reqs []request
	for _, s := range seeds {
		r, _ := seedRequest(s.ID+"/seed", s, mutate.Variant{Transform: "seed", Value: s.Payload})
		reqs = append(reqs, r)
		for _, v := range mutate.Of(s.Payload) {
			if r, ok := seedRequest(s.ID+"/"+v.Transform, s, v); ok {
				reqs = append(reqs, r)
			}
		}
	}
	got, err := eval(evalBin, bundle, pubkey, policy, reqs)
	if err != nil {
		return err
	}
	baseline := map[string]bool{}
	if b, err := os.ReadFile(baselinePath); err == nil {
		var ids []string
		if err := json.Unmarshal(b, &ids); err != nil {
			return fmt.Errorf("%s: %w", baselinePath, err)
		}
		for _, id := range ids {
			baseline[id] = true
		}
	} else if !os.IsNotExist(err) || !write {
		return fmt.Errorf("baseline: %w", err)
	}
	var notBlocked, regressed, gained, blocked, passing []string
	variants, variantsBlocked := 0, 0
	for _, r := range reqs {
		isBlock := got[r.ID] == "block"
		if strings.HasSuffix(r.ID, "/seed") {
			if !isBlock {
				notBlocked = append(notBlocked, r.ID)
			}
			continue
		}
		variants++
		if isBlock {
			variantsBlocked++
			blocked = append(blocked, r.ID)
			if !baseline[r.ID] {
				gained = append(gained, r.ID)
			}
		} else if baseline[r.ID] {
			regressed = append(regressed, r.ID)
		} else {
			passing = append(passing, r.ID)
		}
	}
	fmt.Printf("strata-mutate regression: %d seeds, %d blocked; %d variants, %d blocked (%.1f%%)\n",
		len(seeds), len(seeds)-len(notBlocked), variants, variantsBlocked,
		float64(variantsBlocked)*100/float64(max(variants, 1)))
	show := func(what string, ids []string) {
		if len(ids) == 0 {
			return
		}
		fmt.Printf("%s (%d):\n", what, len(ids))
		for _, id := range ids[:min(len(ids), 40)] {
			fmt.Printf("  %s\n", id)
		}
	}
	show("seeds not blocked", notBlocked)
	show("variants blocked in the baseline, not now", regressed)
	show("variants blocked now, not in the baseline", gained)
	// variants still passing are the family's open part: listed, not a
	// failure
	show("variants still passing", passing)
	if write {
		sort.Strings(blocked)
		b, _ := json.MarshalIndent(blocked, "", " ")
		if err := os.WriteFile(baselinePath, append(b, '\n'), 0o644); err != nil {
			return err
		}
		fmt.Printf("baseline written: %d variants\n", len(blocked))
	}
	if len(notBlocked) > 0 || len(regressed) > 0 {
		return fmt.Errorf("%d seeds not blocked, %d variants regressed", len(notBlocked), len(regressed))
	}
	return nil
}
