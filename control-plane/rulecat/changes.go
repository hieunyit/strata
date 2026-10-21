package rulecat

import (
	"sort"
	"strings"
)

type Change struct {
	ID     uint32 `json:"id"`
	Kind   string `json:"kind"`
	Before *Rule  `json:"before,omitempty"`
	After  *Rule  `json:"after,omitempty"`
}
type Changes struct {
	Added    int      `json:"added"`
	Removed  int      `json:"removed"`
	Modified int      `json:"modified"`
	Changes  []Change `json:"changes"`
	Next     uint32   `json:"next_cursor"`
}

// Diff compares full canonical rule digests, not only ID membership. Metadata
// changes are included because ownership/review/source versions matter too.
func Diff(before, after []Entry, cursor uint32, limit int) Changes {
	if limit < 1 || limit > 200 {
		limit = 200
	}
	old, current := map[uint32]Rule{}, map[uint32]Rule{}
	ids := map[uint32]bool{}
	for _, v := range before {
		old[v.ID] = v.Rule
		ids[v.ID] = true
	}
	for _, v := range after {
		current[v.ID] = v.Rule
		ids[v.ID] = true
	}
	sorted := []uint32{}
	for id := range ids {
		sorted = append(sorted, id)
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	out := Changes{Changes: []Change{}}
	for _, id := range sorted {
		a, aOK := old[id]
		b, bOK := current[id]
		change := Change{ID: id}
		switch {
		case !aOK:
			change.Kind = "added"
			change.After = &b
			out.Added++
		case !bOK:
			change.Kind = "removed"
			change.Before = &a
			out.Removed++
		case a.Digest != b.Digest:
			change.Kind = "modified"
			change.Before = &a
			change.After = &b
			out.Modified++
		default:
			continue
		}
		if id <= cursor {
			continue
		}
		if len(out.Changes) == limit {
			if out.Next == 0 {
				out.Next = out.Changes[len(out.Changes)-1].ID
			}
			continue
		}
		out.Changes = append(out.Changes, change)
	}
	return out
}
func (c *Catalog) Search(source, cve, attack string, after uint32, limit int) ([]Entry, uint32) {
	if limit < 1 || limit > 200 {
		limit = 200
	}
	out := []Entry{}
	for _, v := range c.Entries() {
		if v.ID <= after || source != "" && v.Source != source || attack != "" && v.AttackType != attack {
			continue
		}
		if cve != "" {
			matched := false
			for _, x := range v.CVEs {
				if x == strings.ToUpper(cve) {
					matched = true
				}
			}
			if !matched {
				continue
			}
		}
		if len(out) == limit {
			return out, out[len(out)-1].ID
		}
		out = append(out, v)
	}
	return out, 0
}
