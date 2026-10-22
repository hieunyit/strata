package rulecat

import (
	"slices"
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
	out, next, _ := c.SearchFunc(after, limit, func(v Entry) bool {
		if source != "" && v.Source != source || attack != "" && v.AttackType != attack {
			return false
		}
		return cve == "" || slices.Contains(v.CVEs, strings.ToUpper(cve))
	})
	return out, next
}

// SearchFunc: the entries keep accepts after Rule ID after, at most limit
// (1..200), the cursor of the next page (0: none) and how many match.
func (c *Catalog) SearchFunc(after uint32, limit int, keep func(Entry) bool) ([]Entry, uint32, int) {
	if limit < 1 || limit > 200 {
		limit = 200
	}
	out, next, matched := []Entry{}, uint32(0), 0
	for _, v := range c.Entries() {
		if !keep(v) {
			continue
		}
		matched++
		if v.ID <= after {
			continue
		}
		if len(out) == limit {
			if next == 0 {
				next = out[len(out)-1].ID
			}
			continue
		}
		out = append(out, v)
	}
	return out, next, matched
}

// Facets: the sources and attack types of the catalog's rules, sorted,
// for filters to choose from.
func (c *Catalog) Facets() (sources, attackTypes []string) {
	seen := map[string]bool{}
	sources, attackTypes = []string{}, []string{}
	for _, v := range c.Entries() {
		if v.Source != "" && !seen["s:"+v.Source] {
			seen["s:"+v.Source] = true
			sources = append(sources, v.Source)
		}
		if v.AttackType != "" && !seen["a:"+v.AttackType] {
			seen["a:"+v.AttackType] = true
			attackTypes = append(attackTypes, v.AttackType)
		}
	}
	slices.Sort(sources)
	slices.Sort(attackTypes)
	return sources, attackTypes
}
