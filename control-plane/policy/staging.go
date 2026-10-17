package policy

import (
	"fmt"
	"sort"
)

// stagingFor validates a compiler-internal effective overlay against delegation.
// Public policy JSON cannot supply effective IDs. A deployment caller must also
// verify approval/version and replay/input provenance before invoking Build.
func (c *Compiler) stagingFor(policies []Named) (map[string][]uint32, error) {
	if len(c.StagedRules) == 0 {
		return nil, nil
	}
	if len(c.StagedRules) > 4096 || len(policies) > 4096 {
		return nil, fmt.Errorf("staging: at most 4096 policies")
	}
	byName := make(map[string]Spec, len(policies))
	for _, p := range policies {
		if _, ok := byName[p.Name]; ok {
			return nil, fmt.Errorf("staging: duplicate policy")
		}
		byName[p.Name] = p.Spec
	}
	var out map[string][]uint32
	total := 0
	for name, ids := range c.StagedRules {
		spec, ok := byName[name]
		if !ok {
			return nil, fmt.Errorf("staging: unknown policy %q", name)
		}
		if len(ids) == 0 {
			continue
		}
		if len(ids) > 16 {
			return nil, fmt.Errorf("staging: at most 16 rules per policy")
		}
		total += len(ids)
		if total > 4096 {
			return nil, fmt.Errorf("staging: at most 4096 rules overall")
		}
		if err := spec.Validate(); err != nil {
			return nil, fmt.Errorf("staging: invalid policy: %w", err)
		}
		a := spec.AutoStaging
		if spec.Mode != "enforce" || a == nil || !a.Enabled {
			return nil, fmt.Errorf("staging: explicit enabled enforce-policy delegation required")
		}
		allowed := make(map[uint32]bool, len(a.RuleIDs))
		for _, id := range a.RuleIDs {
			allowed[id] = true
		}
		seen := make(map[uint32]bool, len(ids))
		for _, id := range ids {
			if !allowed[id] || seen[id] {
				return nil, fmt.Errorf("staging: duplicate or undelegated rule %d", id)
			}
			seen[id] = true
		}
		copyIDs := append([]uint32(nil), ids...)
		sort.Slice(copyIDs, func(i, j int) bool { return copyIDs[i] < copyIDs[j] })
		if out == nil {
			out = make(map[string][]uint32)
		}
		out[name] = copyIDs
	}
	return out, nil
}
