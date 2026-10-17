package policy

import (
	"context"
	"errors"
	"fmt"
)

// StagingReader loads effective state for immutable policy resource versions.
// Production supplies the same durable store to replay and deployment.
type StagingReader interface {
	StagedRules(context.Context, map[string]int) (map[string][]uint32, error)
}

func (c *Compiler) withStaging(ctx context.Context, policies []Named) (*Compiler, error) {
	if len(policies) < 1 || len(policies) > 4096 {
		return nil, errors.New("staging: 1 to 4096 policies required")
	}
	if len(c.StagedRules) != 0 {
		return nil, errors.New("staging: explicit overlay cannot replace durable state")
	}
	versions := make(map[string]int, len(policies))
	names := make(map[string]string, len(policies))
	seenNames := make(map[string]bool, len(policies))
	for _, p := range policies {
		if p.ResourceID == "" || p.Version < 1 || p.Name == "" || seenNames[p.Name] || names[p.ResourceID] != "" {
			return nil, errors.New("staging: unique policy resources, versions and names required")
		}
		versions[p.ResourceID] = p.Version
		names[p.ResourceID] = p.Name
		seenNames[p.Name] = true
	}
	state, err := c.StagingStore.StagedRules(ctx, versions)
	if err != nil {
		return nil, fmt.Errorf("staging: load effective state: %w", err)
	}
	next := *c
	next.StagingStore = nil // captured once; a Prepared build never re-reads state
	next.StagedRules = make(map[string][]uint32, len(state))
	for id, rules := range state {
		name, ok := names[id]
		if !ok {
			return nil, errors.New("staging: store returned an unrequested policy")
		}
		next.StagedRules[name] = append([]uint32(nil), rules...)
	}
	// Validate allowlists, modes and codec limits before any compiler subprocess.
	normalized, err := next.stagingFor(policies)
	if err != nil {
		return nil, err
	}
	next.StagedRules = normalized
	return &next, nil
}
