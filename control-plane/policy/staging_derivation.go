package policy

import "errors"

var ErrStagingSourceMismatch = errors.New("staging: captured inputs differ from source bundle")

// addStagedRules is the only in-place snapshot derivation: an additive log-only
// delta under its captured delegation. It cannot change base inputs or remove
// staged IDs. Caller must first bind sourceDigest to the current approved
// bundle, versions and durable state; this helper never authorizes publication.
func (p *Prepared) addStagedRules(sourceDigest, name string, ids []uint32) error {
	if p == nil || len(sourceDigest) != 64 || p.Digest != sourceDigest || p.manifest.Format != 2 {
		return ErrStagingSourceMismatch
	}
	captured, err := snapshotDigest(p.manifest)
	if err != nil {
		return err
	}
	if captured != sourceDigest {
		return ErrStagingSourceMismatch
	}
	if len(ids) < 1 || len(ids) > 16 {
		return errors.New("staging: 1 to 16 additive rules required")
	}
	next := make(map[string][]uint32, len(p.compiler.StagedRules)+1)
	for key, current := range p.compiler.StagedRules {
		next[key] = append([]uint32(nil), current...)
	}
	seen := make(map[uint32]bool, len(ids))
	for _, id := range ids {
		if seen[id] {
			return errors.New("staging: duplicate additive rule")
		}
		seen[id] = true
		found := false
		for _, existing := range next[name] {
			if existing == id {
				found = true
				break
			}
		}
		if !found {
			next[name] = append(next[name], id)
		}
	}
	c := p.compiler
	c.StagedRules = next
	normalized, err := c.stagingFor(p.policies)
	if err != nil {
		return err
	}
	m := p.manifest
	m.StagedRules = normalized
	digest, err := snapshotDigest(m)
	if err != nil {
		return err
	}
	// All validation precedes this commit; errors leave the captured snapshot
	// unchanged and its private files/identity closure untouched.
	p.compiler.StagedRules = normalized
	p.manifest = m
	p.Digest = digest
	return nil
}
