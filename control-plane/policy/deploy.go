package policy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"

	"github.com/strata/strata/agent/pkg/bundlefmt"
	"github.com/strata/strata/control-plane/store"
)

// Store is the part of store.Store deploys use.
type Store interface {
	ListPolicies(ctx context.Context) ([]store.Policy, error)
	WithBundleLock(ctx context.Context, build func(next uint64) error) error
	RecordBundle(ctx context.Context, b store.Bundle, a store.Audit) (store.Bundle, error)
}

// Builder makes a signed bundle.
type Builder interface {
	Build(ctx context.Context, version uint64, policies []Named) ([]byte, error)
}

// Deployer builds and publishes bundles.
type Deployer struct {
	Store   Store
	Builder Builder
	Objects Objects
	// PubKey verifies each bundle before it is published: a bundle the
	// nodes would refuse never leaves the control plane.
	PubKey []byte
}

// ObjectKey of a bundle version.
func ObjectKey(version uint64) string {
	return fmt.Sprintf("bundles/%020d/bundle-%d.sbn", version, version)
}

// Deploy builds the next bundle from the current version of every policy,
// verifies it, uploads it and records it.
func (d *Deployer) Deploy(ctx context.Context, a store.Audit) (store.Bundle, error) {
	var out store.Bundle
	err := d.Store.WithBundleLock(ctx, func(next uint64) error {
		ps, err := d.Store.ListPolicies(ctx)
		if err != nil {
			return err
		}
		sort.Slice(ps, func(i, j int) bool { return ps[i].Name < ps[j].Name })
		named := make([]Named, 0, len(ps))
		contents := map[string]int{}
		for _, p := range ps {
			spec, err := Parse(p.Spec)
			if err != nil {
				return fmt.Errorf("policy %s version %d: %w", p.ID, p.CurrentVersion, err)
			}
			named = append(named, Named{Name: p.Name, Spec: spec})
			contents[p.ID] = p.CurrentVersion
		}
		data, err := d.Builder.Build(ctx, next, named)
		if err != nil {
			return err
		}
		h, err := bundlefmt.Verify(data, d.PubKey)
		if err != nil {
			return fmt.Errorf("policy: the compiled bundle does not verify with the bundle public key: %w", err)
		}
		if h.Version != next || int(h.Policies) != len(named) {
			return fmt.Errorf("policy: compiled bundle says version %d with %d policies, want %d with %d", h.Version, h.Policies, next, len(named))
		}
		sum := sha256.Sum256(data)
		key := ObjectKey(next)
		if err := d.Objects.Put(ctx, key, data, hex.EncodeToString(sum[:])); err != nil {
			return err
		}
		out, err = d.Store.RecordBundle(ctx, store.Bundle{
			Version: next, SHA256: sum[:], ObjectKey: key, SizeBytes: int64(len(data)), Contents: contents,
		}, a)
		return err
	})
	return out, err
}
