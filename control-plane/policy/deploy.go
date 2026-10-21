package policy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/strata/strata/agent/pkg/bundlefmt"
	"github.com/strata/strata/control-plane/auth"
	"github.com/strata/strata/control-plane/store"
)

// Store is the part of store.Store deploys use.
type Store interface {
	// DeployablePolicies: each policy at its newest approved version (four
	// eyes, W13-G2-02).
	DeployablePolicies(ctx context.Context) ([]store.Policy, error)
	WithBundleLock(ctx context.Context, build func(next uint64) error) error
	RecordBundle(ctx context.Context, b store.Bundle, a store.Audit) (store.Bundle, error)
}

// Builder makes a signed bundle.
type Builder interface {
	Build(ctx context.Context, version uint64, policies []Named) ([]byte, error)
}

// Deployer builds and publishes bundles.
type Deployer struct {
	// VerifyReplay checks the exact approved operations against prepared inputs.
	// When set, builders without snapshot support cannot deploy.
	// The last two arguments are the input digest and the rules digest of
	// the prepared bundle (CP-FIX-01).
	VerifyReplay func(context.Context, map[string]int, string, string) error

	Store   Store
	Builder Builder
	Objects Objects
	// PubKey verifies each bundle before it is published: a bundle the
	// nodes would refuse never leaves the control plane.
	PubKey []byte
	// Publish starts the rollout of a recorded bundle; nil: none.
	Publish func(ctx context.Context, b store.Bundle, a store.Audit) (store.Rollout, error)
}

// Deployment is a bundle and its rollout.
type Deployment struct {
	Bundle  store.Bundle
	Rollout *store.Rollout
}

// ObjectKey of a bundle version.
func ObjectKey(version uint64) string {
	return fmt.Sprintf("bundles/%020d/bundle-%d.sbn", version, version)
}

// FreeVersion returns next, or past the newest bundle in the store when
// next is already taken there: a bundle uploaded by a deploy that failed
// before it was recorded, or a database restored behind its artifacts
// (CP-A07). Immutable keys (FS) refuse other content under that key, and a
// version a node may have installed is never reused. Stores that cannot
// list keep next.
func FreeVersion(ctx context.Context, objects Objects, next uint64) (uint64, error) {
	l, ok := objects.(interface {
		List(ctx context.Context, prefix string) ([]ObjectInfo, error)
	})
	if !ok {
		return next, nil
	}
	taken, err := l.List(ctx, path.Dir(ObjectKey(next))+"/")
	if err != nil || len(taken) == 0 {
		return next, err
	}
	all, err := l.List(ctx, "bundles/")
	if err != nil {
		return 0, err
	}
	for _, o := range all {
		seg, _, _ := strings.Cut(strings.TrimPrefix(o.Key, "bundles/"), "/")
		if v, err := strconv.ParseUint(seg, 10, 64); err == nil && v >= next && v < math.MaxInt64 {
			next = v + 1
		}
	}
	return next, nil
}

// enoughSpace refuses a deploy before it builds when the artifact
// directory is nearly full (a store that cannot tell passes).
func enoughSpace(objects Objects) error {
	f, ok := objects.(interface{ FreeBytes() (uint64, error) })
	if !ok {
		return nil
	}
	free, err := f.FreeBytes()
	if err != nil {
		return err
	}
	if free < MinFreeBytes {
		return fmt.Errorf("policy: %d MiB free for artifacts, a deploy needs %d MiB: free space or prune old bundles", free>>20, MinFreeBytes>>20)
	}
	return nil
}

// Deploy builds the next bundle from the newest approved version of every
// policy, verifies it, uploads it, records it and starts its rollout.
func (d *Deployer) Deploy(ctx context.Context, a store.Audit) (Deployment, error) {
	b, err := d.build(ctx, a)
	if err != nil || d.Publish == nil {
		return Deployment{Bundle: b}, err
	}
	ro, err := d.Publish(ctx, b, a)
	if err != nil {
		return Deployment{Bundle: b}, fmt.Errorf("policy: bundle %d stored, rollout not started: %w", b.Version, err)
	}
	return Deployment{Bundle: b, Rollout: &ro}, nil
}

func (d *Deployer) build(ctx context.Context, a store.Audit) (store.Bundle, error) {
	var out store.Bundle
	err := d.Store.WithBundleLock(ctx, func(next uint64) error {
		next, err := FreeVersion(ctx, d.Objects, next)
		if err != nil {
			return err
		}
		if err := enoughSpace(d.Objects); err != nil {
			return err
		}
		ps, err := d.Store.DeployablePolicies(ctx)
		if err != nil {
			return err
		}
		if len(ps) == 0 {
			return errors.New("policy: no policy has an approved version")
		}
		sort.Slice(ps, func(i, j int) bool { return ps[i].Name < ps[j].Name })
		named := make([]Named, 0, len(ps))
		contents := map[string]int{}
		for _, p := range ps {
			// The bundle also carries installation-wide rules, bot/GeoIP data and
			// identity inputs. A publish affects every policy, even unchanged versions.
			if actor := auth.FromContext(ctx); actor != nil && actor.Access != nil && !actor.CanResource("policies/"+p.ID, auth.PermPoliciesDeploy) {
				return auth.ErrScopeDenied
			}
			spec, err := Parse(p.Spec)
			if err != nil {
				return fmt.Errorf("policy %s version %d: %w", p.ID, p.CurrentVersion, err)
			}
			named = append(named, Named{ResourceID: p.ID, Version: p.CurrentVersion, Name: p.Name, Spec: spec})
			contents[p.ID] = p.CurrentVersion
		}
		var data []byte
		inputDigest, rules := "", ""
		if d.VerifyReplay != nil {
			compiler, ok := d.Builder.(interface {
				Prepare(context.Context, []Named) (*Prepared, error)
			})
			if !ok {
				return &ReplayError{Msg: "policy: replay gate requires a snapshot compiler"}
			}
			prepared, e := compiler.Prepare(ctx, named)
			if e != nil {
				return e
			}
			defer prepared.Close()
			inputDigest, rules = prepared.Digest, prepared.RulesDigest
			if err := d.VerifyReplay(ctx, contents, inputDigest, rules); err != nil {
				return err
			}
			data, err = prepared.Build(ctx, next)
		} else {
			data, err = d.Builder.Build(ctx, next, named)
		}
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
		requirements, err := bundlefmt.Requirements(data, d.PubKey)
		if err != nil {
			return err
		}
		if check, ok := d.Store.(interface {
			CheckCapabilities(context.Context, []string) error
		}); ok {
			if err := check.CheckCapabilities(ctx, requirements); err != nil {
				return err
			}
		}
		sum := sha256.Sum256(data)
		key := ObjectKey(next)
		if err := d.Objects.Put(ctx, key, data, hex.EncodeToString(sum[:])); err != nil {
			return err
		}
		out, err = d.Store.RecordBundle(ctx, store.Bundle{
			RequiredCapabilities: requirements, InputDigest: inputDigest, RulesDigest: rules, Version: next, SHA256: sum[:], ObjectKey: key, SizeBytes: int64(len(data)), Contents: contents,
		}, a)
		return err
	})
	return out, err
}
