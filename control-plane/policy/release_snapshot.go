package policy

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/strata/strata/agent/pkg/bundlefmt"
	"github.com/strata/strata/control-plane/store"
)

// PrepareRelease builds once from approved policies under the replay gate. The
// private artifact never becomes LatestBundle or a node's desired version.
func (d *Deployer) PrepareRelease(ctx context.Context, key string) (store.ReleaseSnapshot, error) {
	var out store.ReleaseSnapshot
	if d.VerifyReplay == nil {
		return out, errors.New("release: replay gate is required")
	}
	compiler, ok := d.Builder.(interface {
		Prepare(context.Context, []Named) (*Prepared, error)
	})
	if !ok {
		return out, errors.New("release: snapshot compiler required")
	}
	reader, ok := d.Store.(interface {
		LatestBundle(context.Context) (store.Bundle, error)
		GetPolicyVersion(context.Context, string, int) (store.PolicyVersion, error)
		GetOperation(context.Context, string) (store.Operation, error)
	})
	if !ok {
		return out, errors.New("release: durable evidence store required")
	}
	err := d.Store.WithBundleLock(ctx, func(next uint64) error {
		if err := enoughSpace(d.Objects); err != nil {
			return err
		}
		baseline, err := reader.LatestBundle(ctx)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		ps, err := d.Store.DeployablePolicies(ctx)
		if err != nil {
			return err
		}
		if len(ps) == 0 {
			return errors.New("release: no approved policies")
		}
		sort.Slice(ps, func(i, j int) bool { return ps[i].Name < ps[j].Name })
		named := make([]Named, 0, len(ps))
		contents := map[string]int{}
		proofs := map[string]string{}
		mismatch := false
		for _, p := range ps {
			spec, err := Parse(p.Spec)
			if err != nil {
				return err
			}
			named = append(named, Named{ResourceID: p.ID, Version: p.CurrentVersion, Name: p.Name, Spec: spec})
			contents[p.ID] = p.CurrentVersion
			version, err := reader.GetPolicyVersion(ctx, p.ID, p.CurrentVersion)
			if err != nil {
				return err
			}
			proofs[p.ID] = version.ApprovedReplayID
			if version.ApprovedReplayID == "" {
				mismatch = true
			} else {
				op, err := reader.GetOperation(ctx, version.ApprovedReplayID)
				if err != nil {
					return err
				}
				var proof struct {
					Baseline uint64 `json:"baseline_bundle"`
				}
				if err := json.Unmarshal(op.Result, &proof); err != nil {
					return err
				}
				if proof.Baseline != baseline.Version {
					mismatch = true
				}
			}
		}
		prepared, err := compiler.Prepare(ctx, named)
		if err != nil {
			return err
		}
		defer prepared.Close()
		if err := d.VerifyReplay(ctx, contents, prepared.Digest, prepared.RulesDigest); err != nil {
			return err
		}
		data, err := prepared.Build(ctx, next)
		if err != nil {
			return err
		}
		header, err := bundlefmt.Verify(data, d.PubKey)
		if err != nil {
			return err
		}
		if header.Version != next || int(header.Policies) != len(named) {
			return errors.New("release: invalid snapshot header")
		}
		requirements, err := bundlefmt.Requirements(data, d.PubKey)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		if err := d.Objects.Put(ctx, key, data, hex.EncodeToString(sum[:])); err != nil {
			return err
		}
		out = store.ReleaseSnapshot{ReplayBaselineMismatch: mismatch, Bundle: store.Bundle{Version: next, SHA256: sum[:], ObjectKey: key, SizeBytes: int64(len(data)), Contents: contents, InputDigest: prepared.Digest, RulesDigest: prepared.RulesDigest, RequiredCapabilities: requirements}, PublicKey: append([]byte(nil), d.PubKey...), Baseline: baseline.Version, ReplayIDs: proofs}
		return nil
	})
	return out, err
}

// MaterializeRelease preserves every section byte and only assigns a new signed
// header version/time. FlagRollback is cleared: nodes retain monotonic versions.
func (d *Deployer) MaterializeRelease(ctx context.Context, snapshot store.ReleaseSnapshot, next uint64) (store.Bundle, error) {
	b := snapshot.Bundle
	data, err := d.Objects.Get(ctx, b.ObjectKey)
	if err != nil {
		return store.Bundle{}, err
	}
	sum := sha256.Sum256(data)
	if string(sum[:]) != string(b.SHA256) || int64(len(data)) != b.SizeBytes {
		return store.Bundle{}, errors.New("release: artifact hash or size mismatch")
	}
	header, err := bundlefmt.Verify(data, snapshot.PublicKey)
	if err != nil {
		return store.Bundle{}, err
	}
	if header.Version != b.Version {
		return store.Bundle{}, errors.New("release: snapshot version mismatch")
	}
	body := append([]byte(nil), data[:len(data)-ed25519.SignatureSize]...)
	binary.LittleEndian.PutUint16(body[10:], header.Flags&^bundlefmt.FlagRollback)
	binary.LittleEndian.PutUint64(body[16:], next)
	binary.LittleEndian.PutUint64(body[24:], uint64(time.Now().UnixMilli()))
	compiler, ok := d.Builder.(*Compiler)
	if !ok {
		return store.Bundle{}, errors.New("release: signing compiler unavailable")
	}
	var signature []byte
	if compiler.Signer != nil {
		signature, err = compiler.Signer.Sign(ctx, body)
	} else {
		var seed []byte
		seed, err = os.ReadFile(compiler.KeyFile)
		if err == nil {
			if len(seed) != ed25519.SeedSize {
				return store.Bundle{}, errors.New("release: signing key must be a 32-byte seed")
			}
			signature = ed25519.Sign(ed25519.NewKeyFromSeed(seed), body)
		}
	}
	if err != nil {
		return store.Bundle{}, fmt.Errorf("release: sign: %w", err)
	}
	data = append(body, signature...)
	requirements, err := bundlefmt.Requirements(data, d.PubKey)
	if err != nil {
		return store.Bundle{}, err
	}
	sum = sha256.Sum256(data)
	key := ObjectKey(next)
	if err := d.Objects.Put(ctx, key, data, hex.EncodeToString(sum[:])); err != nil {
		return store.Bundle{}, err
	}
	b.Version, b.ObjectKey, b.SHA256, b.SizeBytes, b.RequiredCapabilities = next, key, sum[:], int64(len(data)), requirements
	return b, nil
}
