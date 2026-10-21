package policy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"reflect"
	"time"

	"github.com/strata/strata/control-plane/store"
)

// Releases coordinates immutable build, independent review and atomic rollout.
// Store authorization is enforced by the HTTP layer, like the existing deployer.
type Releases struct {
	Canary   map[string]float64
	Store    *store.Store
	Deployer *Deployer
	Waves    []float64
	Soak     time.Duration
	Notify   func([]string, store.Bundle)
}

func (r *Releases) Create(ctx context.Context, requestID, source string, a store.Audit) (store.Release, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return store.Release{}, err
	}
	id := hex.EncodeToString(random[:])
	return r.Store.CreateRelease(ctx, id, requestID, source, func() (store.ReleaseSnapshot, error) {
		if source == "" {
			snapshot, err := r.Deployer.PrepareRelease(ctx, "releases/"+id+"/snapshot.sbn")
			snapshot.Waves, snapshot.SoakSeconds, snapshot.Canary = r.Waves, int64(r.Soak/time.Second), r.Canary
			return snapshot, err
		}
		prior, err := r.Store.GetRelease(ctx, source)
		if err != nil {
			return store.ReleaseSnapshot{}, err
		}
		if prior.State != "DEPLOYED" || prior.BundleVersion == 0 {
			return store.ReleaseSnapshot{}, store.ErrReleaseState
		}
		baseline, err := r.Store.LatestBundle(ctx)
		if err != nil {
			return store.ReleaseSnapshot{}, err
		}
		snapshot := prior.Snapshot
		snapshot.Baseline = baseline.Version
		snapshot.ReplayBaselineMismatch = true
		snapshot.Waves, snapshot.SoakSeconds, snapshot.Canary = r.Waves, int64(r.Soak/time.Second), r.Canary
		return snapshot, nil
	}, a)
}
func (r *Releases) Deploy(ctx context.Context, id, etag string, ack *uint64, a store.Audit) (store.Release, error) {
	var out store.Release
	var notify []string
	var bundle store.Bundle
	err := r.Store.WithBundleLock(ctx, func(next uint64) error {
		release, err := r.Store.GetRelease(ctx, id)
		if err != nil {
			return err
		}
		if release.State == "DEPLOYED" {
			out = release
			return nil
		}
		if !reflect.DeepEqual(release.Snapshot.Canary, r.Canary) {
			return errors.New("release: canary configuration changed; prepare and review a new release")
		}
		if release.Etag != etag || etag == "" {
			return store.ErrEtagMismatch
		}
		if release.State != "APPROVED" {
			return store.ErrReleaseState
		}
		current, err := r.Store.LatestBundle(ctx)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		if (release.Snapshot.Baseline != current.Version || release.SourceRelease != "" || release.Snapshot.ReplayBaselineMismatch) && (ack == nil || *ack != current.Version) {
			return store.ErrReleaseBaseline
		}
		if err := enoughSpace(r.Deployer.Objects); err != nil {
			return err
		}
		if err := r.Store.CheckCapabilities(ctx, release.Snapshot.Bundle.RequiredCapabilities); err != nil {
			return err
		}
		next, err = FreeVersion(ctx, r.Deployer.Objects, next)
		if err != nil {
			return err
		}
		bundle, err = r.Deployer.MaterializeRelease(ctx, release.Snapshot, next)
		if err != nil {
			return err
		}
		out, _, notify, err = r.Store.CommitReleaseDeployment(ctx, id, etag, bundle, ack, release.Snapshot.Waves, time.Duration(release.Snapshot.SoakSeconds)*time.Second, a)
		return err
	})
	if err == nil && r.Notify != nil && len(notify) > 0 {
		r.Notify(notify, bundle)
	}
	return out, err
}
