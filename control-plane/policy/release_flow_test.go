package policy_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/strata/strata/control-plane/policy"
	"github.com/strata/strata/control-plane/replay"
	"github.com/strata/strata/control-plane/store"
)

func TestNativeReleaseReviewDeployAndRollback(t *testing.T) {
	f := newStagingWriter(t, false)
	ctx := t.Context()
	compiler := f.writer.Compiler
	ps, err := f.store.DeployablePolicies(ctx)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := policy.Parse(ps[0].Spec)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := compiler.Prepare(ctx, []policy.Named{{ResourceID: ps[0].ID, Version: ps[0].CurrentVersion, Name: ps[0].Name, Spec: spec}})
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close()
	version, err := f.store.GetPolicyVersion(ctx, ps[0].ID, ps[0].CurrentVersion)
	if err != nil {
		t.Fatal(err)
	}
	// Synthetic completed replay evidence tests gate binding, not detector quality.
	proof, err := json.Marshal(replay.Report{InputDigest: prepared.Digest, RulesDigest: prepared.RulesDigest, DraftSHA256: hex.EncodeToString(f.source.SHA256), BaselineBundle: 1, BaselineSHA256: hex.EncodeToString(f.source.SHA256), Corpus: &replay.Route{Samples: 100}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, "UPDATE operations SET result=$2 WHERE id=$1", version.ApprovedReplayID, proof); err != nil {
		t.Fatal(err)
	}
	d := &policy.Deployer{Store: f.store, Builder: compiler, Objects: f.objects, PubKey: f.writer.PubKey, VerifyReplay: (replay.Gate{Store: f.store}).Check}
	service := &policy.Releases{Store: f.store, Deployer: d, Waves: []float64{1}}
	creator := store.Audit{Subject: "local:creator", Actor: "creator", Action: "release.create"}
	reviewer := store.Audit{Subject: "local:reviewer", Actor: "reviewer", Action: "release.review"}
	release, err := service.Create(ctx, "create-release", "", creator)
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := f.store.LatestBundle(ctx)
	if err != nil || baseline.Version != 1 {
		t.Fatal("preparation changed current bundle")
	}
	release, err = f.store.ReviewRelease(ctx, release.ID, release.Etag, release.SnapshotHash, release.Snapshot.ReplayIDs, true, reviewer)
	if err != nil {
		t.Fatal(err)
	}
	// Deployment must not consult changed live compiler/rule inputs.
	compiler.Binary = "/unavailable/compiler"
	if err := os.WriteFile(f.rules, []byte("invalid now"), 0600); err != nil {
		t.Fatal(err)
	}
	first, err := service.Deploy(ctx, release.ID, release.Etag, nil, creator)
	if err != nil {
		t.Fatal(err)
	}
	duplicate, err := service.Deploy(ctx, release.ID, release.Etag, nil, creator)
	if err != nil || duplicate.BundleVersion != first.BundleVersion {
		t.Fatal("deploy retry created another bundle")
	}
	rollback, err := service.Create(ctx, "rollback-release", release.ID, creator)
	if err != nil {
		t.Fatal(err)
	}
	rollback, err = f.store.ReviewRelease(ctx, rollback.ID, rollback.Etag, rollback.SnapshotHash, rollback.Snapshot.ReplayIDs, true, reviewer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Deploy(ctx, rollback.ID, rollback.Etag, nil, creator); !errors.Is(err, store.ErrReleaseBaseline) {
		t.Fatal("historical replay warning bypassed")
	}
	ack := first.BundleVersion
	rolled, err := service.Deploy(ctx, rollback.ID, rollback.Etag, &ack, creator)
	if err != nil {
		t.Fatal(err)
	}
	if rolled.BundleVersion <= first.BundleVersion {
		t.Fatal("rollback version went backwards")
	}
	before, _ := f.objects.Get(ctx, policy.ObjectKey(first.BundleVersion))
	after, _ := f.objects.Get(ctx, policy.ObjectKey(rolled.BundleVersion))
	if !bytes.Equal(before[64:len(before)-64], after[64:len(after)-64]) {
		t.Fatal("rollback mixed current rules with old policies")
	}
}
