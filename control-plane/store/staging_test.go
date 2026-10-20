package store_test

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/strata/strata/control-plane/db"
	"github.com/strata/strata/control-plane/localauth/localauthtest"
	"github.com/strata/strata/control-plane/store"
)

func stagingFixture(t *testing.T) (*pgxpool.Pool, *store.Store, store.Bundle, store.Bundle, store.StagingAction) {
	t.Helper()
	p := localauthtest.Pool(t)
	s := store.New(p)
	ctx := t.Context()
	author := store.Audit{Actor: "operator", Subject: "operator"}
	_, err := s.CreatePolicy(ctx, store.Policy{ID: "example-api", Name: "example-api", Spec: []byte(`{"mode":"enforce","auto_staging":{"enabled":true,"rule_ids":[942100,942101],"window_seconds":300,"min_matches":100,"min_reports":5,"fp_threshold_bps":500}}`)}, author)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.SubmitPolicyVersion(ctx, "example-api", 1, author); err != nil {
		t.Fatal(err)
	}
	if _, err = s.DecidePolicyVersion(ctx, "example-api", 1, true, "", store.Audit{Actor: "approver", Subject: "approver"}); err != nil {
		t.Fatal(err)
	}
	source := store.Bundle{Version: 1, InputDigest: strings.Repeat("a", 64), SHA256: []byte(strings.Repeat("a", 32)), ObjectKey: "bundles/1", SizeBytes: 100, Contents: map[string]int{"example-api": 1}}
	if source, err = s.RecordBundle(ctx, source, author); err != nil {
		t.Fatal(err)
	}
	b := store.Bundle{Version: 2, InputDigest: strings.Repeat("b", 64), SHA256: []byte(strings.Repeat("b", 32)), ObjectKey: "bundles/2", SizeBytes: 101, Contents: map[string]int{"example-api": 1}}
	to := time.Date(2026, 10, 17, 0, 5, 0, 123456000, time.UTC)
	a := store.StagingAction{ID: "staging-example", PolicyID: "example-api", PolicyVersion: 1, RuleID: 942100, Matches: math.MaxUint64, Reports: math.MaxUint64, WindowFrom: to.Add(-5 * time.Minute), WindowTo: to}
	return p, s, source, b, a
}

func TestStagingRecordAtomicRetryAndPersistence(t *testing.T) {
	p, s, source, b, a := stagingFixture(t)
	ctx := t.Context()
	audit := store.Audit{Actor: "rule-health", Channel: "system", Action: "rule-staging", Resource: "rules/942100"}
	got, err := s.RecordStagingBundle(ctx, source, b, a, audit)
	if err != nil {
		t.Fatal(err)
	}
	if got.Matches != math.MaxUint64 || got.Reports != math.MaxUint64 || got.SourceBundle != 1 || got.BundleVersion != 2 || got.RolloutID != nil || got.CreatedAt.IsZero() {
		t.Fatalf("record: %+v", got)
	}
	// Retry through another Store, after the latest bundle moved to the derived one.
	again, err := store.New(p).RecordStagingBundle(ctx, source, b, a, audit)
	if err != nil || again.ID != got.ID || !again.CreatedAt.Equal(got.CreatedAt) {
		t.Fatalf("retry: %+v %v", again, err)
	}
	var count int
	if err = p.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action='rule-staging'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("duplicate audit: %d %v", count, err)
	}
	state, err := store.New(p).StagedRules(ctx, map[string]int{"example-api": 1})
	if err != nil || len(state["example-api"]) != 1 || state["example-api"][0] != 942100 {
		t.Fatalf("persisted: %v %v", state, err)
	}
	other, err := s.StagedRules(ctx, map[string]int{"example-api": 2, "example-web": 1})
	if err != nil || len(other) != 0 {
		t.Fatalf("version leaked: %v %v", other, err)
	}
	a.Reports--
	if _, err = s.RecordStagingBundle(ctx, source, b, a, audit); !errors.Is(err, store.ErrStagingConflict) {
		t.Fatalf("changed retry: %v", err)
	}
	// A normal bundle with the same policy version does not clear the ledger.
	next := b
	next.Version = 3
	next.ObjectKey = "bundles/3"
	if _, err = s.RecordBundle(ctx, next, audit); err != nil {
		t.Fatal(err)
	}
	state, err = s.StagedRules(ctx, source.Contents)
	if err != nil || len(state["example-api"]) != 1 {
		t.Fatalf("normal deploy reset state: %v %v", state, err)
	}
}

func TestStagingRecordRollsBackWithAudit(t *testing.T) {
	p, s, source, b, a := stagingFixture(t)
	ctx := t.Context()
	if _, err := s.RecordStagingBundle(ctx, source, b, a, store.Audit{Actor: "worker", Channel: "invalid"}); err == nil {
		t.Fatal("bad audit accepted")
	}
	latest, err := s.LatestBundle(ctx)
	if err != nil || latest.Version != 1 {
		t.Fatalf("bundle escaped transaction: %+v %v", latest, err)
	}
	var count int
	if err = p.QueryRow(ctx, `SELECT count(*) FROM rule_staging_actions`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("state escaped transaction: %d %v", count, err)
	}
	if _, err = s.RecordStagingBundle(ctx, source, b, a, store.Audit{Actor: "worker", Channel: "system"}); err != nil {
		t.Fatal(err)
	}
}

func TestStagingSourceChecksAndSingleWriter(t *testing.T) {
	p, s, source, b, a := stagingFixture(t)
	ctx := t.Context()
	audit := store.Audit{Actor: "worker", Channel: "system"}
	fake := source
	fake.InputDigest = strings.Repeat("c", 64)
	if _, err := s.RecordStagingBundle(ctx, fake, b, a, audit); !errors.Is(err, store.ErrStagingConflict) {
		t.Fatalf("forged digest: %v", err)
	}
	fake = source
	fake.SHA256 = []byte(strings.Repeat("c", 32))
	if _, err := s.RecordStagingBundle(ctx, fake, b, a, audit); !errors.Is(err, store.ErrStagingConflict) {
		t.Fatalf("forged SHA: %v", err)
	}
	// Unreviewed/legacy rows must not grant delegation even when in a bundle.
	if _, err := p.Exec(ctx, `UPDATE policy_versions SET decided_subject=NULL WHERE policy_id='example-api'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RecordStagingBundle(ctx, source, b, a, audit); !errors.Is(err, store.ErrStagingConflict) {
		t.Fatalf("no independent approval: %v", err)
	}
	if _, err := p.Exec(ctx, `UPDATE policy_versions SET decided_subject='approver' WHERE policy_id='example-api'`); err != nil {
		t.Fatal(err)
	}
	// Two independently scheduled reductions from one source cannot both commit.
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			candidate := a
			candidate.ID = fmt.Sprintf("action-%d", i)
			candidate.RuleID += uint32(i)
			_, err := store.New(p).RecordStagingBundle(ctx, source, b, candidate, audit)
			results <- err
		}(i)
	}
	wg.Wait()
	close(results)
	success, conflict := 0, 0
	for err := range results {
		if err == nil {
			success++
		} else if errors.Is(err, store.ErrStagingConflict) {
			conflict++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatalf("writers: success=%d conflict=%d", success, conflict)
	}
	a.ID = "later-attempt"
	if _, err := s.RecordStagingBundle(ctx, source, b, a, audit); !errors.Is(err, store.ErrStagingConflict) {
		t.Fatalf("stale source: %v", err)
	}
}

func TestStagingLedgerBoundsAndMigration(t *testing.T) {
	p, s, source, b, a := stagingFixture(t)
	ctx := t.Context()
	for _, alter := range []func(*store.StagingAction){func(v *store.StagingAction) { v.RuleID = 0 }, func(v *store.StagingAction) { v.Reports = 0 }, func(v *store.StagingAction) { v.Reports = 2; v.Matches = 1 }, func(v *store.StagingAction) { v.WindowFrom = v.WindowTo }, func(v *store.StagingAction) { v.WindowFrom = v.WindowTo.Add(-25 * time.Hour) }, func(v *store.StagingAction) { v.PolicyVersion = 2 }, func(v *store.StagingAction) { v.ID = strings.Repeat("x", 129) }} {
		bad := a
		alter(&bad)
		if _, err := s.RecordStagingBundle(ctx, source, b, bad, store.Audit{}); err == nil {
			t.Fatalf("invalid action accepted: %+v", bad)
		}
	}
	if _, err := s.StagedRules(ctx, map[string]int{"example-api": 0}); err == nil {
		t.Fatal("invalid version accepted")
	}
	versions := map[string]int{}
	for i := 0; i < 4097; i++ {
		versions[fmt.Sprint(i)] = 1
	}
	if _, err := s.StagedRules(ctx, versions); err == nil {
		t.Fatal("unbounded policies")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := s.RecordStagingBundle(canceled, source, b, a, store.Audit{}); err == nil {
		t.Fatal("cancel ignored")
	}
	if err := db.Migrate(ctx, p, 20); err != nil {
		t.Fatal(err)
	}
	// up again through 21 to the latest, which the store's queries need
	latestVersion, err := db.Latest()
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(ctx, p, latestVersion); err != nil {
		t.Fatal(err)
	}
	// Existing approved bundle preserved; no staging inferred by migration.
	latest, err := s.LatestBundle(ctx)
	if err != nil || latest.Version != 1 {
		t.Fatalf("migration changed baseline: %+v %v", latest, err)
	}
	state, err := s.StagedRules(ctx, source.Contents)
	if err != nil || len(state) != 0 {
		t.Fatalf("migration inferred staging: %v %v", state, err)
	}
}
