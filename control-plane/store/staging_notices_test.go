package store_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/strata/strata/control-plane/store"
)

func TestStagingNoticesPersistAndPageEqualTimestamps(t *testing.T) {
	p, s, source, b, a := stagingFixture(t)
	ctx := t.Context()
	audit := store.Audit{Actor: "worker", Channel: "system"}
	if _, err := s.RecordStagingBundle(ctx, source, b, a, audit); err != nil {
		t.Fatal(err)
	}
	parent, err := s.LatestBundle(ctx)
	if err != nil {
		t.Fatal(err)
	}
	b.Version = 3
	b.ObjectKey = "bundles/3"
	b.InputDigest = strings.Repeat("c", 64)
	b.SHA256 = []byte(strings.Repeat("c", 32))
	a.ID = "staging-z"
	a.RuleID = 942101
	if _, err = s.RecordStagingBundle(ctx, parent, b, a, audit); err != nil {
		t.Fatal(err)
	}
	stamp := time.Date(2026, 10, 17, 3, 0, 0, 123456000, time.UTC)
	if _, err = p.Exec(ctx, `UPDATE rule_staging_actions SET created_at=$1`, stamp); err != nil {
		t.Fatal(err)
	}
	if _, err = p.Exec(ctx, `INSERT INTO connector_groups(id,name) VALUES('example-edge','example-edge'); INSERT INTO nodes(id,group_id) VALUES('example-node','example-edge')`); err != nil {
		t.Fatal(err)
	}
	ro, _, err := s.StartStagingRollout(ctx, a.ID, []string{"example-node"}, []float64{1}, 0, audit)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.SetRolloutState(ctx, ro.ID, store.RolloutPaused, "review", []string{store.RolloutRunning}, audit); err != nil {
		t.Fatal(err)
	}
	var auditBefore int
	if err = p.QueryRow(ctx, `SELECT count(*) FROM audit_log`).Scan(&auditBefore); err != nil {
		t.Fatal(err)
	}
	first, err := store.New(p).StagingNotices(ctx, nil, "", 1)
	if err != nil || len(first) != 1 || first[0].ID != "staging-z" || first[0].Matches != "18446744073709551615" || first[0].Reports != "18446744073709551615" || first[0].RolloutState != "PAUSED" {
		t.Fatalf("first: %+v %v", first, err)
	}
	next, err := s.StagingNotices(ctx, &first[0].CreatedAt, first[0].ID, 1)
	if err != nil || len(next) != 1 || next[0].ID != "staging-example" || next[0].RolloutState != "PENDING" || next[0].RolloutID != "" {
		t.Fatalf("next: %+v %v", next, err)
	}
	end, err := s.StagingNotices(ctx, &next[0].CreatedAt, next[0].ID, 1)
	if err != nil || len(end) != 0 {
		t.Fatalf("end: %+v %v", end, err)
	}
	var auditAfter int
	if err = p.QueryRow(ctx, `SELECT count(*) FROM audit_log`).Scan(&auditAfter); err != nil || auditAfter != auditBefore {
		t.Fatal("notice reads changed audit/state")
	}
	for _, limit := range []int{0, 52} {
		if _, err = s.StagingNotices(ctx, nil, "", limit); err == nil {
			t.Fatal("invalid limit")
		}
	}
	if _, err = s.StagingNotices(ctx, nil, "unpaired", 1); err == nil {
		t.Fatal("unpaired cursor")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err = s.StagingNotices(canceled, nil, "", 1); err == nil {
		t.Fatal("cancel ignored")
	}
}
