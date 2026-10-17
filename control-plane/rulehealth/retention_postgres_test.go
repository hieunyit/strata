package rulehealth

import (
	"context"
	"testing"
	"time"

	"github.com/strata/strata/control-plane/localauth/localauthtest"
	"github.com/strata/strata/control-plane/store"
)

func TestContextRetentionRunsAgainstPostgres(t *testing.T) {
	p := localauthtest.Pool(t)
	s := store.New(p)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	for _, id := range []string{"old", "recent"} {
		at := time.Now()
		if id == "old" {
			at = at.Add(-91 * 24 * time.Hour)
		}
		a := store.Audit{Actor: "operator", Subject: "example-operator", RequestID: id,
			RuleContext: &store.EventRuleContext{PolicyID: "example-api", EventTime: at, RuleIDs: []uint32{942100}}}
		if _, err := s.MarkEventFalsePositive(ctx, id, "normal", "", a); err != nil {
			t.Fatal(err)
		}
	}
	stop, _ := startRetention(t, s, time.Hour)
	for {
		var n int
		if err := p.QueryRow(ctx, "SELECT count(*) FROM rule_annotation_context WHERE block_id='old'").Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("retention worker did not delete expired context")
		case <-time.After(5 * time.Millisecond):
		}
	}
	stop()
	var recent int
	if err := p.QueryRow(ctx, "SELECT count(*) FROM rule_annotation_context WHERE block_id='recent'").Scan(&recent); err != nil || recent != 1 {
		t.Fatalf("recent context lost: %d %v", recent, err)
	}
	if annotations, err := s.EventAnnotations(ctx, []string{"old", "recent"}); err != nil || len(annotations) != 2 {
		t.Fatalf("annotation lost: %v %v", annotations, err)
	}
}
