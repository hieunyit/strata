package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/strata/strata/agent/pkg/privacy"
)

func TestPrivacyAppliedBeforePersistenceAndUnknownSettingsNotAcknowledged(t *testing.T) {
	store := NewMockEventStore()
	svc := NewIngestService(store, DefaultBatcherConfig(), time.Hour)
	defer func() { _ = svc.Close(context.Background()) }()
	filter, err := privacy.New([]string{"customer_id"}, []string{`PRIVATE-[0-9]+`})
	if err != nil {
		t.Fatal(err)
	}
	svc.Privacy = func(context.Context, string, uint64) (*privacy.Filter, error) { return filter, nil }
	e := Event{BlockID: "STR-0000-0000-0000-0001", Timestamp: time.Now(), NodeID: "example-node", PolicyID: "example-api", PolicyVersion: 7, Action: "block", HTTPMethod: "GET", HTTPPath: "/api?password=example-secret", Headers: []Header{{Name: "Authorization", Value: "example-token"}}, Violations: []Violation{{RuleID: 942100, Field: "ARGS:customer_id", Snippet: "example-customer"}, {RuleID: 942101, Field: "ARGS:q", Snippet: "PRIVATE-123"}}}
	ack, err := svc.ProcessBatch(context.Background(), EventBatch{NodeID: "example-node", Seq: 1, Events: []Event{e}})
	if err != nil || !ack.Success {
		t.Fatal("ingest", err)
	}
	stored, err := store.GetEvent(context.Background(), e.BlockID)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(stored)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"example-secret", "example-token", "example-customer", "PRIVATE-123"} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("persisted secret", secret)
		}
	}
	if e.Headers[0].Value != "example-token" || e.Violations[0].Snippet != "example-customer" {
		t.Fatal("producer memory mutated")
	}
	svc.Privacy = func(context.Context, string, uint64) (*privacy.Filter, error) {
		return nil, errors.New("database unavailable")
	}
	e.BlockID = "STR-0000-0000-0000-0002"
	ack, err = svc.ProcessBatch(context.Background(), EventBatch{NodeID: "example-node", Seq: 2, Events: []Event{e}})
	if err == nil || ack.Success {
		t.Fatal("unknown privacy acknowledged")
	}
	if _, err := store.GetEvent(context.Background(), e.BlockID); err == nil {
		t.Fatal("unknown privacy persisted")
	}
}
