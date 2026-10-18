package api

import (
	"net/http"
	"testing"
	"time"

	"github.com/strata/strata/control-plane/ingest"
	"github.com/strata/strata/control-plane/localauth/localauthtest"
	"github.com/strata/strata/control-plane/store"
)

func TestAnnotationBindsRuleContextFromLookedUpEvent(t *testing.T) {
	p := localauthtest.Pool(t)
	pg := store.New(p)
	_, events := setupTestServer(t)
	const block = "STR-8F3K-Q2VD-7XNM-A1PC"
	e, err := events.GetEvent(t.Context(), block)
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(ServerConfig{Auth: tokenRoles{}, Annotations: pg}, events)
	endpoint := "/v1/events/" + block + ":markFalsePositive"
	body := map[string]string{"reason": "legitimate login", "request_id": "context-retry"}
	if code, resp := do(t, s, http.MethodPost, endpoint, "operator", body); code != 200 {
		t.Fatalf("mark: %d %v", code, resp)
	}
	from, to := e.Timestamp.Add(-time.Second), e.Timestamp.Add(time.Second)
	count := func(rule uint32, policy string, want uint64) {
		t.Helper()
		n, err := store.New(p).RuleFalsePositiveEvents(t.Context(), rule, policy, from, to)
		if err != nil || n != want {
			t.Fatalf("rule %d policy %s: %d, want %d: %v", rule, policy, n, want, err)
		}
	}
	count(942100, e.PolicyID, 1)
	count(942100, "different-policy", 0)
	// A retry returns the first result, even if an upstream duplicate row now
	// has different rule claims. It must not rewrite the original snapshot.
	e.MatchedRules = []uint32{777777}
	if err := events.SaveEvents(t.Context(), []ingest.Event{*e}); err != nil {
		t.Fatal(err)
	}
	if code, _ := do(t, s, http.MethodPost, endpoint, "operator", body); code != 200 {
		t.Fatal("retry lost idempotency")
	}
	count(942100, e.PolicyID, 1)
	count(777777, e.PolicyID, 0)
	if code, _ := do(t, s, http.MethodPost, endpoint, "operator", map[string]any{"reason": "normal", "event_context": map[string]any{"rule_ids": []int{777777}}}); code != 400 {
		t.Fatalf("client supplied health context accepted: %d", code)
	}
}
