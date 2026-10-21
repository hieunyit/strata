package store

import (
	"encoding/json"
	"github.com/strata/strata/control-plane/apidiscovery"
	"sync"
	"testing"
	"time"
)

func TestDiscoveryConcurrentDraftsAndStaleBaseline(t *testing.T) {
	st, p, doc, samples := discoveryFixture(t)
	ctx := t.Context()
	if err := st.SaveDiscoveryBatch(ctx, "example-api", "test", "scope-etag", "batch", "sa:collector", samples); err != nil {
		t.Fatal(err)
	}
	endpoints, err := st.DiscoveredEndpoints(ctx, "example-api", "test", "scope-etag", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	proposal, err := st.CreateDiscoveryProposal(ctx, "example-api", "test", "scope-etag", endpoints[0].Key, doc.Digest, Audit{Actor: "operator", Subject: "oidc:operator", Action: "discovery.propose", RequestID: "proposal"})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 3)
	for range 3 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			draft, err := st.DraftDiscoveryProposal(ctx, proposal.ID, proposal.Etag, p.ID, p.Etag, "scope-etag", Audit{Actor: "operator", Subject: "oidc:operator", Action: "discovery.draft", RequestID: "concurrent", Resource: "policies/" + p.ID})
			if err == nil && draft.CurrentVersion != 2 {
				err = ErrEtagMismatch
			}
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	var n int
	if err = st.pool.QueryRow(ctx, `SELECT count(*) FROM operations WHERE policy_id=$1`, p.ID).Scan(&n); err != nil || n != 1 {
		t.Fatalf("duplicate replay %d %v", n, err)
	}
	// A different proposal is immutable but cannot draft against a changed baseline.
	second, err := st.CreateDiscoveryProposal(ctx, "example-api", "test", "scope-etag", endpoints[0].Key, doc.Digest, Audit{Actor: "operator", Subject: "oidc:operator", Action: "discovery.propose", RequestID: "second"})
	if err != nil {
		t.Fatal(err)
	}
	doc.Operations = []apidiscovery.Operation{{Path: "/api/health", Method: "GET", ContentTypes: []string{}}}
	doc.ScopeEtag = "scope-etag"
	if _, err = st.SaveDiscoveryDocument(ctx, doc, Audit{Actor: "operator", Subject: "oidc:operator", Action: "discovery.document", RequestID: "new-document"}); err != nil {
		t.Fatal(err)
	}
	current, err := st.GetPolicy(ctx, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = st.DraftDiscoveryProposal(ctx, second.ID, second.Etag, p.ID, current.Etag, "scope-etag", Audit{Actor: "operator", Subject: "oidc:operator", Action: "discovery.draft", RequestID: "stale-base", Resource: "policies/" + p.ID}); err == nil {
		t.Fatal("stale baseline drafted")
	}
	after, err := st.GetPolicy(ctx, p.ID)
	if err != nil || after.CurrentVersion != 2 {
		t.Fatal("failed draft changed policy", err)
	}
	rows, err := st.DiscoveryProposals(ctx, "example-api", "test", "scope-etag", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range rows {
		if v.ID == second.ID && v.DraftVersion != 0 {
			t.Fatal("failed draft left attachment")
		}
	}
	var reference map[string]json.RawMessage
	if err = json.Unmarshal(after.Spec, &reference); err != nil {
		t.Fatal(err)
	}
	if len(reference["api_discovery"]) == 0 {
		t.Fatal("lost immutable proposal reference")
	}
}
