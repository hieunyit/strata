package store

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/strata/strata/control-plane/apidiscovery"
	"github.com/strata/strata/control-plane/localauth/localauthtest"
	"strings"
	"testing"
	"time"
)

func discoveryFixture(t *testing.T) (*Store, Policy, DiscoveryDocument, []apidiscovery.Sample) {
	t.Helper()
	pool := localauthtest.Pool(t)
	st := New(pool)
	ctx := t.Context()
	now := time.Now().UTC()
	if _, err := pool.Exec(ctx, `INSERT INTO connector_groups(id,name) VALUES('example-group','Example');INSERT INTO applications(id,name,owner,etag,created_by) VALUES('example-api','Example','team','scope-etag','operator');INSERT INTO application_environments(application_id,id,name,group_id) VALUES('example-api','test','Test','example-group')`); err != nil {
		t.Fatal(err)
	}
	policy, err := st.CreatePolicy(ctx, Policy{ID: "policy-api", Name: "example-api", Spec: []byte(`{"mode":"shadow","future_setting":true}`)}, Audit{Actor: "operator", Subject: "oidc:operator"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO application_routes(application_id,environment_id,id,host,path_prefix,policy_id) VALUES('example-api','test','api','api.example.test','/api',$1)`, policy.ID); err != nil {
		t.Fatal(err)
	}
	doc, err := st.SaveDiscoveryDocument(ctx, DiscoveryDocument{ApplicationID: "example-api", EnvironmentID: "test", ScopeEtag: "scope-etag", Operations: []apidiscovery.Operation{}}, Audit{Actor: "operator", Subject: "oidc:operator", Action: "discovery.document", RequestID: "document"})
	if err != nil {
		t.Fatal(err)
	}
	samples := []apidiscovery.Sample{}
	for i := range 20 {
		v := apidiscovery.Observation{ID: fmt.Sprintf("00000000-0000-0000-0000-%012d", i+1), RouteID: "api", Method: "POST", Path: "/api/users/alice@example.test?token=private", ContentType: "application/json", BodyBytes: 234, BackendStatus: 200, BackendResponse: true, SourceIP: fmt.Sprintf("198.51.100.%d", i%3+1), At: now.Add(time.Duration(i-20) * time.Minute)}
		sample, err := apidiscovery.Normalize(v, bytes.Repeat([]byte{7}, 32), "example-api/test", now)
		if err != nil {
			t.Fatal(err)
		}
		samples = append(samples, sample)
	}
	return st, policy, doc, samples
}
func TestDiscoveryPrivacyQuotasDedupAndRetention(t *testing.T) {
	st, _, _, samples := discoveryFixture(t)
	ctx := t.Context()
	now := time.Now().UTC()
	for _, batch := range []string{"batch-a", "batch-a", "batch-b"} {
		if err := st.SaveDiscoveryBatch(ctx, "example-api", "test", "scope-etag", batch, "sa:collector", samples); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := st.DiscoveredEndpoints(ctx, "example-api", "test", "scope-etag", now)
	if err != nil || len(rows) != 1 || rows[0].Samples != 20 || rows[0].IndependentSources != 3 || !rows[0].Eligible {
		t.Fatalf("inventory %+v %v", rows, err)
	}
	if rows[0].Path != "/api/users/{param1}" {
		t.Fatal(rows[0])
	}
	for _, table := range []string{"discovery_observations", "audit_log", "discovery_batches"} {
		var raw []byte
		if err = st.pool.QueryRow(ctx, `SELECT coalesce(jsonb_agg(t),'[]') FROM `+table+` t`).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		for _, bad := range []string{"alice@example.test", "token=private", "198.51.100"} {
			if strings.Contains(string(raw), bad) {
				t.Fatalf("%s leaked %s", table, bad)
			}
		}
	}
	if err = st.SaveDiscoveryBatch(ctx, "example-api", "test", "scope-next", "batch-new", "sa:collector", samples); err != ErrEtagMismatch {
		t.Fatalf("stale scope %v", err)
	}
	changed := append([]apidiscovery.Sample(nil), samples...)
	changed[0].BodyBytes++
	if err = st.SaveDiscoveryBatch(ctx, "example-api", "test", "scope-etag", "batch-a", "sa:collector", changed); err != ErrRequestReused {
		t.Fatalf("batch reuse %v", err)
	}
	if err = st.SaveDiscoveryBatch(ctx, "example-api", "test", "scope-etag", "oversized", "sa:collector", make([]apidiscovery.Sample, 101)); err == nil {
		t.Fatal("oversized batch")
	}
	if err = st.RetainDiscovery(ctx, now.Add(8*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	rows, err = st.DiscoveredEndpoints(ctx, "example-api", "test", "scope-etag", now)
	if err != nil || len(rows) != 0 {
		t.Fatalf("retention %+v %v", rows, err)
	}
}
func TestDiscoveryProposalDraftAtomicIdempotentAndReviewed(t *testing.T) {
	st, p, doc, samples := discoveryFixture(t)
	ctx := t.Context()
	if err := st.SaveDiscoveryBatch(ctx, "example-api", "test", "scope-etag", "batch-a", "sa:collector", samples[:5]); err != nil {
		t.Fatal(err)
	}
	rows, err := st.DiscoveredEndpoints(ctx, "example-api", "test", "scope-etag", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	a := Audit{Actor: "operator", Subject: "oidc:operator", Action: "discovery.propose", RequestID: "proposal"}
	if _, err = st.CreateDiscoveryProposal(ctx, "example-api", "test", "scope-etag", rows[0].Key, doc.Digest, a); err == nil {
		t.Fatal("insufficient sources/span accepted")
	}
	if err = st.SaveDiscoveryBatch(ctx, "example-api", "test", "scope-etag", "batch-b", "sa:collector", samples); err != nil {
		t.Fatal(err)
	}
	proposal, err := st.CreateDiscoveryProposal(ctx, "example-api", "test", "scope-etag", rows[0].Key, doc.Digest, a)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := st.CreateDiscoveryProposal(ctx, "example-api", "test", "scope-etag", rows[0].Key, doc.Digest, a)
	if err != nil || retry.ID != proposal.ID {
		t.Fatal("proposal retry", err)
	}
	a.Action = "discovery.draft"
	a.Resource = "policies/" + p.ID
	a.RequestID = "draft"
	draft, err := st.DraftDiscoveryProposal(ctx, proposal.ID, proposal.Etag, p.ID, p.Etag, "scope-etag", a)
	if err != nil {
		t.Fatal(err)
	}
	again, err := st.DraftDiscoveryProposal(ctx, proposal.ID, proposal.Etag, p.ID, p.Etag, "scope-etag", a)
	if err != nil || again.CurrentVersion != draft.CurrentVersion {
		t.Fatal("draft retry", err)
	}
	if draft.CurrentVersion != 2 || draft.ApprovedVersion != 0 || draft.DeployedVersion != 0 {
		t.Fatalf("automatic activation %+v", draft)
	}
	var fields map[string]json.RawMessage
	if err = json.Unmarshal(draft.Spec, &fields); err != nil {
		t.Fatal(err)
	}
	if string(fields["future_setting"]) != "true" || !strings.Contains(string(fields["api_discovery"]), proposal.Digest) || !strings.Contains(string(fields["api_discovery"]), "documentation_only") {
		t.Fatalf("reference %s", draft.Spec)
	}
	var n int
	if err = st.pool.QueryRow(ctx, `SELECT count(*) FROM operations WHERE policy_id=$1`, p.ID).Scan(&n); err != nil || n != 1 {
		t.Fatalf("replay %d %v", n, err)
	}
	a.RequestID = "second"
	if _, err = st.DraftDiscoveryProposal(ctx, proposal.ID, proposal.Etag, p.ID, draft.Etag, "scope-etag", a); err == nil {
		t.Fatal("proposal reused for a second draft")
	}
	proposals, err := st.DiscoveryProposals(ctx, "example-api", "test", "scope-etag", time.Now().UTC())
	if err != nil || len(proposals) != 1 || proposals[0].ReviewState != "DRAFT" {
		t.Fatalf("review %+v %v", proposals, err)
	}
	if _, err = st.pool.Exec(ctx, `UPDATE applications SET etag='scope-next'`); err != nil {
		t.Fatal(err)
	}
	proposals, err = st.DiscoveryProposals(ctx, "example-api", "test", "scope-next", time.Now().UTC())
	if err != nil || len(proposals) != 0 {
		t.Fatal("scope changed", err)
	}
}

func TestDiscoveryCardinalityAndObservationQuotas(t *testing.T) {
	st, _, _, samples := discoveryFixture(t)
	ctx := t.Context()
	if _, err := st.pool.Exec(ctx, `INSERT INTO discovery_observations(observation_key,application_id,environment_id,scope_etag,route_id,method,path,content_type,body_bytes,source_hash,at) SELECT md5(g::text)||md5('key'||g),'example-api','test','scope-etag','api','GET','/api/items/'||g,'none',0,repeat('a',64),now() FROM generate_series(1,1000) g`); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveDiscoveryBatch(ctx, "example-api", "test", "scope-etag", "cardinality", "sa:collector", samples[:1]); err == nil || !strings.Contains(err.Error(), "endpoint quota") {
		t.Fatalf("cardinality %v", err)
	}
	if _, err := st.pool.Exec(ctx, `INSERT INTO discovery_observations(observation_key,application_id,environment_id,scope_etag,route_id,method,path,content_type,body_bytes,source_hash,at) SELECT md5(g::text)||md5('key'||g),'example-api','test','scope-etag','api','GET','/api/items/1','none',0,repeat('a',64),now() FROM generate_series(1001,10000) g`); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveDiscoveryBatch(ctx, "example-api", "test", "scope-etag", "rows", "sa:collector", samples[:1]); err == nil || !strings.Contains(err.Error(), "observation quota") {
		t.Fatalf("observation cap %v", err)
	}
}
