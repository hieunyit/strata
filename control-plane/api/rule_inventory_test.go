package api

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/strata/strata/control-plane/policy"
	"github.com/strata/strata/control-plane/ruleinventory"
	"github.com/strata/strata/control-plane/store"
)

func TestRuleInventoryAndExceptionDrafts(t *testing.T) {
	previous, st, pool, events, _ := investigationFixture(t)
	ctx := t.Context()
	now := time.Now().UTC()
	path := filepath.Join(t.TempDir(), "rules.yaml")
	source := `ir_version: 1
ruleset: {name: example-pack, version: '1.0'}
rules:
- id: 700011
  name: Virtual patch CVE-2026-12345
  layer: managed
  metadata: {source: strata, attack_type: rce, owner: example-team}
`
	if err := os.WriteFile(path, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	catalog := &ruleinventory.Catalog{Store: st, Paths: []string{path}}
	if err := catalog.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	s := NewServer(ServerConfig{Auth: previous.cfg.Auth, Applications: st, Annotations: st, RuleCatalog: catalog, ReplayKick: func() {}}, events)
	rec := investigationRequest(t, s, "viewer", "GET", "/v1/rule-catalog?cve=CVE-2026-12345", nil, 200)
	if !json.Valid(rec.Body.Bytes()) {
		t.Fatal(rec.Body.String())
	}
	investigationRequest(t, s, "outsider", "GET", "/v1/rule-catalog/700011?application_id=example-api&environment_id=test", nil, 403)
	investigationRequest(t, s, "viewer", "GET", "/v1/rule-catalog/700011?application_id=example-api&environment_id=other", nil, 404)
	investigationRequest(t, s, "viewer", "GET", "/v1/rule-catalog/700011?application_id=example-api&environment_id=test", nil, 200)
	var history struct {
		Catalogs []store.CatalogSnapshot `json:"catalogs"`
	}
	rec = investigationRequest(t, s, "viewer", "GET", "/v1/rule-catalogs", nil, 200)
	if err := json.Unmarshal(rec.Body.Bytes(), &history); err != nil || len(history.Catalogs) != 1 {
		t.Fatalf("history %+v %v", history, err)
	}
	digest := history.Catalogs[0].Digest
	investigationRequest(t, s, "viewer", "GET", "/v1/rule-catalogs:diff?from="+digest+"&to="+digest, nil, 200)
	investigationRequest(t, s, "viewer", "GET", "/v1/rule-catalogs:diff?from=../../etc/passwd&to="+digest, nil, 400)
	p, err := st.GetPolicy(ctx, "policy-api")
	if err != nil {
		t.Fatal(err)
	}
	exceptions := []policy.Exception{{ID: "exc-0123456789abcdef0123456789abcdef", RuleID: 700011, Method: "POST", Host: "api.example.test", Path: "/api/search", Field: "ARGS:q", Reason: "private investigation context", ExpiresUnixMS: now.Add(-time.Hour).UnixMilli()}, {ID: "exc-1123456789abcdef0123456789abcdef", RuleID: 700011, Method: "POST", Host: "other.example.test", Path: "/private/search", Field: "ARGS:q", Reason: "another app", ExpiresUnixMS: now.Add(time.Hour).UnixMilli()}}
	raw, err := json.Marshal(map[string]any{"mode": "enforce", "future_setting": true, "exceptions": exceptions})
	if err != nil {
		t.Fatal(err)
	}
	p, err = st.UpdatePolicy(ctx, p.ID, p.Etag, raw, store.Audit{Actor: "operator", Subject: "oidc:operator", Action: "policy.update"})
	if err != nil {
		t.Fatal(err)
	}
	rec = investigationRequest(t, s, "viewer", "GET", "/v1/exceptions?application_id=example-api&environment_id=test", nil, 200)
	var page ruleinventory.ExceptionPage
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Exceptions) != 1 || page.Exceptions[0].Exception.Reason != "" || page.Exceptions[0].Editable || page.Exceptions[0].UnusedStatus != "unknown" {
		t.Fatalf("viewer scope/privacy: %+v", page)
	}
	input := ExceptionLifecycleRequest{ApplicationID: "example-api", EnvironmentID: "test", PolicyID: p.ID, Etag: p.Etag, RequestID: "cleanup"}
	investigationRequest(t, s, "viewer", "POST", "/v1/exceptions:cleanupExpired", input, 403)
	rec = investigationRequest(t, s, "operator", "POST", "/v1/exceptions:cleanupExpired", input, 200)
	investigationRequest(t, s, "operator", "POST", "/v1/exceptions:cleanupExpired", input, 200)
	var receipt EventRuleDraft
	if err := json.Unmarshal(rec.Body.Bytes(), &receipt); err != nil || receipt.State != "DRAFT" || receipt.PolicyVersion != 3 {
		t.Fatalf("cleanup receipt %+v %v", receipt, err)
	}
	current, err := st.GetPolicy(ctx, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := policy.Parse(current.Spec)
	if err != nil || len(spec.Exceptions) != 1 || spec.Exceptions[0].ID != exceptions[1].ID {
		t.Fatalf("cleanup scope %+v %v", spec, err)
	}
	// The action creates one replay and never silently approves/deploys.
	var operations int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM operations WHERE policy_id=$1`, p.ID).Scan(&operations); err != nil || operations != 1 {
		t.Fatalf("replay count %d %v", operations, err)
	}
	input.Etag = p.Etag
	input.RequestID = "stale"
	investigationRequest(t, s, "operator", "POST", "/v1/exceptions:cleanupExpired", input, 409)
}
