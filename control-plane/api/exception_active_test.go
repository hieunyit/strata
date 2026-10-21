package api

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/strata/strata/control-plane/policy"
	"github.com/strata/strata/control-plane/ruleinventory"
	"github.com/strata/strata/control-plane/store"
)

func TestExceptionInventoryRetainsNodeActiveRevisions(t *testing.T) {
	s, st, pool, _, _ := investigationFixture(t)
	ctx := t.Context()
	p, err := st.GetPolicy(ctx, "policy-api")
	if err != nil {
		t.Fatal(err)
	}
	e := policy.Exception{ID: "exc-0123456789abcdef0123456789abcdef", RuleID: 700011, Method: "POST", Host: "api.example.test", Path: "/api/search", Field: "ARGS:q", Reason: "example", ExpiresUnixMS: time.Now().Add(time.Hour).UnixMilli()}
	raw, err := json.Marshal(map[string]any{"mode": "enforce", "exceptions": []policy.Exception{e}})
	if err != nil {
		t.Fatal(err)
	}
	author := store.Audit{Actor: "operator", Subject: "oidc:operator"}
	approver := store.Audit{Actor: "approver", Subject: "oidc:approver"}
	p, err = st.UpdatePolicy(ctx, p.ID, p.Etag, raw, author)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.SubmitPolicyVersion(ctx, p.ID, p.CurrentVersion, author); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DecidePolicyVersion(ctx, p.ID, p.CurrentVersion, true, "reviewed", approver); err != nil {
		t.Fatal(err)
	}
	if _, err := st.RecordBundle(ctx, store.Bundle{Version: 1, SHA256: make([]byte, 32), ObjectKey: "bundles/example.sbn", SizeBytes: 128, Contents: map[string]int{p.ID: p.CurrentVersion}}, author); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE nodes SET bundle_version=1,bundle_state='ACTIVE' WHERE id='node-a'`); err != nil {
		t.Fatal(err)
	}
	p, err = st.GetPolicy(ctx, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	p, err = st.UpdatePolicy(ctx, p.ID, p.Etag, []byte(`{"mode":"enforce"}`), author)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.SubmitPolicyVersion(ctx, p.ID, p.CurrentVersion, author); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DecidePolicyVersion(ctx, p.ID, p.CurrentVersion, true, "reviewed cleanup", approver); err != nil {
		t.Fatal(err)
	}
	rec := investigationRequest(t, s, "viewer", "GET", "/v1/exceptions?application_id=example-api&environment_id=test", nil, 200)
	var page ruleinventory.ExceptionPage
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Exceptions) != 1 || page.Exceptions[0].PolicyVersion != 2 || page.Exceptions[0].ActiveNodes != 1 || page.Exceptions[0].Editable {
		t.Fatalf("active old version hidden: %+v", page)
	}
	if _, err := pool.Exec(ctx, `UPDATE nodes SET revoked_at=now() WHERE id='node-a'`); err != nil {
		t.Fatal(err)
	}
	rec = investigationRequest(t, s, "viewer", "GET", "/v1/exceptions?application_id=example-api&environment_id=test", nil, 200)
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Exceptions) != 0 {
		t.Fatalf("revoked node kept obsolete revision %+v", page)
	}
}
