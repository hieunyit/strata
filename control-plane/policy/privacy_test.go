package policy

import (
	"context"
	"testing"

	"github.com/strata/strata/control-plane/localauth/localauthtest"
	"github.com/strata/strata/control-plane/store"
)

func TestPrivacyUsesPinnedBundleRevisionNotLatestDraft(t *testing.T) {
	ctx := context.Background()
	pool := localauthtest.Pool(t)
	st := store.New(pool)
	a := store.Audit{Actor: "example-admin", Subject: "local:example-admin", Action: "policies.create", Resource: "policies/example-api"}
	p, err := st.CreatePolicy(ctx, store.Policy{ID: "example-resource", Name: "example-api", Spec: []byte(`{"mode":"shadow","privacy":{"sensitive_fields":["customer_id"],"mask_patterns":["PRIVATE-[0-9]+"]}}`)}, a)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.RecordBundle(ctx, store.Bundle{Version: 7, SHA256: make([]byte, 32), ObjectKey: "bundles/example-7.sbn", SizeBytes: 1, Contents: map[string]int{p.ID: 1}, CreatedBy: a.Actor}, a); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpdatePolicy(ctx, p.ID, p.Etag, []byte(`{"mode":"shadow"}`), a); err != nil {
		t.Fatal(err)
	}
	r := PrivacyResolver{Store: st}
	f, err := r.Filter(ctx, "example-api", 7)
	if err != nil || f.Field("ARGS:customer_id", "private") != "[MASKED]" || f.Text("PRIVATE-123") != "[MASKED]" {
		t.Fatal("draft replaced historical privacy", err)
	}
	if _, err := r.Filter(ctx, "example-api", 8); err == nil {
		t.Fatal("unknown bundle used latest draft")
	}
}
