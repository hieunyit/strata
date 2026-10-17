package store_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/strata/strata/control-plane/localauth/localauthtest"
	"github.com/strata/strata/control-plane/policy"
	"github.com/strata/strata/control-plane/store"
)

func TestAutoStagingPolicyRequiresIndependentApproval(t *testing.T) {
	p := localauthtest.Pool(t)
	s := store.New(p)
	ctx := t.Context()
	draft := store.Audit{Actor: "operator", Subject: "operator"}
	raw := json.RawMessage(`{"mode":"enforce","auto_staging":{"enabled":true,"rule_ids":[942100],"window_seconds":300,"min_matches":100,"min_reports":5,"fp_threshold_bps":500}}`)
	created, err := s.CreatePolicy(ctx, store.Policy{ID: "example-api", Name: "example-api", Spec: raw}, draft)
	if err != nil {
		t.Fatal(err)
	}
	ds, err := s.DeployablePolicies(ctx)
	if err != nil || len(ds) != 0 {
		t.Fatalf("draft grants delegation: %v %v", ds, err)
	}
	if _, err := s.SubmitPolicyVersion(ctx, created.ID, 1, draft); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DecidePolicyVersion(ctx, created.ID, 1, true, "", draft); !errors.Is(err, store.ErrFourEyes) {
		t.Fatalf("self approval: %v", err)
	}
	if _, err := s.DecidePolicyVersion(ctx, created.ID, 1, true, "allow configured reduction", store.Audit{Actor: "approver", Subject: "approver"}); err != nil {
		t.Fatal(err)
	}
	ds, err = store.New(p).DeployablePolicies(ctx)
	if err != nil || len(ds) != 1 {
		t.Fatalf("approved delegation lost: %v %v", ds, err)
	}
	spec, err := policy.Parse(ds[0].Spec)
	if err != nil || spec.AutoStaging == nil || !spec.AutoStaging.Enabled || spec.AutoStaging.MinReports != 5 {
		t.Fatalf("stored delegation: %+v %v", spec, err)
	}
	// Saving an edited draft must not replace the previously approved authority.
	if _, err := s.UpdatePolicy(ctx, created.ID, created.Etag, []byte(`{"mode":"enforce","auto_staging":{"enabled":false}}`), draft); err != nil {
		t.Fatal(err)
	}
	ds, err = s.DeployablePolicies(ctx)
	if err != nil || len(ds) != 1 || ds[0].CurrentVersion != 1 {
		t.Fatalf("unapproved edit became authority: %v %v", ds, err)
	}
}
