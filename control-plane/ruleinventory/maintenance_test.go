package ruleinventory

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/strata/strata/control-plane/localauth/localauthtest"
	"github.com/strata/strata/control-plane/policy"
	"github.com/strata/strata/control-plane/store"
)

func maintenancePolicy(t *testing.T, st *store.Store, id string, now time.Time) store.Policy {
	t.Helper()
	spec := map[string]any{"mode": "enforce", "future_setting": true, "exceptions": []policy.Exception{{ID: "exc-0123456789abcdef0123456789abcdef", RuleID: 700011, Method: "GET", Host: "api.example.test", Path: "/api/search", Field: "ARGS:q", Reason: "synthetic legitimate value", ExpiresUnixMS: now.Add(-time.Hour).UnixMilli()}, {ID: "exc-1123456789abcdef0123456789abcdef", RuleID: 700011, Method: "GET", Host: "api.example.test", Path: "/api/next", Field: "ARGS:q", Reason: "synthetic legitimate value", ExpiresUnixMS: now.Add(24 * time.Hour).UnixMilli()}}}
	raw, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	p, err := st.CreatePolicy(t.Context(), store.Policy{ID: id, Name: id, Spec: raw}, store.Audit{Actor: "operator", Subject: "oidc:operator", Action: "policy.create"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.SubmitPolicyVersion(t.Context(), p.ID, 1, store.Audit{Actor: "operator", Subject: "oidc:operator"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DecidePolicyVersion(t.Context(), p.ID, 1, true, "reviewed", store.Audit{Actor: "approver", Subject: "oidc:approver"}); err != nil {
		t.Fatal(err)
	}
	p, err = st.GetPolicy(t.Context(), p.ID)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func TestMaintenanceDraftsWithoutPublishingOrOverwriting(t *testing.T) {
	pool := localauthtest.Pool(t)
	st := store.New(pool)
	now := time.Now().UTC()
	ctx := t.Context()
	first := maintenancePolicy(t, st, "example-api", now)
	busy := maintenancePolicy(t, st, "example-busy", now)
	if _, err := st.UpdatePolicy(ctx, busy.ID, busy.Etag, []byte(`{"mode":"shadow","custom_future":"keep"}`), store.Audit{Actor: "operator", Subject: "oidc:operator"}); err != nil {
		t.Fatal(err)
	}
	kicks := 0
	m := &Maintenance{Store: st, Now: func() time.Time { return now }, ReplayKick: func() { kicks++ }}
	if err := m.Once(ctx); err != nil {
		t.Fatal(err)
	}
	current, err := st.GetPolicy(ctx, first.ID)
	if err != nil || current.CurrentVersion != 2 || current.ApprovedVersion != 1 || current.DeployedVersion != 0 {
		t.Fatalf("unexpected activation: %+v %v", current, err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(current.Spec, &fields); err != nil {
		t.Fatal(err)
	}
	if string(fields["future_setting"]) != "true" {
		t.Fatal("cleanup discarded future settings")
	}
	spec, err := policy.Parse(current.Spec)
	if err != nil || len(spec.Exceptions) != 1 || spec.Exceptions[0].ExpiresUnixMS <= now.UnixMilli() {
		t.Fatalf("cleanup scope: %+v %v", spec, err)
	}
	currentBusy, err := st.GetPolicy(ctx, busy.ID)
	if err != nil {
		t.Fatal(err)
	}
	var busyFields map[string]json.RawMessage
	if err := json.Unmarshal(currentBusy.Spec, &busyFields); err != nil {
		t.Fatal(err)
	}
	if currentBusy.CurrentVersion != 2 || string(busyFields["custom_future"]) != `"keep"` || string(busyFields["mode"]) != `"shadow"` {
		t.Fatalf("human draft overwritten: %+v", currentBusy)
	}

	tasks, err := st.ExceptionMaintenance(ctx, first.ID)
	if err != nil || len(tasks) != 1 || tasks[0].State != "drafted" || tasks[0].DraftVersion != 2 {
		t.Fatalf("task %+v %v", tasks, err)
	}
	var operations int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM operations WHERE policy_id=$1`, first.ID).Scan(&operations); err != nil || operations != 1 {
		t.Fatalf("replay %d %v", operations, err)
	}
	// Simulate a crash between draft commit and task completion. A new worker
	// retrieves the original durable receipt even after the current etag changed.
	if _, err := pool.Exec(ctx, `UPDATE exception_maintenance SET state='pending',draft_version=NULL WHERE policy_id=$1`, first.ID); err != nil {
		t.Fatal(err)
	}
	m = &Maintenance{Store: st, Now: func() time.Time { return now.Add(25 * time.Hour) }, ReplayKick: func() { kicks++ }}
	if err := m.Once(ctx); err != nil {
		t.Fatal(err)
	}
	current, err = st.GetPolicy(ctx, first.ID)
	if err != nil || current.CurrentVersion != 2 {
		t.Fatalf("retry duplicated draft: %+v %v", current, err)
	}
	if kicks != 2 {
		t.Fatalf("replay notifications=%d", kicks)
	}
}

func TestMaintenanceReconcilesWithNoExpiredCandidates(t *testing.T) {
	pool := localauthtest.Pool(t)
	st := store.New(pool)
	ctx := t.Context()
	now := time.Now().UTC()
	p := maintenancePolicy(t, st, "example-reconcile", now)
	task, err := st.QueueExceptionMaintenance(ctx, p.ID, 1, p.Etag, []string{"exc-0123456789abcdef0123456789abcdef"})
	if err != nil {
		t.Fatal(err)
	}
	p, err = st.UpdatePolicy(ctx, p.ID, p.Etag, []byte(`{"mode":"shadow"}`), store.Audit{Actor: "operator", Subject: "oidc:operator"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = st.SubmitPolicyVersion(ctx, p.ID, 2, store.Audit{Actor: "operator", Subject: "oidc:operator"}); err != nil {
		t.Fatal(err)
	}
	if _, err = st.DecidePolicyVersion(ctx, p.ID, 2, true, "reviewed", store.Audit{Actor: "approver", Subject: "oidc:approver"}); err != nil {
		t.Fatal(err)
	}
	m := Maintenance{Store: st}
	if err = m.Once(ctx); err != nil {
		t.Fatal(err)
	}
	tasks, err := st.ExceptionMaintenance(ctx, p.ID)
	if err != nil || len(tasks) != 1 || tasks[0].State != "superseded" || tasks[0].Etag == task.Etag {
		t.Fatalf("not reconciled: %+v %v", tasks, err)
	}
	if _, err = pool.Exec(ctx, `UPDATE exception_maintenance SET updated_at=now()-interval '31 days'`); err != nil {
		t.Fatal(err)
	}
	if err = m.Once(ctx); err != nil {
		t.Fatal(err)
	}
	tasks, err = st.ExceptionMaintenance(ctx, p.ID)
	if err != nil || len(tasks) != 0 {
		t.Fatalf("not pruned: %+v %v", tasks, err)
	}
}
