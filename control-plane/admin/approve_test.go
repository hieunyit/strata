package admin_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/strata/strata/control-plane/admin"
	"github.com/strata/strata/control-plane/api"
	"github.com/strata/strata/control-plane/auth"
	"github.com/strata/strata/control-plane/auth/authtest"
	"github.com/strata/strata/control-plane/ingest"
	"github.com/strata/strata/control-plane/store"
)

type decidingStore struct {
	admin.PolicyStore
	decided int
}

func (d *decidingStore) DecidePolicyVersion(_ context.Context, id string, v int, approve bool, _ string, _ store.Audit) (store.PolicyVersion, error) {
	d.decided++
	state := store.VersionRejected
	if approve {
		state = store.VersionApproved
	}
	return store.PolicyVersion{PolicyID: id, Version: v, State: state}, nil
}

type replayState struct {
	admin.OperationStore
	op  store.Operation
	err error
}

func (r *replayState) LatestReplay(context.Context, string, int) (store.Operation, error) {
	return r.op, r.err
}

// PO 16/10/2026: with replay configured, a version is approved only once
// its newest replay is DONE; a rejection never waits for it.
func TestApproveNeedsADoneReplay(t *testing.T) {
	ctx := context.Background()
	is := authtest.New(t)
	v, err := auth.NewVerifier(ctx, auth.Config{Issuer: is.URL, Audience: authtest.Audience})
	if err != nil {
		t.Fatal(err)
	}
	ps, ops := &decidingStore{}, &replayState{}
	a, err := admin.New(ctx, v, admin.BuildInfo{}, admin.Deps{Policies: ps, Operations: ops})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	h := api.NewServer(api.ServerConfig{Auth: v, Admin: a.Gateway}, ingest.NewMockEventStore()).Handler()
	call := func(verb, body string) (int, string) {
		req := httptest.NewRequest(http.MethodPost, "/v1/policies/example-api:"+verb, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+is.Token(t, authtest.Claims{Subject: "lab-approver", Roles: []string{"approver"}}))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}
	for _, tc := range []struct {
		name string
		op   store.Operation
		err  error
		want string
	}{
		{"no replay", store.Operation{}, store.ErrNotFound, "has no replay"},
		{"pending", store.Operation{ID: "op-1", State: store.OpPending}, nil, "is PENDING"},
		{"running", store.Operation{ID: "op-1", State: store.OpRunning}, nil, "is RUNNING"},
		{"failed", store.Operation{ID: "op-1", State: store.OpFailed, Error: "no corpus"}, nil, "failed (no corpus)"},
	} {
		ops.op, ops.err = tc.op, tc.err
		if c, body := call("approve", `{"version":2}`); c != http.StatusBadRequest || !strings.Contains(body, tc.want) {
			t.Errorf("%s: %d %s", tc.name, c, body)
		}
	}
	if ps.decided != 0 {
		t.Fatalf("decided without a done replay: %d", ps.decided)
	}
	if c, body := call("reject", `{"version":2,"comment":"not yet"}`); c != http.StatusOK {
		t.Fatalf("reject while the replay runs: %d %s", c, body)
	}
	ops.op, ops.err = store.Operation{ID: "op-1", State: store.OpDone}, nil
	if c, body := call("approve", `{"version":2}`); c != http.StatusOK || !strings.Contains(body, "APPROVED") {
		t.Fatalf("approve after a done replay: %d %s", c, body)
	}
}
