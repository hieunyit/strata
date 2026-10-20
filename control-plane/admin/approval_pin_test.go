package admin_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/strata/strata/control-plane/admin"
	"github.com/strata/strata/control-plane/api"
	"github.com/strata/strata/control-plane/auth"
	"github.com/strata/strata/control-plane/auth/authtest"
	"github.com/strata/strata/control-plane/ingest"
	"github.com/strata/strata/control-plane/localauth/localauthtest"
	"github.com/strata/strata/control-plane/store"
)

func TestApproveReplayPinRESTInPostgres(t *testing.T) {
	ctx := t.Context()
	pg := store.New(localauthtest.Pool(t))
	// the author signs in through OIDC: its stored subject is namespaced (CP-SEC-01)
	author := store.Audit{Actor: "author", Subject: auth.OIDCSubjectPrefix + "author"}
	for _, id := range []string{"example-api", "other-api", "legacy-api"} {
		if _, err := pg.CreatePolicy(ctx, store.Policy{ID: id, Name: id, Spec: []byte(`{}`)}, author); err != nil {
			t.Fatal(err)
		}
		if _, err := pg.SubmitPolicyVersion(ctx, id, 1, author); err != nil {
			t.Fatal(err)
		}
	}
	run := func(id, failure string) store.Operation {
		t.Helper()
		op, err := pg.CreateReplayOperation(ctx, id, 1, author)
		if err != nil {
			t.Fatal(err)
		}
		claimed, ok, err := pg.ClaimOperation(ctx, time.Now().Add(-time.Hour))
		if err != nil || !ok || claimed.ID != op.ID {
			t.Fatal("claim", err)
		}
		if err = pg.FinishOperation(ctx, op.ID, []byte(`{"samples":1}`), failure); err != nil {
			t.Fatal(err)
		}
		return op
	}
	a := run("example-api", "")
	other := run("other-api", "")
	_ = run("legacy-api", "")
	is := authtest.New(t)
	verifier, err := auth.NewVerifier(ctx, auth.Config{Issuer: is.URL, Audience: authtest.Audience})
	if err != nil {
		t.Fatal(err)
	}
	adm, err := admin.New(ctx, verifier, admin.BuildInfo{}, admin.Deps{Policies: pg, Operations: pg})
	if err != nil {
		t.Fatal(err)
	}
	defer adm.Close()
	handler := api.NewServer(api.ServerConfig{Auth: verifier, Admin: adm.Gateway}, ingest.NewMockEventStore()).Handler()
	call := func(id, subject, role, body string, want int) {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/v1/policies/"+id+":approve", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+is.Token(t, authtest.Claims{Subject: subject, Roles: []string{role}}))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Fatalf("%s %s: %d %s (want %d)", id, body, rec.Code, rec.Body.String(), want)
		}
	}
	for _, pin := range []string{other.ID, "op-missing"} {
		call("example-api", "reviewer", "approver", fmt.Sprintf(`{"version":1,"expected_replay_id":%q}`, pin), 400)
	}
	for _, pin := range []string{"has space", strings.Repeat("a", 129), "\n"} {
		call("example-api", "reviewer", "approver", fmt.Sprintf(`{"version":1,"expected_replay_id":%q}`, pin), 400)
	}
	failed := run("example-api", "example failure")
	call("example-api", "reviewer", "approver", fmt.Sprintf(`{"version":1,"expected_replay_id":%q}`, failed.ID), 400)
	b := run("example-api", "")
	before, err := pg.AuditEntries(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		subject, role, pin string
		code               int
	}{
		{"reviewer", "approver", a.ID, 400}, {"reviewer", "viewer", b.ID, 403}, {"reviewer", "operator", b.ID, 403}, {"author", "approver", b.ID, 403},
	} {
		call("example-api", tc.subject, tc.role, fmt.Sprintf(`{"version":1,"expected_replay_id":%q}`, tc.pin), tc.code)
	}
	call("example-api", "reviewer", "approver", fmt.Sprintf(`{"version":2,"expected_replay_id":%q}`, b.ID), 400)
	after, err := pg.AuditEntries(ctx, 100)
	if err != nil || len(before) != len(after) {
		t.Fatal("rejected approval wrote audit", err)
	}
	call("example-api", "reviewer", "approver", fmt.Sprintf(`{"version":1,"expected_replay_id":%q}`, b.ID), 200)
	saved, err := pg.GetPolicyVersion(ctx, "example-api", 1)
	if err != nil || saved.ApprovedReplayID != b.ID {
		t.Fatal("proof", err)
	}
	call("legacy-api", "reviewer", "approver", `{"version":1}`, 200)
	legacy, err := pg.GetPolicyVersion(ctx, "legacy-api", 1)
	if err != nil || legacy.ApprovedReplayID == "" {
		t.Fatal("legacy compatibility", err)
	}
	// A later PENDING replay never rewrites a committed approval.
	if _, err = pg.CreateReplayOperation(ctx, "example-api", 1, author); err != nil {
		t.Fatal(err)
	}
	saved, err = pg.GetPolicyVersion(ctx, "example-api", 1)
	if err != nil || saved.ApprovedReplayID != b.ID {
		t.Fatal("approval replaced", err)
	}
	pending, err := pg.CreateReplayOperation(ctx, "other-api", 1, author)
	if err != nil {
		t.Fatal(err)
	}
	call("other-api", "reviewer", "approver", fmt.Sprintf(`{"version":1,"expected_replay_id":%q}`, pending.ID), 400)
	call("other-api", "reviewer", "approver", `{"version":1,"expected_replay_id":"op-missing"}`, 400)
	t.Log("PASS: stale/wrong/missing/failed replay, validation, RBAC and four eyes refused; exact proof and legacy caller accepted")
}
