package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/strata/strata/control-plane/auth"
	"github.com/strata/strata/control-plane/store"
)

func TestApplicationsScopesAndRetriesInPostgres(t *testing.T) {
	pool := migratedPool(t)
	st := store.New(pool)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `INSERT INTO connector_groups(id,name) VALUES('edge-a','A'),('edge-b','B');
 INSERT INTO nodes(id,group_id) VALUES('node-a','edge-a'),('node-b','edge-b');
 INSERT INTO policies(id,name,etag,created_by) VALUES('shared','shared','tag','test'),('own-a','own-a','tag','test')`); err != nil {
		t.Fatal(err)
	}
	audit := store.Audit{Actor: "admin", Subject: "local:admin", Action: "application.save"}
	application := func(id, group, host string) store.Application {
		return store.Application{ID: id, Name: id, Owner: "example-owner", Environments: []store.ApplicationEnvironment{{ID: "prod", Name: "Production", GroupID: group}}, Routes: []store.ApplicationRoute{{ID: "api", EnvironmentID: "prod", Host: host, PathPrefix: "/", PolicyID: "shared"}}}
	}
	a, err := st.SaveApplication(ctx, application("app-a", "edge-a", "a.example.test"), true, "create-a", audit)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := st.SaveApplication(ctx, application("app-a", "edge-a", "a.example.test"), true, "create-a", audit)
	if err != nil || retry.Etag != a.Etag {
		t.Fatalf("retry: %+v %v", retry, err)
	}
	changed := application("app-a", "edge-a", "a.example.test")
	changed.Owner = "different"
	if _, err = st.SaveApplication(ctx, changed, true, "create-a", audit); !errors.Is(err, store.ErrApplicationConflict) {
		t.Fatalf("reused request: %v", err)
	}
	b, err := st.SaveApplication(ctx, application("app-b", "edge-b", "b.example.test"), true, "create-b", audit)
	if err != nil {
		t.Fatal(err)
	}
	var binding store.ApplicationBinding
	appA, appB := a.ID, b.ID
	binding, err = st.AddApplicationBinding(ctx, store.ApplicationBinding{Subject: "local:alice", Role: "operator", ApplicationID: &appA, RequestID: "grant-a"}, audit)
	if err != nil {
		t.Fatal(err)
	}
	duplicate, err := st.AddApplicationBinding(ctx, store.ApplicationBinding{Subject: "local:alice", Role: "operator", ApplicationID: &appA, RequestID: "grant-a"}, audit)
	if err != nil || duplicate.ID != binding.ID {
		t.Fatalf("binding retry: %v", err)
	}
	resolve := func(subject string) *auth.Principal {
		t.Helper()
		p, err := st.ResolveApplicationAccess(ctx, &auth.Principal{Subject: subject, Roles: []auth.Role{auth.RoleAdmin}})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	alice := resolve("local:alice")
	if !alice.CanResource("applications/app-a", auth.PermApplicationsRead) || alice.CanResource("applications/app-b", auth.PermApplicationsRead) {
		t.Fatal("application IDOR")
	}
	if alice.CanResource("policies/shared", auth.PermPoliciesWrite) {
		t.Fatal("shared-policy write escaped other application")
	}
	if len(alice.Access.Events) != 1 || alice.Access.Events[0].Host != "a.example.test" || len(alice.Access.Events[0].Nodes) != 1 || alice.Access.Events[0].Nodes[0] != "node-a" {
		t.Fatalf("event scope: %+v", alice.Access.Events)
	}
	if _, err = st.AddApplicationBinding(ctx, store.ApplicationBinding{Subject: "local:alice", Role: "operator", ApplicationID: &appB}, audit); err != nil {
		t.Fatal(err)
	}
	alice = resolve("local:alice")
	if !alice.CanResource("policies/shared", auth.PermPoliciesWrite) {
		t.Fatal("all owners granted but shared write denied")
	}
	if _, err = st.AddApplicationBinding(ctx, store.ApplicationBinding{Subject: "local:mixed", Role: "viewer", ApplicationID: &appA}, audit); err != nil {
		t.Fatal(err)
	}
	if _, err = st.AddApplicationBinding(ctx, store.ApplicationBinding{Subject: "local:mixed", Role: "operator", ApplicationID: &appB}, audit); err != nil {
		t.Fatal(err)
	}
	if resolve("local:mixed").Can(auth.PermEventsReadSensitive) {
		t.Fatal("viewer data became sensitive through another application's operator role")
	}
	if _, err = st.AddApplicationBinding(ctx, store.ApplicationBinding{Subject: "local:revoked", Role: "viewer", ApplicationID: &appA}, audit); err != nil {
		t.Fatal(err)
	}
	bs, err := st.ApplicationBindings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range bs {
		if row.Subject == "local:revoked" {
			if err = st.DeleteApplicationBinding(ctx, row.ID, audit); err != nil {
				t.Fatal(err)
			}
		}
	}
	if resolve("local:revoked").Can(auth.PermEventsRead) {
		t.Fatal("last binding removal restored global role")
	}
	old := a
	a.Name = "New name"
	if _, err = st.SaveApplication(ctx, a, false, "update-a", audit); err != nil {
		t.Fatal(err)
	}
	if _, err = st.SaveApplication(ctx, old, false, "stale-a", audit); !errors.Is(err, store.ErrApplicationConflict) {
		t.Fatalf("stale etag: %v", err)
	}
	overlap := application("app-overlap", "edge-a", "a.example.test")
	overlap.Routes[0].PathPrefix = "/v1/"
	if _, err = st.SaveApplication(ctx, overlap, true, "overlap", audit); err == nil {
		t.Fatal("cross-application overlapping ownership accepted")
	}
	if _, err = st.GetApplication(ctx, "app-overlap"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("rejected application persisted")
	}
}
