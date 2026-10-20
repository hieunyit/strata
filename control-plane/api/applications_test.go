package api

import (
	"context"
	"encoding/json"
	"github.com/strata/strata/control-plane/auth"
	"github.com/strata/strata/control-plane/ingest"
	"github.com/strata/strata/control-plane/localauth/localauthtest"
	"github.com/strata/strata/control-plane/store"
	"testing"
)

func TestApplicationAPIIDORAndEnvironment(t *testing.T) {
	pool := localauthtest.Pool(t)
	st := store.New(pool)
	ctx := t.Context()
	if _, err := pool.Exec(ctx, `INSERT INTO connector_groups(id,name) VALUES('edge','Edge'); INSERT INTO policies(id,name,etag,created_by) VALUES('example-api','example-api','e','test')`); err != nil {
		t.Fatal(err)
	}
	adminAudit := store.Audit{Subject: "local:admin", Actor: "admin", Action: "test"}
	app := store.Application{ID: "app-a", Name: "Example", Owner: "Owner", Environments: []store.ApplicationEnvironment{{ID: "prod", Name: "Prod", GroupID: "edge"}, {ID: "dev", Name: "Dev", GroupID: "edge"}}, Routes: []store.ApplicationRoute{{ID: "prod", EnvironmentID: "prod", Host: "api.example.test", PathPrefix: "/", PolicyID: "example-api"}, {ID: "dev", EnvironmentID: "dev", Host: "dev.example.test", PathPrefix: "/", PolicyID: "example-api"}}}
	if _, err := st.SaveApplication(ctx, app, true, "create", adminAudit); err != nil {
		t.Fatal(err)
	}
	id, env := "app-a", "prod"
	if _, err := st.AddApplicationBinding(ctx, store.ApplicationBinding{Subject: "operator", Role: "viewer", ApplicationID: &id, EnvironmentID: &env}, adminAudit); err == nil {
		t.Fatal("unnamespaced subject accepted")
	}
	// tokenRoles uses a legacy subject; wrap it into the authenticated namespace.
	verifier := auth.ResolveAccess{Authenticator: applicationTokens{}, Resolve: st.ResolveApplicationAccess}
	binding, err := st.AddApplicationBinding(ctx, store.ApplicationBinding{Subject: "local:operator", Role: "viewer", ApplicationID: &id, EnvironmentID: &env}, adminAudit)
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(ServerConfig{Auth: verifier, Applications: st}, ingest.NewMockEventStore())
	headers := map[string]string{"Authorization": "Bearer operator"}
	code, data := machineRequest(server.Handler(), "GET", "/v1/applications/app-a", nil, headers)
	var out struct {
		Application store.Application `json:"application"`
	}
	if err = json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	if code != 200 || len(out.Application.Environments) != 1 || len(out.Application.Routes) != 1 || out.Application.Environments[0].ID != "prod" {
		t.Fatalf("environment disclosure: %d %s", code, data)
	}
	for _, path := range []string{"/v1/applications/app-b", "/v1/audit", "/v1/application-role-bindings", "/v1/service-accounts"} {
		code, _ := machineRequest(server.Handler(), "GET", path, nil, headers)
		if code != 403 && code != 404 {
			t.Fatalf("IDOR %s: %d", path, code)
		}
	}
	code, _ = machineRequest(server.Handler(), "POST", "/v1/applications", map[string]any{"application": app}, headers)
	if code != 403 {
		t.Fatal("scoped application write")
	}
	if err := st.DeleteApplicationBinding(ctx, binding.ID, adminAudit); err != nil {
		t.Fatal(err)
	}
	code, _ = machineRequest(server.Handler(), "GET", "/v1/applications/app-a", nil, headers)
	if code != 404 {
		t.Fatalf("revoked binding retained access: %d", code)
	}
}

type applicationTokens struct{}

func (applicationTokens) Authenticate(_ context.Context, raw string) (*auth.Principal, error) {
	return &auth.Principal{Subject: "local:" + raw, Name: raw, Roles: []auth.Role{auth.RoleAdmin}}, nil
}
