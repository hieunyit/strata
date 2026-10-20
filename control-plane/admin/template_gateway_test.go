package admin_test

import (
	"context"
	"encoding/json"
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

type creatingStore struct {
	admin.PolicyStore
	created store.Policy
}

func (c *creatingStore) CreatePolicy(_ context.Context, p store.Policy, _ store.Audit) (store.Policy, error) {
	c.created = p
	p.CurrentVersion = 1
	return p, nil
}

// W20-S-01: POST /v1/policies?template=api through the REST gateway, and
// GET /v1/policyTemplates.
func TestCreatePolicyFromTemplateOverREST(t *testing.T) {
	ctx := context.Background()
	is := authtest.New(t)
	v, err := auth.NewVerifier(ctx, auth.Config{Issuer: is.URL, Audience: authtest.Audience})
	if err != nil {
		t.Fatal(err)
	}
	ps := &creatingStore{}
	a, err := admin.New(ctx, v, admin.BuildInfo{}, admin.Deps{Policies: ps})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	h := api.NewServer(api.ServerConfig{Auth: v, Admin: a.Gateway}, ingest.NewMockEventStore()).Handler()
	call := func(method, path, body string, roles ...string) (int, string) {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+is.Token(t, authtest.Claims{Subject: "lab-operator", Roles: roles}))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}
	if c, body := call(http.MethodGet, "/v1/policyTemplates", "", "viewer"); c != http.StatusOK || !strings.Contains(body, `"name":"api"`) {
		t.Fatalf("list templates: %d %s", c, body)
	}
	c, body := call(http.MethodPost, "/v1/policies?template=api", `{"id":"example-api","name":"example-api","spec":{"mode":"MODE_ENFORCE"}}`, "operator")
	if c != http.StatusOK {
		t.Fatalf("create: %d %s", c, body)
	}
	var spec map[string]any
	_ = json.Unmarshal(ps.created.Spec, &spec)
	if spec["mode"] != "enforce" || spec["oversize"] != "block" || spec["template"] == nil {
		t.Errorf("stored spec %s", ps.created.Spec)
	}
	if c, body := call(http.MethodPost, "/v1/policies?template=nope", `{"id":"example-x","name":"example-x"}`, "operator"); c != http.StatusBadRequest || !strings.Contains(body, "template") {
		t.Errorf("unknown template: %d %s", c, body)
	}
	if c, _ := call(http.MethodPost, "/v1/policies?template=api", `{"id":"example-y","name":"example-y"}`, "viewer"); c != http.StatusForbidden {
		t.Errorf("viewer created a policy: %d", c)
	}
}
