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
	"github.com/strata/strata/control-plane/policy"
	"github.com/strata/strata/control-plane/store"
)

type onePolicy struct{ admin.PolicyStore }

func (onePolicy) GetPolicy(context.Context, string) (store.Policy, error) {
	return store.Policy{ID: "example-api", Name: "example-api"}, nil
}

type costlyDeployer struct{}

func (costlyDeployer) Deploy(context.Context, store.Audit) (policy.Deployment, error) {
	return policy.Deployment{}, &policy.CostError{Total: 60000, Budget: 50000, Top: []policy.RuleCost{
		{ID: 942100, Name: "SQL Injection Attack Detected via libinjection", Cost: 2081},
		{ID: 941100, Name: "XSS Attack Detected via libinjection", Cost: 1751},
		{ID: 932230, Name: "Remote Command Execution", Cost: 626},
	}}
}

// W07-G2-01: a policy over the cost budget is refused with 400 and the
// three costliest rules.
func TestDeployOverCostBudgetIs400(t *testing.T) {
	ctx := context.Background()
	is := authtest.New(t)
	v, err := auth.NewVerifier(ctx, auth.Config{Issuer: is.URL, Audience: authtest.Audience})
	if err != nil {
		t.Fatal(err)
	}
	a, err := admin.New(ctx, v, admin.BuildInfo{}, admin.Deps{Policies: onePolicy{}, Deployer: costlyDeployer{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	h := api.NewServer(api.ServerConfig{Auth: v, Admin: a.Gateway}, ingest.NewMockEventStore()).Handler()
	req := httptest.NewRequest(http.MethodPost, "/v1/policies/example-api:deploy", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+is.Token(t, authtest.Claims{Subject: "lab-operator", Roles: []string{"operator"}}))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	for _, want := range []string{"60000", "50000", "SQL Injection Attack Detected via libinjection", "XSS Attack Detected via libinjection", "Remote Command Execution"} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("body lacks %q: %s", want, rec.Body.String())
		}
	}
}
