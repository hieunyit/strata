package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/strata/strata/control-plane/apidiscovery"
	"github.com/strata/strata/control-plane/auth"
	"github.com/strata/strata/control-plane/store"
	"strings"
	"testing"
	"time"
)

type discoveryTestAuth struct{ base auth.Authenticator }

func (a discoveryTestAuth) Authenticate(ctx context.Context, raw string) (*auth.Principal, error) {
	if raw == "collector" || raw == "untrusted" {
		return &auth.Principal{Subject: "sa:" + raw, Name: "collector", Roles: []auth.Role{auth.RoleAdmin}, Scopes: []auth.Permission{auth.PermDiscoveryIngest, auth.PermApplicationsRead, auth.PermPoliciesRead}}, nil
	}
	if raw == "admin-session" {
		return &auth.Principal{Subject: "oidc:admin", Roles: []auth.Role{auth.RoleAdmin}}, nil
	}
	return a.base.Authenticate(ctx, raw)
}
func TestDiscoveryGateScopedWorkflowAndNoAutomaticEnforcement(t *testing.T) {
	previous, st, pool, events, _ := investigationFixture(t)
	now := time.Now().UTC()
	gate := apidiscovery.Gate{Enabled: true, ApprovalReference: "synthetic-approval-only", ApprovalExpires: now.Add(time.Hour), TrustedCollectors: map[string]bool{"sa:collector": true}, Key: bytes.Repeat([]byte{8}, 32)}
	s := NewServer(ServerConfig{Auth: discoveryTestAuth{previous.cfg.Auth}, Applications: st, Discovery: gate, ReplayKick: func() {}}, events)
	base := "?application_id=example-api&environment_id=test"
	initial := investigationRequest(t, s, "viewer", "GET", "/v1/discovery"+base, nil, 200)
	var empty struct {
		Endpoints []store.DiscoveredEndpoint `json:"endpoints"`
	}
	if err := json.Unmarshal(initial.Body.Bytes(), &empty); err != nil || len(empty.Endpoints) != 0 {
		t.Fatal("security events used as discovery traffic", err)
	}
	observations := []apidiscovery.Observation{}
	for i := range 20 {
		observations = append(observations, apidiscovery.Observation{ID: fmt.Sprintf("00000000-0000-0000-0000-%012d", i+1), RouteID: "api", Method: "POST", Path: "/api/users/alice@example.test?token=secret", ContentType: "application/json", BodyBytes: 123, BackendStatus: 201, BackendResponse: true, SourceIP: fmt.Sprintf("198.51.100.%d", i%3+1), At: now.Add(time.Duration(i-20) * time.Minute)})
	}
	req := discoveryObservationRequest{ApplicationID: "example-api", EnvironmentID: "test", RequestID: "batch", Observations: observations}
	investigationRequest(t, s, "operator", "POST", "/v1/discovery/observations", req, 403)
	investigationRequest(t, s, "admin-session", "POST", "/v1/discovery/observations", req, 403)
	investigationRequest(t, s, "untrusted", "POST", "/v1/discovery/observations", req, 403)
	s.cfg.Discovery.Enabled = false
	investigationRequest(t, s, "collector", "POST", "/v1/discovery/observations", req, 503)
	s.cfg.Discovery.Enabled = true
	s.cfg.Discovery.ApprovalExpires = now.Add(-time.Second)
	investigationRequest(t, s, "collector", "POST", "/v1/discovery/observations", req, 503)
	s.cfg.Discovery.ApprovalExpires = gate.ApprovalExpires
	bad := req
	bad.Observations = []apidiscovery.Observation{observations[0]}
	bad.Observations[0].BackendStatus = 403
	investigationRequest(t, s, "collector", "POST", "/v1/discovery/observations", bad, 400)
	bad.Observations[0].BackendStatus = 200
	bad.Observations[0].RouteID = "private"
	investigationRequest(t, s, "collector", "POST", "/v1/discovery/observations", bad, 403)
	for range 2 {
		investigationRequest(t, s, "collector", "POST", "/v1/discovery/observations", req, 202)
	}
	docReq := discoveryDocumentRequest{ApplicationID: "example-api", EnvironmentID: "test", Document: `{"openapi":"3.0.3","info":{"title":"Example","version":"1"},"paths":{}}`, RequestID: "document"}
	investigationRequest(t, s, "viewer", "PUT", "/v1/discovery/document", docReq, 403)
	rec := investigationRequest(t, s, "operator", "PUT", "/v1/discovery/document", docReq, 200)
	var doc store.DiscoveryDocument
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	rec = investigationRequest(t, s, "viewer", "GET", "/v1/discovery"+base, nil, 200)
	for _, bad := range []string{"alice@example.test", "token=secret", "198.51.100"} {
		if strings.Contains(rec.Body.String(), bad) {
			t.Fatalf("inventory leaked %s", bad)
		}
	}
	var inventory struct {
		Endpoints []store.DiscoveredEndpoint `json:"endpoints"`
		Runtime   bool                       `json:"runtime_enforcement"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &inventory); err != nil || len(inventory.Endpoints) != 1 || !inventory.Endpoints[0].Eligible || inventory.Runtime {
		t.Fatalf("inventory %+v %v", inventory, err)
	}
	investigationRequest(t, s, "outsider", "GET", "/v1/discovery"+base, nil, 403)
	propose := discoveryProposalRequest{ApplicationID: "example-api", EnvironmentID: "test", EndpointKey: inventory.Endpoints[0].Key, BaseDigest: doc.Digest, RequestID: "propose"}
	investigationRequest(t, s, "viewer", "POST", "/v1/discovery/proposals", propose, 403)
	rec = investigationRequest(t, s, "operator", "POST", "/v1/discovery/proposals", propose, 200)
	var proposal store.DiscoveryProposal
	if err := json.Unmarshal(rec.Body.Bytes(), &proposal); err != nil {
		t.Fatal(err)
	}
	p, err := st.GetPolicy(t.Context(), "policy-api")
	if err != nil {
		t.Fatal(err)
	}
	draft := discoveryDraftRequest{ApplicationID: "example-api", EnvironmentID: "test", ID: proposal.ID, Etag: proposal.Etag, PolicyEtag: p.Etag, RequestID: "draft"}
	for range 2 {
		investigationRequest(t, s, "operator", "POST", "/v1/discovery/proposals:draft", draft, 200)
	}
	download := "/v1/discovery/proposals/" + proposal.ID + base
	rec = investigationRequest(t, s, "viewer", "GET", download, nil, 200)
	if !strings.Contains(rec.Body.String(), "documentation_only") {
		t.Fatal("missing enforcement limit")
	}
	investigationRequest(t, s, "outsider", "GET", download, nil, 403)
	current, err := st.GetPolicy(t.Context(), p.ID)
	if err != nil || current.CurrentVersion != 2 || current.ApprovedVersion != 0 || current.DeployedVersion != 0 {
		t.Fatalf("activation %+v %v", current, err)
	}
	var replay int
	if err = pool.QueryRow(t.Context(), `SELECT count(*) FROM operations WHERE policy_id=$1`, p.ID).Scan(&replay); err != nil || replay != 1 {
		t.Fatal("duplicate replay", err)
	}
	if _, err = st.SubmitPolicyVersion(t.Context(), p.ID, 2, store.Audit{Actor: "operator", Subject: "oidc:operator"}); err != nil {
		t.Fatal(err)
	}
	if _, err = st.DecidePolicyVersion(t.Context(), p.ID, 2, true, "review", store.Audit{Actor: "operator", Subject: "oidc:operator"}); err == nil {
		t.Fatal("self approval accepted")
	}
}
