package auth_test

import (
	"github.com/strata/strata/control-plane/auth"
	admin "github.com/strata/strata/control-plane/gen/strata/admin/v1"
	"testing"
)

func TestScopedRPCMatrix(t *testing.T) {
	for _, role := range auth.Roles {
		t.Run(string(role), func(t *testing.T) {
			p := &auth.Principal{Roles: []auth.Role{role}, Access: &auth.Access{Resources: map[string]map[auth.Permission]bool{"policies/a": {auth.PermPoliciesRead: true, auth.PermPoliciesWrite: true, auth.PermPoliciesApprove: true, auth.PermPoliciesDeploy: true}}, Events: []auth.EventScope{{Sensitive: false}}}}
			for _, id := range []string{"a", "b"} {
				req := &admin.GetPolicyRequest{PolicyId: id}
				if got := p.ScopedRPC("/strata.admin.v1.PolicyService/GetPolicy", req, auth.PermPoliciesRead); got != (id == "a") {
					t.Fatalf("Get %s: %v", id, got)
				}
				if got := p.ScopedRPC("/strata.admin.v1.PolicyService/ApprovePolicy", req, auth.PermPoliciesApprove); got != (id == "a" && role.Allows(auth.PermPoliciesApprove)) {
					t.Fatalf("Approve %s: %v", id, got)
				}
			}
			if p.ScopedRPC("/unknown/CreateSomething", &admin.GetPolicyRequest{}, auth.PermPoliciesWrite) || p.Can(auth.PermApplicationsWrite) || p.Can(auth.PermEventsReadSensitive) {
				t.Fatal("global or sensitive permission escaped")
			}
			original := &admin.ListPoliciesResponse{Policies: []*admin.Policy{{Id: "a"}, {Id: "b"}}}
			filtered := p.FilterRPC("/strata.admin.v1.PolicyService/ListPolicies", original).(*admin.ListPoliciesResponse)
			if len(filtered.Policies) != 1 || filtered.Policies[0].Id != "a" || len(original.Policies) != 2 {
				t.Fatal("unsafe list filtering")
			}
		})
	}
}
