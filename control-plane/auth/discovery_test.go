package auth

import "testing"

func TestDiscoveryIngestPermissionCeiling(t *testing.T) {
	for _, role := range []Role{RoleViewer, RoleOperator, RoleApprover} {
		if role.Allows(PermDiscoveryIngest) {
			t.Fatalf("%s can ingest discovery", role)
		}
	}
	if !RoleAdmin.Allows(PermDiscoveryIngest) {
		t.Fatal("admin permission missing")
	}
	for _, scopes := range [][]Permission{{}, {PermEventsRead}} {
		if (&Principal{Roles: []Role{RoleAdmin}, Scopes: scopes}).Can(PermDiscoveryIngest) {
			t.Fatal("scope ceiling ignored")
		}
	}
	if !(&Principal{Roles: []Role{RoleAdmin}, Scopes: []Permission{PermDiscoveryIngest}}).Can(PermDiscoveryIngest) {
		t.Fatal("explicit ceiling refused")
	}
}
