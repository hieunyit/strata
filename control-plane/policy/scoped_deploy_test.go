package policy

import (
	"context"
	"errors"
	"github.com/strata/strata/control-plane/auth"
	"github.com/strata/strata/control-plane/store"
	"testing"
)

type scopedDeployStore struct{ fakeStore }

func (*scopedDeployStore) LatestBundle(context.Context) (store.Bundle, error) {
	return store.Bundle{Version: 1, Contents: map[string]int{"own": 1, "other": 1}}, nil
}
func TestScopedDeployCannotPublishAnotherApplicationsChange(t *testing.T) {
	st := &scopedDeployStore{fakeStore: fakeStore{policies: []store.Policy{{ID: "own", Name: "own", CurrentVersion: 2, Spec: []byte(`{"mode":"shadow"}`)}, {ID: "other", Name: "other", CurrentVersion: 2, Spec: []byte(`{"mode":"shadow"}`)}}}}
	p := &auth.Principal{Roles: []auth.Role{auth.RoleOperator}, Access: &auth.Access{Resources: map[string]map[auth.Permission]bool{"policies/own": {auth.PermPoliciesDeploy: true}}}}
	d := Deployer{Store: st}
	_, err := d.Deploy(auth.WithPrincipal(t.Context(), p), store.Audit{})
	if !errors.Is(err, auth.ErrScopeDenied) {
		t.Fatalf("unrelated changed policy escaped: %v", err)
	}
	if len(st.bundles) != 0 {
		t.Fatal("unauthorized bundle recorded")
	}
}
