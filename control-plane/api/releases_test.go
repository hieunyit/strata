package api

import (
	"context"
	"testing"

	"github.com/strata/strata/control-plane/auth"
	"github.com/strata/strata/control-plane/ingest"
	"github.com/strata/strata/control-plane/localauth/localauthtest"
	"github.com/strata/strata/control-plane/policy"
	"github.com/strata/strata/control-plane/store"
)

func TestReleaseAPIAuthorizationAndFourEyes(t *testing.T) {
	pool := localauthtest.Pool(t)
	st := store.New(pool)
	ctx := t.Context()
	creator := store.Audit{Actor: "operator", Subject: "operator", Action: "test"}
	snapshot := store.ReleaseSnapshot{Bundle: store.Bundle{SHA256: make([]byte, 32)}, ReplayIDs: map[string]string{}}
	release, err := st.CreateRelease(ctx, "example-release", "create", "", func() (store.ReleaseSnapshot, error) { return snapshot, nil }, creator)
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(ServerConfig{Auth: tokenRoles{}, Releases: &policy.Releases{Store: st}}, ingest.NewMockEventStore())
	action := map[string]any{"etag": release.Etag, "snapshot_hash": release.SnapshotHash, "replay_ids": map[string]string{}}
	code, _ := machineRequest(server.Handler(), "POST", "/v1/releases/example-release:approve", action, map[string]string{"Authorization": "Bearer operator"})
	if code != 403 {
		t.Fatalf("operator approved release: %d", code)
	}
	// The creator can have admin rights later; identity still prevents self-review.
	if _, err := pool.Exec(ctx, "UPDATE releases SET created_subject=$2 WHERE id=$1", release.ID, "user-admin"); err != nil {
		t.Fatal(err)
	}
	code, _ = machineRequest(server.Handler(), "POST", "/v1/releases/example-release:approve", action, nil)
	if code != 403 {
		t.Fatalf("self-approved release: %d", code)
	}
	code, _ = machineRequest(server.Handler(), "POST", "/v1/releases/example-release:approve", action, map[string]string{"Authorization": "Bearer approver"})
	if code != 200 {
		t.Fatalf("independent approval: %d", code)
	}
	scoped := NewServer(ServerConfig{Auth: restrictedReleaseAuth{}, Releases: &policy.Releases{Store: st}}, ingest.NewMockEventStore())
	for _, path := range []string{"/v1/releases", "/v1/releases/example-release"} {
		code, _ = machineRequest(scoped.Handler(), "GET", path, nil, nil)
		if code != 403 {
			t.Fatalf("global snapshot disclosed: %d", code)
		}
	}
	code, _ = machineRequest(server.Handler(), "POST", "/v1/releases", map[string]string{"request_id": ""}, nil)
	if code != 400 {
		t.Fatal("unbounded/empty release request accepted")
	}
}

type restrictedReleaseAuth struct{}

func (restrictedReleaseAuth) Authenticate(context.Context, string) (*auth.Principal, error) {
	return &auth.Principal{Subject: "local:scoped", Roles: []auth.Role{auth.RoleAdmin}, Access: &auth.Access{}}, nil
}
