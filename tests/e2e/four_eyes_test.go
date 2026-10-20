package e2e

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/strata/strata/control-plane/admin"
	"github.com/strata/strata/control-plane/api"
	"github.com/strata/strata/control-plane/auth"
	"github.com/strata/strata/control-plane/auth/authtest"
	"github.com/strata/strata/control-plane/db"
	"github.com/strata/strata/control-plane/ingest"
	"github.com/strata/strata/control-plane/policy"
	"github.com/strata/strata/control-plane/store"
)

// W13-G2-02 "Xong khi": whoever drafted a version cannot approve it; a
// deploy before the approval is refused. Also: the review queue, reject
// with a reason, and a deploy takes each policy's newest approved version
// (a draft of another policy stays out of the bundle).
func TestFourEyes(t *testing.T) {
	ctx := context.Background()
	pool := startPostgres(t)
	latest, _ := db.Latest()
	if err := db.Migrate(ctx, pool, latest); err != nil {
		t.Fatal(err)
	}
	st := store.New(pool)
	objects, err := artifactStore(ctx, t)
	if err != nil {
		t.Fatal(err)
	}
	seed := make([]byte, ed25519.SeedSize)
	copy(seed, "e2e-bundle-signing-seed-32-bytes")
	keyFile := filepath.Join(t.TempDir(), "bundle.key")
	if err := os.WriteFile(keyFile, seed, 0o600); err != nil {
		t.Fatal(err)
	}
	is := authtest.New(t)
	v, err := auth.NewVerifier(ctx, auth.Config{Issuer: is.URL, Audience: authtest.Audience})
	if err != nil {
		t.Fatal(err)
	}
	adm, err := admin.New(ctx, v, admin.BuildInfo{Version: "e2e"}, admin.Deps{
		Policies: st,
		Deployer: &policy.Deployer{Store: st, Objects: objects, PubKey: ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey),
			Builder: &policy.Compiler{Binary: buildFakeCompiler(t), KeyFile: keyFile}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(adm.Close)
	e := &fleetEnv{issuer: is, rest: api.NewServer(api.ServerConfig{Auth: v, Admin: adm.Gateway}, ingest.NewMockEventStore()).Handler()}

	type version struct {
		PolicyID        string `json:"policy_id"`
		Version         uint32 `json:"version"`
		State           string `json:"state"`
		SubmittedBy     string `json:"submitted_by"`
		DecidedBy       string `json:"decided_by"`
		DecisionComment string `json:"decision_comment"`
	}
	type verOut struct {
		Version version `json:"version"`
	}
	post := func(role, path, body string, want int) verOut {
		t.Helper()
		var out verOut
		if c := e.call(t, role, http.MethodPost, path, body, &out); c != want {
			t.Fatalf("%s %s %s: %d, want %d", role, path, body, c, want)
		}
		return out
	}
	type polOut struct {
		Policy struct {
			Version         uint32 `json:"version"`
			Etag            string `json:"etag"`
			ApprovedVersion uint32 `json:"approved_version"`
			DeployedVersion uint32 `json:"deployed_version"`
		} `json:"policy"`
	}
	get := func(id string) polOut {
		t.Helper()
		var p polOut
		if c := e.call(t, "viewer", http.MethodGet, "/v1/policies/"+id, "", &p); c != http.StatusOK {
			t.Fatalf("get %s: %d", id, c)
		}
		return p
	}

	// the admin drafts and submits example-api: it may approve policies, but
	// not this one
	if c := e.call(t, "admin", http.MethodPost, "/v1/policies", `{"id":"example-api","name":"example-api","spec":{"mode":"MODE_SHADOW"}}`, nil); c != http.StatusOK {
		t.Fatalf("create: %d", c)
	}
	post("admin", "/v1/policies/example-api:deploy", `{}`, http.StatusBadRequest)
	if got := post("admin", "/v1/policies/example-api:submit", `{}`, http.StatusOK).Version; got.State != "SUBMITTED" || !strings.Contains(got.SubmittedBy, "lab-admin") {
		t.Fatalf("submit: %+v", got)
	}
	post("admin", "/v1/policies/example-api:submit", `{}`, http.StatusBadRequest) // not a draft any more
	post("admin", "/v1/policies/example-api:approve", `{"version":1}`, http.StatusForbidden)
	post("operator", "/v1/policies/example-api:approve", `{"version":1}`, http.StatusForbidden) // no policies:approve
	post("approver", "/v1/policies/example-api:approve", `{}`, http.StatusBadRequest)           // which version?
	post("approver", "/v1/policies/example-api:approve", `{"version":9}`, http.StatusNotFound)
	post("admin", "/v1/policies/example-api:deploy", `{}`, http.StatusBadRequest)

	// the review queue
	var queue struct {
		Versions []version `json:"versions"`
	}
	if c := e.call(t, "viewer", http.MethodGet, "/v1/policies/-/versions?state=SUBMITTED", "", &queue); c != http.StatusOK ||
		len(queue.Versions) != 1 || queue.Versions[0].PolicyID != "example-api" {
		t.Fatalf("queue: %d %+v", c, queue)
	}
	if c := e.call(t, "viewer", http.MethodGet, "/v1/policies/-/versions", "", nil); c != http.StatusBadRequest {
		t.Fatalf("every policy without a state: %d", c)
	}

	if got := post("approver", "/v1/policies/example-api:approve", `{"version":1,"comment":"replay clean"}`, http.StatusOK).Version; got.State != "APPROVED" ||
		!strings.Contains(got.DecidedBy, "lab-approver") || got.DecisionComment != "replay clean" {
		t.Fatalf("approve: %+v", got)
	}
	if p := get("example-api"); p.Policy.ApprovedVersion != 1 || p.Policy.DeployedVersion != 0 {
		t.Fatalf("after approval: %+v", p)
	}

	// another policy, still a draft: a deploy of example-api leaves it out
	if c := e.call(t, "operator", http.MethodPost, "/v1/policies", `{"id":"example-web","name":"example-web","spec":{"mode":"MODE_SHADOW"}}`, nil); c != http.StatusOK {
		t.Fatalf("create web: %d", c)
	}
	type dep struct {
		Bundle struct {
			Contents map[string]uint32 `json:"contents"`
		} `json:"bundle"`
	}
	var d dep
	if c := e.call(t, "operator", http.MethodPost, "/v1/policies/example-api:deploy", `{}`, &d); c != http.StatusOK ||
		fmt.Sprint(d.Bundle.Contents) != "map[example-api:1]" {
		t.Fatalf("deploy: %d %+v", c, d)
	}
	if p := get("example-api"); p.Policy.DeployedVersion != 1 {
		t.Fatalf("deployed: %+v", p)
	}
	post("operator", "/v1/policies/example-web:deploy", `{}`, http.StatusBadRequest)

	// example-api version 2 drafted: deploys of it wait; rejected with a
	// reason, then a version 3 approved replaces it
	p := get("example-api")
	if c := e.call(t, "operator", http.MethodPatch, "/v1/policies/example-api",
		fmt.Sprintf(`{"etag":%q,"spec":{"mode":"MODE_ENFORCE"}}`, p.Policy.Etag), nil); c != http.StatusOK {
		t.Fatalf("edit: %d", c)
	}
	post("operator", "/v1/policies/example-api:deploy", `{}`, http.StatusBadRequest)
	post("operator", "/v1/policies/example-api:submit", `{}`, http.StatusOK)
	post("approver", "/v1/policies/example-api:reject", `{"version":2}`, http.StatusBadRequest) // a reason is required
	if got := post("approver", "/v1/policies/example-api:reject", `{"version":2,"comment":"replay: 40 new blocks on /v1/login"}`, http.StatusOK).Version; got.State != "REJECTED" {
		t.Fatalf("reject: %+v", got)
	}
	p = get("example-api")
	if c := e.call(t, "operator", http.MethodPatch, "/v1/policies/example-api",
		fmt.Sprintf(`{"etag":%q,"spec":{"mode":"MODE_ENFORCE","oversize":"OVERSIZE_PASS"}}`, p.Policy.Etag), nil); c != http.StatusOK {
		t.Fatalf("edit 3: %d", c)
	}
	approve(t, e.call, "example-api")
	post("approver", "/v1/policies/example-api:approve", `{"version":2}`, http.StatusBadRequest) // REJECTED
	if c := e.call(t, "operator", http.MethodPost, "/v1/policies/example-api:deploy", `{}`, &d); c != http.StatusOK ||
		fmt.Sprint(d.Bundle.Contents) != "map[example-api:3]" {
		t.Fatalf("deploy 3: %d %+v", c, d)
	}
	var vs struct {
		Versions []version `json:"versions"`
	}
	if c := e.call(t, "viewer", http.MethodGet, "/v1/policies/example-api/versions", "", &vs); c != http.StatusOK {
		t.Fatalf("versions: %d", c)
	}
	var states []string
	for _, x := range vs.Versions {
		states = append(states, fmt.Sprintf("%d:%s", x.Version, x.State))
	}
	if strings.Join(states, " ") != "3:DEPLOYED 2:REJECTED 1:DEPLOYED" {
		t.Fatalf("states: %v", states)
	}
}
