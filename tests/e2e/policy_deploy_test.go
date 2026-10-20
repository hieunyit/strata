package e2e

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"github.com/strata/strata/agent/pkg/bundlefmt"
	"github.com/strata/strata/control-plane/admin"
	"github.com/strata/strata/control-plane/api"
	"github.com/strata/strata/control-plane/auth"
	"github.com/strata/strata/control-plane/auth/authtest"
	"github.com/strata/strata/control-plane/db"
	"github.com/strata/strata/control-plane/ingest"
	"github.com/strata/strata/control-plane/policy"
	"github.com/strata/strata/control-plane/store"
)

// The lab's MinIO image, pinned by digest.
const minioImage = "cgr.dev/chainguard/minio@sha256:7df55d002b698e4494a131b848dd553361bbe58b7e19f62d9623c29af1ba9ccf"

func startMinIO(t *testing.T) (endpoint string, client *minio.Client) {
	t.Helper()
	name := fmt.Sprintf("strata-e2e-minio-%d", time.Now().UnixNano()%1000000)
	out, err := exec.Command("docker", "run", "-d", "--rm", "--name", name,
		"-e", "MINIO_ROOT_USER=strata", "-e", "MINIO_ROOT_PASSWORD=strata-e2e-secret",
		"-p", "127.0.0.1::9000", minioImage, "server", "/data").CombinedOutput()
	if err != nil {
		t.Fatalf("start minio: %v: %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "stop", "-t", "2", name).Run() })
	port, err := exec.Command("docker", "port", name, "9000/tcp").Output()
	if err != nil {
		t.Fatal(err)
	}
	endpoint = strings.TrimSpace(strings.Split(string(port), "\n")[0])
	client, err = minio.New(endpoint, &minio.Options{Creds: credentials.NewStaticV4("strata", "strata-e2e-secret", "")})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(60 * time.Second)
	for {
		err := client.MakeBucket(context.Background(), "strata-bundles", minio.MakeBucketOptions{})
		if err == nil {
			return endpoint, client
		}
		if time.Now().After(deadline) {
			t.Fatalf("minio not ready: %v", err)
		}
		time.Sleep(300 * time.Millisecond)
	}
}

func buildFakeCompiler(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "fakecompile")
	if out, err := exec.Command("go", "build", "-o", bin, "./fakecompile").CombinedOutput(); err != nil {
		t.Fatalf("build fakecompile: %v: %s", err, out)
	}
	return bin
}

// W04-G2-01: an edit with a stale etag gets 409; every edit is a new
// version; a deploy puts the signed bundle and its sha256 in MinIO.
func TestPolicyEditAndDeploy(t *testing.T) {
	ctx := context.Background()
	pool := startPostgres(t)
	latest, _ := db.Latest()
	if err := db.Migrate(ctx, pool, latest); err != nil {
		t.Fatal(err)
	}
	st := store.New(pool)
	endpoint, mc := startMinIO(t)
	objects, err := policy.NewS3(ctx, policy.S3Config{Endpoint: endpoint, Bucket: "strata-bundles", AccessKey: "strata", SecretKey: "strata-e2e-secret"})
	if err != nil {
		t.Fatal(err)
	}
	seed := make([]byte, ed25519.SeedSize)
	copy(seed, "e2e-bundle-signing-seed-32-bytes")
	keyFile := filepath.Join(t.TempDir(), "bundle.key")
	if err := os.WriteFile(keyFile, seed, 0o600); err != nil {
		t.Fatal(err)
	}
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)

	is := authtest.New(t)
	v, err := auth.NewVerifier(ctx, auth.Config{Issuer: is.URL, Audience: authtest.Audience})
	if err != nil {
		t.Fatal(err)
	}
	adm, err := admin.New(ctx, v, admin.BuildInfo{Version: "e2e"}, admin.Deps{
		Policies: st,
		Deployer: &policy.Deployer{Store: st, Objects: objects, PubKey: pub,
			Builder: &policy.Compiler{Binary: buildFakeCompiler(t), KeyFile: keyFile}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(adm.Close)
	e := &fleetEnv{issuer: is, rest: api.NewServer(api.ServerConfig{Auth: v, Admin: adm.Gateway}, ingest.NewMockEventStore()).Handler()}

	type pol struct {
		Policy struct {
			Version uint32 `json:"version"`
			Etag    string `json:"etag"`
			Spec    struct {
				Mode string `json:"mode"`
			} `json:"spec"`
		} `json:"policy"`
	}
	create := `{"id":"example-api","name":"example-api","spec":{"mode":"MODE_SHADOW"}}`
	if c := e.call(t, "viewer", http.MethodPost, "/v1/policies", create, nil); c != http.StatusForbidden {
		t.Fatalf("viewer creates: %d", c)
	}
	var p1 pol
	if c := e.call(t, "operator", http.MethodPost, "/v1/policies", create, &p1); c != http.StatusOK || p1.Policy.Version != 1 || p1.Policy.Etag == "" {
		t.Fatalf("create: %d %+v", c, p1)
	}
	if c := e.call(t, "operator", http.MethodPost, "/v1/policies", create, nil); c != http.StatusConflict {
		t.Fatalf("create twice: %d", c)
	}
	if c := e.call(t, "operator", http.MethodPost, "/v1/policies", `{"id":"x","name":"x","spec":{"mode":"MODE_UNSPECIFIED"}}`, nil); c != http.StatusBadRequest {
		t.Fatalf("spec without a mode: %d", c)
	}
	// CP-SEC-02: names go into object keys and paths
	if c := e.call(t, "operator", http.MethodPost, "/v1/policies", `{"id":"dots","name":"..","spec":{"mode":"MODE_SHADOW"}}`, nil); c != http.StatusBadRequest {
		t.Fatalf("policy named ..: %d", c)
	}

	patch := func(etag, mode string) (int, pol) {
		var out pol
		c := e.call(t, "operator", http.MethodPatch, "/v1/policies/example-api",
			fmt.Sprintf(`{"etag":%q,"spec":{"mode":%q,"oversize":"OVERSIZE_BLOCK"}}`, etag, mode), &out)
		return c, out
	}
	c, p2 := patch(p1.Policy.Etag, "MODE_ENFORCE")
	if c != http.StatusOK || p2.Policy.Version != 2 || p2.Policy.Spec.Mode != "MODE_ENFORCE" || p2.Policy.Etag == p1.Policy.Etag {
		t.Fatalf("update: %d %+v", c, p2)
	}
	if c, _ := patch(p1.Policy.Etag, "MODE_SHADOW"); c != http.StatusConflict {
		t.Fatalf("update with a stale etag: %d, want 409", c)
	}
	if c, _ := patch("", "MODE_SHADOW"); c != http.StatusBadRequest {
		t.Fatalf("update without an etag: %d", c)
	}
	c, p3 := patch(p2.Policy.Etag, "MODE_SHADOW")
	if c != http.StatusOK || p3.Policy.Version != 3 {
		t.Fatalf("second update: %d %+v", c, p3)
	}
	var versions struct {
		Versions []struct {
			Version uint32 `json:"version"`
			Spec    struct {
				Mode string `json:"mode"`
			} `json:"spec"`
		} `json:"versions"`
	}
	if c := e.call(t, "viewer", http.MethodGet, "/v1/policies/example-api/versions", "", &versions); c != http.StatusOK || len(versions.Versions) != 3 {
		t.Fatalf("versions: %d %+v", c, versions)
	}
	if versions.Versions[0].Version != 3 || versions.Versions[1].Spec.Mode != "MODE_ENFORCE" || versions.Versions[2].Spec.Mode != "MODE_SHADOW" {
		t.Fatalf("version history: %+v", versions.Versions)
	}

	// Deploy: approver and viewer may not; an operator may.
	for _, role := range []string{"viewer", "approver"} {
		if c := e.call(t, role, http.MethodPost, "/v1/policies/example-api:deploy", `{}`, nil); c != http.StatusForbidden {
			t.Fatalf("%s deploys: %d", role, c)
		}
	}
	type dep struct {
		Bundle struct {
			Version   string            `json:"version"`
			Sha256    string            `json:"sha256"`
			ObjectKey string            `json:"object_key"`
			Contents  map[string]uint32 `json:"contents"`
		} `json:"bundle"`
	}
	// four eyes (W13-G2-02): not before version 3 is approved
	if c := e.call(t, "operator", http.MethodPost, "/v1/policies/example-api:deploy", `{}`, nil); c != http.StatusBadRequest {
		t.Fatalf("deploy of a draft: %d", c)
	}
	approve(t, e.call, "example-api")
	for want := 1; want <= 2; want++ {
		var d dep
		if c := e.call(t, "operator", http.MethodPost, "/v1/policies/example-api:deploy", `{}`, &d); c != http.StatusOK {
			t.Fatalf("deploy: %d", c)
		}
		if d.Bundle.Version != fmt.Sprint(want) || d.Bundle.Contents["example-api"] != 3 {
			t.Fatalf("deploy %d: %+v", want, d.Bundle)
		}
		obj, err := mc.GetObject(ctx, "strata-bundles", d.Bundle.ObjectKey, minio.GetObjectOptions{})
		if err != nil {
			t.Fatal(err)
		}
		info, err := obj.Stat()
		if err != nil {
			t.Fatalf("bundle %s not in MinIO: %v", d.Bundle.ObjectKey, err)
		}
		data := make([]byte, info.Size)
		if _, err := obj.Read(data); err != nil && err.Error() != "EOF" {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != d.Bundle.Sha256 || info.UserMetadata["Sha256"] != d.Bundle.Sha256 {
			t.Fatalf("sha256: object %x, API %s, metadata %q", sum, d.Bundle.Sha256, info.UserMetadata["Sha256"])
		}
		h, err := bundlefmt.Verify(data, pub)
		if err != nil || h.Version != uint64(want) {
			t.Fatalf("stored bundle: %+v %v", h, err)
		}
	}
	latestB, err := st.LatestBundle(ctx)
	if err != nil || latestB.Version != 2 {
		t.Fatalf("bundles table: %+v %v", latestB, err)
	}
	entries, _ := st.AuditEntries(ctx, 20)
	var actions []string
	for _, a := range entries {
		actions = append(actions, a.Action)
	}
	for _, want := range []string{"CreatePolicy", "UpdatePolicy", "SubmitPolicy", "ApprovePolicy", "DeployPolicy"} {
		if !strings.Contains(strings.Join(actions, " "), want) {
			t.Errorf("audit lacks %s: %v", want, actions)
		}
	}
}

type caller func(t *testing.T, role, method, path, body string, out any) int

// approve submits the newest version of a policy as an operator and
// approves it as an approver (four eyes, W13-G2-02).
func approve(t *testing.T, call caller, id string) {
	t.Helper()
	var sub struct {
		Version struct {
			Version uint32 `json:"version"`
			State   string `json:"state"`
		} `json:"version"`
	}
	if c := call(t, "operator", http.MethodPost, "/v1/policies/"+id+":submit", `{}`, &sub); c != http.StatusOK || sub.Version.State != "SUBMITTED" {
		t.Fatalf("submit %s: %d %+v", id, c, sub)
	}
	var ap struct {
		Version struct {
			State string `json:"state"`
		} `json:"version"`
	}
	if c := call(t, "approver", http.MethodPost, "/v1/policies/"+id+":approve",
		fmt.Sprintf(`{"version":%d,"comment":"looks right"}`, sub.Version.Version), &ap); c != http.StatusOK || ap.Version.State != "APPROVED" {
		t.Fatalf("approve %s: %d %+v", id, c, ap)
	}
}
