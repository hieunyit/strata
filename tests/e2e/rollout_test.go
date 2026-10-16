package e2e

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/strata/strata/agent/pkg/bundlefmt"
	"github.com/strata/strata/control-plane/admin"
	"github.com/strata/strata/control-plane/api"
	"github.com/strata/strata/control-plane/auth"
	"github.com/strata/strata/control-plane/auth/authtest"
	"github.com/strata/strata/control-plane/db"
	"github.com/strata/strata/control-plane/fleet"
	"github.com/strata/strata/control-plane/ingest"
	"github.com/strata/strata/control-plane/policy"
	"github.com/strata/strata/control-plane/store"
)

// pausedBundleObjects pauses a selected object after a bounded prefix. It makes
// kill/restart tests independent of loopback throughput and polling timing.
type pausedBundleObjects struct {
	source  fleet.BundleObjects
	mu      sync.Mutex
	key     string
	after   int64
	release chan struct{}
}

func (p *pausedBundleObjects) pause(key string, after int64) func() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.key, p.after, p.release = key, after, make(chan struct{})
	ch := p.release
	var once sync.Once
	return func() { once.Do(func() { close(ch) }) }
}
func (p *pausedBundleObjects) Open(ctx context.Context, key string, offset int64) (io.ReadCloser, error) {
	r, err := p.source.Open(ctx, key, offset)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if key != p.key || p.release == nil {
		return r, nil
	}
	return &pausedBundleReader{ReadCloser: r, ctx: ctx, left: p.after - offset, release: p.release}, nil
}

type pausedBundleReader struct {
	io.ReadCloser
	ctx     context.Context
	left    int64
	release <-chan struct{}
}

func (r *pausedBundleReader) Read(b []byte) (int, error) {
	if r.left <= 0 {
		select {
		case <-r.release:
			return r.ReadCloser.Read(b)
		case <-r.ctx.Done():
			return 0, r.ctx.Err()
		}
	}
	if int64(len(b)) > r.left {
		b = b[:r.left]
	}
	n, err := r.ReadCloser.Read(b)
	r.left -= int64(n)
	return n, err
}

// platform is a control plane with everything: PostgreSQL, MinIO, fleet
// with enrollment and bundle distribution, rollouts, the admin REST API.
type platform struct {
	*fleetEnv
	pub       ed25519.PublicKey
	downloads *pausedBundleObjects
}

func startPlatform(t *testing.T) *platform {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	pool := startPostgres(t)
	latest, _ := db.Latest()
	if err := db.Migrate(ctx, pool, latest); err != nil {
		t.Fatal(err)
	}
	st := store.New(pool)
	endpoint, _ := startMinIO(t)
	objects, err := policy.NewS3(ctx, policy.S3Config{Endpoint: endpoint, Bucket: "strata-bundles", AccessKey: "strata", SecretKey: "strata-e2e-secret"})
	if err != nil {
		t.Fatal(err)
	}
	seed := make([]byte, ed25519.SeedSize)
	copy(seed, "e2e-rollout-signing-seed-32bytes")
	keyFile := filepath.Join(t.TempDir(), "bundle.key")
	_ = os.WriteFile(keyFile, seed, 0o600)
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)

	dir := t.TempDir()
	caFile, caKey, cert, key := fleetPKI(t, dir)
	ca, err := fleet.LoadCA(caFile, caKey)
	if err != nil {
		t.Fatal(err)
	}
	tlsCfg, err := fleet.ServerTLS(caFile, cert, key)
	if err != nil {
		t.Fatal(err)
	}
	trust, _ := os.ReadFile(caFile)
	presence := fleet.NewPresence()
	rollouts := fleet.NewRollouts(st, presence, fleet.DefaultWaves, 0)
	go rollouts.Run(ctx)
	svc := ingest.NewIngestService(ingest.NewMockEventStore(), ingest.DefaultBatcherConfig(), time.Hour)
	t.Cleanup(func() { _ = svc.Close(context.Background()) })
	downloads := &pausedBundleObjects{source: objects}
	gs := fleet.NewGRPCServer(tlsCfg, fleet.NewServer(fleet.Config{
		Ingest: svc, Registry: st, CA: ca, TrustBundle: trust, BundlePubKey: pub, Presence: presence,
		Objects: downloads, Rollouts: rollouts,
	}))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = gs.Serve(ln) }()
	t.Cleanup(gs.Stop)

	is := authtest.New(t)
	v, err := auth.NewVerifier(ctx, auth.Config{Issuer: is.URL, Audience: authtest.Audience})
	if err != nil {
		t.Fatal(err)
	}
	dep := &policy.Deployer{Store: st, Objects: objects, PubKey: pub,
		Builder: &policy.Compiler{Binary: buildFakeCompiler(t), KeyFile: keyFile}, Publish: rollouts.Start}
	adm, err := admin.New(ctx, v, admin.BuildInfo{Version: "e2e"}, admin.Deps{
		Fleet: st, Presence: presence, Policies: st, Deployer: dep, Rollouts: st, Kicker: rollouts,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(adm.Close)
	rest := api.NewServer(api.ServerConfig{Auth: v, Admin: adm.Gateway}, ingest.NewMockEventStore()).Handler()
	return &platform{fleetEnv: &fleetEnv{st: st, addr: ln.Addr().String(), rest: rest, issuer: is, caFile: caFile, presence: presence}, pub: pub, downloads: downloads}
}

type node struct {
	id, dir, identity, bundles, control string
	proc                                *agentProcess
}

func (p *platform) enrollNodes(t *testing.T, bin string, n int) []*node {
	t.Helper()
	if c := p.call(t, "admin", http.MethodPost, "/v1/groups", `{"id":"lab","name":"Lab"}`, nil); c != http.StatusOK && c != http.StatusConflict {
		t.Fatalf("group: %d", c)
	}
	var nodes []*node
	for i := 0; i < n; i++ {
		var tok struct {
			Token string `json:"token"`
		}
		if c := p.call(t, "admin", http.MethodPost, "/v1/groups/lab/enrollmentTokens", `{}`, &tok); c != http.StatusOK {
			t.Fatalf("token: %d", c)
		}
		d := t.TempDir()
		nd := &node{dir: d, identity: filepath.Join(d, "identity"), bundles: filepath.Join(d, "bundles"), control: filepath.Join(d, "control")}
		tf := filepath.Join(d, "token")
		_ = os.WriteFile(tf, []byte(tok.Token), 0o600)
		if out, err := exec.Command(bin, "enroll", "--server", p.addr, "--server-name", "cp.example.test",
			"--tls-ca", p.caFile, "--token-file", tf, "--identity-dir", nd.identity).CombinedOutput(); err != nil {
			t.Fatalf("enroll: %v: %s", err, out)
		}
		raw, _ := os.ReadFile(filepath.Join(nd.identity, "node-id"))
		nd.id = strings.TrimSpace(string(raw))
		nodes = append(nodes, nd)
		time.Sleep(10 * time.Millisecond) // distinct created_at: the wave order
	}
	return nodes
}

func (nd *node) start(t *testing.T, bin, addr string, extra ...string) {
	t.Helper()
	args := append([]string{"run", "--event-socket", filepath.Join(nd.dir, "events.sock"),
		"--spool-dir", filepath.Join(nd.dir, "spool"), "--server", addr, "--server-name", "cp.example.test",
		"--identity-dir", nd.identity, "--bundle-dir", nd.bundles, "--control-file", nd.control,
		"--metrics-file", filepath.Join(nd.dir, "no-metrics"), "--metrics-addr", ""}, extra...)
	nd.proc = startAgentProcess(t, bin, args...)
	t.Cleanup(func() { _ = nd.proc.stop(5 * time.Second) })
}

// controlVersion reads the version the node's control file names.
func (nd *node) controlVersion() uint64 {
	b, err := os.ReadFile(nd.control)
	if err != nil || len(b) < 32 {
		return 0
	}
	var v uint64
	for i := 7; i >= 0; i-- {
		v = v<<8 | uint64(b[24+i])
	}
	return v
}

type rolloutJSON struct {
	Rollout struct {
		ID          string `json:"id"`
		State       string `json:"state"`
		Reason      string `json:"reason"`
		CurrentWave int    `json:"current_wave"`
		Nodes       []struct {
			NodeID string `json:"node_id"`
			Wave   int    `json:"wave"`
			State  string `json:"state"`
			Error  string `json:"error"`
		} `json:"nodes"`
	} `json:"rollout"`
}

func (p *platform) deploy(t *testing.T, mode string) string {
	t.Helper()
	var pol struct {
		Policy struct {
			Etag string `json:"etag"`
		} `json:"policy"`
	}
	if c := p.call(t, "viewer", http.MethodGet, "/v1/policies/example-api", "", &pol); c == http.StatusNotFound {
		p.call(t, "operator", http.MethodPost, "/v1/policies", `{"id":"example-api","name":"example-api","spec":{"mode":"MODE_SHADOW"}}`, nil)
	} else if c == http.StatusOK {
		p.call(t, "operator", http.MethodPatch, "/v1/policies/example-api", fmt.Sprintf(`{"etag":%q,"spec":{"mode":%q}}`, pol.Policy.Etag, mode), nil)
	}
	approve(t, p.call, "example-api")
	var d struct {
		RolloutID string `json:"rollout_id"`
	}
	if c := p.call(t, "operator", http.MethodPost, "/v1/policies/example-api:deploy", `{}`, &d); c != http.StatusOK || d.RolloutID == "" {
		t.Fatalf("deploy: %d %+v", c, d)
	}
	return d.RolloutID
}

func (p *platform) rollout(t *testing.T, id string) rolloutJSON {
	t.Helper()
	var r rolloutJSON
	if c := p.call(t, "viewer", http.MethodGet, "/v1/rollouts/"+id, "", &r); c != http.StatusOK {
		t.Fatalf("rollout: %d", c)
	}
	return r
}

// W10-N-01: a node enrolled after a deploy gets the bundle the fleet runs
// at once (the bundle of the latest finished rollout), not only after the
// next deploy. Negative: none before any rollout finished, and a rollout
// still running is not handed out.
func TestNewNodeGetsTheFleetBundle(t *testing.T) {
	p := startPlatform(t)
	bin := buildAgentBinary(t)
	first := p.enrollNodes(t, bin, 1)[0]
	first.start(t, bin, p.addr)
	waitFor(t, "first node online", 30*time.Second, func() bool { return p.node(t, first.id).Online })
	time.Sleep(3 * time.Second)
	if v := first.controlVersion(); v != 0 {
		t.Fatalf("bundle %d before any deploy", v)
	}

	r1 := p.deploy(t, "MODE_SHADOW")
	waitFor(t, "rollout 1 done", 60*time.Second, func() bool { return p.rollout(t, r1).Rollout.State == "DONE" })
	late := p.enrollNodes(t, bin, 1)[0]
	start := time.Now()
	late.start(t, bin, p.addr)
	waitFor(t, "the late node runs bundle 1", 30*time.Second, func() bool { return late.controlVersion() == 1 })
	t.Logf("node enrolled after the deploy runs bundle 1 %s after it started", time.Since(start).Round(time.Millisecond))

	// Rollout 2 cannot finish (its first node is stopped): a node enrolled
	// now gets bundle 1, the last finished one, not 2.
	_ = first.proc.stop(5 * time.Second)
	r2 := p.deploy(t, "MODE_ENFORCE")
	if st := p.rollout(t, r2).Rollout.State; st != "RUNNING" {
		t.Fatalf("rollout 2 is %s", st)
	}
	third := p.enrollNodes(t, bin, 1)[0]
	third.start(t, bin, p.addr)
	waitFor(t, "the third node runs bundle 1", 30*time.Second, func() bool { return third.controlVersion() == 1 })
	time.Sleep(3 * time.Second)
	if v := third.controlVersion(); v != 1 {
		t.Fatalf("a node enrolled during rollout 2 runs bundle %d", v)
	}
}

// W05-G1-01 and W05-G2-01 with three real agents: waves in order, a FAILED
// node stops the rollout, kill -9 while writing leaves no broken file and
// the download resumes.
func TestRolloutToRealAgents(t *testing.T) {
	p := startPlatform(t)
	bin := buildAgentBinary(t)
	nodes := p.enrollNodes(t, bin, 3)
	for _, nd := range nodes {
		nd.start(t, bin, p.addr)
	}
	waitFor(t, "agents online", 30*time.Second, func() bool {
		for _, nd := range nodes {
			if !p.node(t, nd.id).Online {
				return false
			}
		}
		return true
	})

	// Watch when each node's control file first names version 1.
	var mu sync.Mutex
	firstSeen := map[string]time.Time{}
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(20 * time.Millisecond):
			}
			for _, nd := range nodes {
				if nd.controlVersion() >= 1 {
					mu.Lock()
					if _, ok := firstSeen[nd.id]; !ok {
						firstSeen[nd.id] = time.Now()
					}
					mu.Unlock()
				}
			}
		}
	}()

	// 1. Bundle 1: one node, then 10% (one more), then all, in order.
	r1 := p.deploy(t, "MODE_SHADOW")
	waitFor(t, "rollout 1 done", 60*time.Second, func() bool { return p.rollout(t, r1).Rollout.State == "DONE" })
	close(stop)
	ro := p.rollout(t, r1).Rollout
	for i, nd := range nodes {
		var got *struct {
			NodeID string `json:"node_id"`
			Wave   int    `json:"wave"`
			State  string `json:"state"`
			Error  string `json:"error"`
		}
		for j := range ro.Nodes {
			if ro.Nodes[j].NodeID == nd.id {
				got = &ro.Nodes[j]
			}
		}
		if got == nil || got.Wave != i || got.State != "ACTIVE" {
			t.Fatalf("node %d: %+v", i, got)
		}
		if v := nd.controlVersion(); v != 1 {
			t.Fatalf("node %d control file names %d", i, v)
		}
		data, _ := os.ReadFile(filepath.Join(nd.bundles, "bundle-1.sbn"))
		if _, err := bundlefmt.Verify(data, p.pub); err != nil {
			t.Fatalf("node %d bundle: %v", i, err)
		}
	}
	mu.Lock()
	t1, t2, t3 := firstSeen[nodes[0].id], firstSeen[nodes[1].id], firstSeen[nodes[2].id]
	mu.Unlock()
	// ACTIVE comes 2 s after the control file (no worker metrics yet), so a
	// later wave starts at least that much later.
	if t2.Sub(t1) <= time.Second || t3.Sub(t2) <= time.Second {
		t.Fatalf("waves not in order: %s, %s, %s", t1.Format(time.StampMilli), t2.Format(time.StampMilli), t3.Format(time.StampMilli))
	}
	t.Logf("bundle 1 reached the nodes at +0, +%s, +%s", t2.Sub(t1).Round(time.Millisecond), t3.Sub(t1).Round(time.Millisecond))

	// 2. The first node now checks signatures with another key: bundle 2
	// FAILS on it and the rollout stops; the others keep bundle 1.
	_ = nodes[0].proc.stop(5 * time.Second)
	_, wrong, _ := ed25519.GenerateKey(nil)
	wrongPub := filepath.Join(t.TempDir(), "wrong.pub")
	_ = os.WriteFile(wrongPub, wrong.Public().(ed25519.PublicKey), 0o644)
	nodes[0].start(t, bin, p.addr, "--bundle-pubkey", wrongPub)
	r2 := p.deploy(t, "MODE_ENFORCE")
	waitFor(t, "rollout 2 failed", 60*time.Second, func() bool { return p.rollout(t, r2).Rollout.State == "FAILED" })
	ro2 := p.rollout(t, r2).Rollout
	if !strings.Contains(ro2.Reason, nodes[0].id) || !strings.Contains(ro2.Reason, "signature") {
		t.Fatalf("reason %q", ro2.Reason)
	}
	time.Sleep(3 * time.Second)
	if nodes[1].controlVersion() != 1 || nodes[2].controlVersion() != 1 || nodes[0].controlVersion() != 1 {
		t.Fatal("a node left bundle 1 although the rollout stopped")
	}
	if c := p.call(t, "operator", http.MethodPost, "/v1/rollouts/"+r2+":abort", `{}`, nil); c != http.StatusOK {
		t.Fatalf("abort: %d", c)
	}
	// Aborted: the node that has not installed bundle 2 is not offered it
	// again when it reconnects.
	_ = nodes[0].proc.stop(5 * time.Second)
	nodes[0].start(t, bin, p.addr)
	waitFor(t, "node 0 back", 30*time.Second, func() bool { return p.node(t, nodes[0].id).Online })
	time.Sleep(3 * time.Second)
	if v := nodes[0].controlVersion(); v != 1 {
		t.Fatalf("after the abort node 0 installed bundle %d", v)
	}

	// 3. kill -9 the first node while it writes a 64 MB bundle: nothing
	// broken on disk, the control file still names bundle 1; after a
	// restart the download resumes and the node runs bundle 3.
	t.Setenv("FAKECOMPILE_SIZE", fmt.Sprint(64<<20))
	const prefix = int64(1 << 20)
	release := p.downloads.pause(policy.ObjectKey(3), prefix)
	t.Cleanup(release)
	r3 := p.deploy(t, "MODE_SHADOW")
	partial := filepath.Join(nodes[0].bundles, ".partial-3")
	waitFor(t, "download started", 30*time.Second, func() bool {
		st, err := os.Stat(partial)
		return err == nil && st.Size() == prefix
	})
	_ = nodes[0].proc.cmd.Process.Kill()
	<-nodes[0].proc.done
	st, err := os.Stat(partial)
	if err != nil {
		t.Fatal(err)
	}
	if st.Size() != prefix {
		t.Fatalf("download escaped deterministic pause: %d", st.Size())
	}
	release()
	if v := nodes[0].controlVersion(); v != 1 {
		t.Fatalf("control file names %d after kill -9", v)
	}
	if _, err := os.Stat(filepath.Join(nodes[0].bundles, "bundle-3.sbn")); err == nil {
		data, _ := os.ReadFile(filepath.Join(nodes[0].bundles, "bundle-3.sbn"))
		if _, err := bundlefmt.Verify(data, p.pub); err != nil {
			t.Fatalf("a broken bundle-3.sbn after kill -9: %v", err)
		}
	}
	t.Logf("killed with %d of %d bytes downloaded", st.Size(), 64<<20)
	nodes[0].start(t, bin, p.addr)
	waitFor(t, "download resumed", 30*time.Second, func() bool {
		return strings.Contains(nodes[0].proc.logBuf.String(), fmt.Sprintf("offset=%d", st.Size()))
	})
	waitFor(t, "rollout 3 done", 120*time.Second, func() bool { return p.rollout(t, r3).Rollout.State == "DONE" })
	for i, nd := range nodes {
		if nd.controlVersion() != 3 {
			t.Fatalf("node %d control file names %d", i, nd.controlVersion())
		}
		data, _ := os.ReadFile(filepath.Join(nd.bundles, "bundle-3.sbn"))
		if len(data) != 64<<20+ed25519.SignatureSize {
			t.Fatalf("node %d bundle 3: %d bytes", i, len(data))
		}
		if _, err := bundlefmt.Verify(data, p.pub); err != nil {
			t.Fatalf("node %d bundle 3: %v", i, err)
		}
	}
}
