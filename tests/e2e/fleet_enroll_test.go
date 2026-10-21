package e2e

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/strata/strata/control-plane/admin"
	"github.com/strata/strata/control-plane/api"
	"github.com/strata/strata/control-plane/auth"
	"github.com/strata/strata/control-plane/auth/authtest"
	"github.com/strata/strata/control-plane/db"
	"github.com/strata/strata/control-plane/fleet"
	"github.com/strata/strata/control-plane/ingest"
	"github.com/strata/strata/control-plane/store"
)

// fleetPKI writes a node CA (72 h, so it outlives 24 h node certificates)
// and a server certificate for cp.example.test into dir.
func fleetPKI(t *testing.T, dir string) (caFile, caKeyFile, srvCert, srvKey string) {
	t.Helper()
	mk := func(tmpl, parent *x509.Certificate, pkey *ecdsa.PrivateKey) (*ecdsa.PrivateKey, *x509.Certificate) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		sn, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
		tmpl.SerialNumber, tmpl.NotBefore, tmpl.NotAfter = sn, time.Now().Add(-time.Hour), time.Now().Add(72*time.Hour)
		if parent == nil {
			parent, pkey = tmpl, key
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, pkey)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := x509.ParseCertificate(der)
		return key, c
	}
	caKey, ca := mk(&x509.Certificate{Subject: pkix.Name{CommonName: "e2e node CA"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}, nil, nil)
	sKey, s := mk(&x509.Certificate{Subject: pkix.Name{CommonName: "cp.example.test"}, DNSNames: []string{"cp.example.test"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}, ca, caKey)
	write := func(name, typ string, der []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	ck, _ := x509.MarshalECPrivateKey(caKey)
	sk, _ := x509.MarshalECPrivateKey(sKey)
	return write("ca.pem", "CERTIFICATE", ca.Raw), write("ca-key.pem", "EC PRIVATE KEY", ck),
		write("cp.pem", "CERTIFICATE", s.Raw), write("cp-key.pem", "EC PRIVATE KEY", sk)
}

type fleetEnv struct {
	st       *store.Store
	addr     string
	rest     http.Handler
	issuer   *authtest.Issuer
	caFile   string
	presence *fleet.Presence
	events   *ingest.MockEventStore
}

// startFleet runs a control plane (fleet gRPC with commands, admin REST)
// on a fresh PostgreSQL. certLife: 0 for 24 h node certificates.
func startFleet(t *testing.T) *fleetEnv { return startFleetWith(t, 0) }

func startFleetWith(t *testing.T, certLife time.Duration) *fleetEnv {
	t.Helper()
	ctx := context.Background()
	pool := startPostgres(t)
	latest, _ := db.Latest()
	if err := db.Migrate(ctx, pool, latest); err != nil {
		t.Fatal(err)
	}
	st := store.New(pool)
	dir := t.TempDir()
	caFile, caKey, cert, key := fleetPKI(t, dir)
	ca, err := fleet.LoadCA(caFile, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca.Lifetime = certLife
	tlsCfg, err := fleet.ServerTLS(caFile, cert, key)
	if err != nil {
		t.Fatal(err)
	}
	presence := fleet.NewPresence()
	trust, _ := os.ReadFile(caFile)
	events := ingest.NewMockEventStore()
	svc := ingest.NewIngestService(events, ingest.DefaultBatcherConfig(), time.Hour)
	t.Cleanup(func() { _ = svc.Close(ctx) })
	gs := fleet.NewGRPCServer(tlsCfg, fleet.NewServer(fleet.Config{
		Ingest: svc, Registry: st, CA: ca, TrustBundle: trust, BundlePubKey: make([]byte, 32), Presence: presence,
	}))
	commands := fleet.NewCommands(st, presence)
	cctx, stopCommands := context.WithCancel(ctx)
	t.Cleanup(stopCommands)
	go commands.Run(cctx)
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
	adm, err := admin.New(ctx, v, admin.BuildInfo{Version: "e2e"}, admin.Deps{Fleet: st, Presence: presence, Commands: st, CommandKicker: commands})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(adm.Close)
	srv := api.NewServer(api.ServerConfig{Auth: v, Admin: adm.Gateway}, ingest.NewMockEventStore())
	return &fleetEnv{st: st, addr: ln.Addr().String(), rest: srv.Handler(), issuer: is, caFile: caFile, presence: presence, events: events}
}

// call sends a REST request as role and decodes the JSON answer.
func (e *fleetEnv) call(t *testing.T, role, method, path, body string, out any) int {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+e.issuer.Token(t, authtest.Claims{Subject: "lab-" + role, Roles: []string{role}}))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	e.rest.ServeHTTP(rec, req)
	if out != nil && rec.Code < 300 {
		if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
			t.Fatalf("%s %s: %v: %s", method, path, err, rec.Body.String())
		}
	}
	return rec.Code
}

type nodeJSON struct {
	ID     string `json:"id"`
	Online bool   `json:"online"`
}

func (e *fleetEnv) node(t *testing.T, id string) nodeJSON {
	t.Helper()
	var out struct {
		Nodes []nodeJSON `json:"nodes"`
	}
	if c := e.call(t, "viewer", http.MethodGet, "/v1/nodes", "", &out); c != http.StatusOK {
		t.Fatalf("GET /v1/nodes: %d", c)
	}
	for _, n := range out.Nodes {
		if n.ID == id {
			return n
		}
	}
	t.Fatalf("node %s not listed", id)
	return nodeJSON{}
}

func waitFor(t *testing.T, what string, limit time.Duration, f func() bool) time.Duration {
	t.Helper()
	start := time.Now()
	for !f() {
		if time.Since(start) > limit {
			t.Fatalf("%s: not within %s", what, limit)
		}
		time.Sleep(100 * time.Millisecond)
	}
	return time.Since(start)
}

// W04-G1-01: an agent enrolls and gets a 24 h certificate; the token cannot
// be used twice; the node shows online/offline within 30 s; revocation
// locks it out.
func TestFleetEnrollConnectRevoke(t *testing.T) {
	e := startFleet(t)
	bin := buildAgentBinary(t)

	// Admin creates a group and a token; a viewer may not.
	if c := e.call(t, "viewer", http.MethodPost, "/v1/groups", `{"id":"lab","name":"Lab"}`, nil); c != http.StatusForbidden {
		t.Fatalf("viewer creates a group: %d", c)
	}
	if c := e.call(t, "admin", http.MethodPost, "/v1/groups", `{"id":"lab","name":"Lab"}`, nil); c != http.StatusOK {
		t.Fatalf("create group: %d", c)
	}
	var tok struct {
		Token string `json:"token"`
	}
	if c := e.call(t, "admin", http.MethodPost, "/v1/groups/lab/enrollmentTokens", `{}`, &tok); c != http.StatusOK || !strings.HasPrefix(tok.Token, "stet_") {
		t.Fatalf("create token: %d %q", c, tok.Token)
	}
	tokFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokFile, []byte(tok.Token), 0o600); err != nil {
		t.Fatal(err)
	}

	enroll := func(dir string) (string, error) {
		out, err := exec.Command(bin, "enroll", "--server", e.addr, "--server-name", "cp.example.test",
			"--tls-ca", e.caFile, "--token-file", tokFile, "--identity-dir", dir).CombinedOutput()
		return string(out), err
	}
	idDir := filepath.Join(t.TempDir(), "identity")
	if out, err := enroll(idDir); err != nil {
		t.Fatalf("enroll: %v: %s", err, out)
	}
	pair, err := tls.LoadX509KeyPair(filepath.Join(idDir, "node.crt"), filepath.Join(idDir, "node.key"))
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(pair.Certificate[0])
	if life := leaf.NotAfter.Sub(leaf.NotBefore); life < 24*time.Hour || life > 24*time.Hour+2*time.Minute {
		t.Fatalf("certificate lifetime %s, want 24 h", life)
	}
	raw, _ := os.ReadFile(filepath.Join(idDir, "node-id"))
	nodeID := strings.TrimSpace(string(raw))
	if st, _ := os.Stat(filepath.Join(idDir, "node.key")); st.Mode().Perm() != 0o600 {
		t.Fatalf("key mode %o", st.Mode().Perm())
	}

	// The same token a second time: refused, nothing written.
	second := filepath.Join(t.TempDir(), "identity2")
	if out, err := enroll(second); err == nil || !strings.Contains(out, "not valid") {
		t.Fatalf("token reused: err %v: %s", err, out)
	}
	if _, err := os.Stat(filepath.Join(second, "node.crt")); err == nil {
		t.Fatal("a certificate was stored for a reused token")
	}

	// Run the agent with its identity: online within 30 s.
	base := t.TempDir()
	run := func() *agentProcess {
		return startAgentProcess(t, bin, "run", "--event-socket", filepath.Join(base, "events.sock"),
			"--spool-dir", filepath.Join(base, "spool"), "--server", e.addr, "--server-name", "cp.example.test",
			"--identity-dir", idDir, "--metrics-addr", "")
	}
	agent := run()
	took := waitFor(t, "online", 30*time.Second, func() bool { return e.node(t, nodeID).Online })
	t.Logf("online %s after start", took.Round(time.Millisecond))
	// CP-B05: a real agent reports its spool through the authenticated heartbeat;
	// missing worker metrics remain unavailable, rather than a fabricated zero.
	waitFor(t, "persisted spool telemetry", 25*time.Second, func() bool {
		nodes, _, err := e.st.HealthNodes(t.Context(), []string{nodeID})
		if err != nil {
			t.Fatal(err)
		}
		return len(nodes) == 1 && nodes[0].Telemetry != nil && nodes[0].Telemetry.Spool != nil && nodes[0].Telemetry.Spool.LimitBytes > 0 && !nodes[0].Telemetry.MetricsAvailable
	})

	// kill -9: no goodbye; offline within 30 s.
	_ = agent.cmd.Process.Kill()
	<-agent.done
	took = waitFor(t, "offline", 30*time.Second, func() bool { return !e.node(t, nodeID).Online })
	t.Logf("offline %s after kill -9", took.Round(time.Millisecond))

	// Back online, then revoked: the stream is cut and the agent refused.
	agent = run()
	defer func() { _ = agent.stop(5 * time.Second) }()
	waitFor(t, "online again", 30*time.Second, func() bool { return e.node(t, nodeID).Online })
	if c := e.call(t, "operator", http.MethodDelete, "/v1/nodes/"+nodeID, "", nil); c != http.StatusForbidden {
		t.Fatalf("operator revokes: %d", c)
	}
	if c := e.call(t, "admin", http.MethodDelete, "/v1/nodes/"+nodeID, "", nil); c != http.StatusOK {
		t.Fatalf("revoke: %d", c)
	}
	waitFor(t, "stream cut", 5*time.Second, func() bool { return !e.presence.Connected(nodeID) })
	time.Sleep(2 * time.Second) // the agent retries; it must stay out
	if e.presence.Connected(nodeID) || e.node(t, nodeID).Online {
		t.Fatal("revoked node connected again")
	}
	if !strings.Contains(agent.logBuf.String(), "refused this node") {
		t.Errorf("agent log does not show the refusal:\n%s", agent.logBuf.String())
	}

	// Every write is in the audit log, without the token.
	entries, err := e.st.AuditEntries(context.Background(), 20)
	if err != nil {
		t.Fatal(err)
	}
	var actions []string
	for _, a := range entries {
		actions = append(actions, a.Action)
		if b, _ := json.Marshal(a); strings.Contains(string(b), tok.Token) {
			t.Fatal("the enrollment token is in the audit log")
		}
	}
	for _, want := range []string{"CreateGroup", "CreateEnrollmentToken", "FleetService/Enroll", "RevokeNode"} {
		if !strings.Contains(strings.Join(actions, " "), want) {
			t.Errorf("audit log lacks %s: %v", want, actions)
		}
	}
}
