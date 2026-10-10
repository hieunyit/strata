package fleet

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net/url"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	fleetv1 "github.com/strata/strata/agent/gen/strata/fleet/v1"
	"github.com/strata/strata/control-plane/ingest"
	"github.com/strata/strata/control-plane/store"
)

// memRegistry is an in-memory Registry with store.Store's semantics.
type memRegistry struct {
	mu       sync.Mutex
	tokens   map[string]*memToken // by token
	nodes    map[string]store.Node
	seen     map[string]int
	desired  map[string]store.Bundle
	statuses []string // node/version/state
}

type memToken struct {
	group   string
	expires time.Time
	used    bool
}

func newMemRegistry() *memRegistry {
	return &memRegistry{tokens: map[string]*memToken{}, nodes: map[string]store.Node{}, seen: map[string]int{}, desired: map[string]store.Bundle{}}
}

func (m *memRegistry) addToken(tok string, ttl time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokens[tok] = &memToken{group: "lab", expires: time.Now().Add(ttl)}
}

func (m *memRegistry) Enroll(_ context.Context, token string, n store.Node, now time.Time, issue func(string) (store.Issued, error)) (store.Node, store.Issued, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t := m.tokens[token]
	if t == nil || t.used || !now.Before(t.expires) {
		return store.Node{}, store.Issued{}, store.ErrTokenInvalid
	}
	iss, err := issue(t.group)
	if err != nil {
		return store.Node{}, store.Issued{}, err // the token stays unused
	}
	t.used = true
	n.GroupID, n.CertSerial, n.CertNotAfter = t.group, iss.Serial, &iss.NotAfter
	m.nodes[n.ID] = n
	return n, iss, nil
}

func (m *memRegistry) GetNode(_ context.Context, id string) (store.Node, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n, ok := m.nodes[id]
	if !ok {
		return store.Node{}, store.ErrNotFound
	}
	return n, nil
}

func (m *memRegistry) NodeSeen(_ context.Context, id string, at time.Time, host, _, _ string, _ *int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := m.nodes[id]
	n.LastSeenAt, n.Connected = &at, true
	if host != "" {
		n.Hostname = host
	}
	m.nodes[id] = n
	m.seen[id]++
	return nil
}

func (m *memRegistry) DesiredBundle(_ context.Context, node string) (store.Bundle, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.desired[node]
	if !ok {
		return store.Bundle{}, store.ErrNotFound
	}
	return b, nil
}

func (m *memRegistry) ReportBundleStatus(_ context.Context, node string, version uint64, state, _ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.statuses = append(m.statuses, fmt.Sprintf("%s/%d/%s", node, version, state))
	return nil
}

func (m *memRegistry) NodeDisconnected(_ context.Context, id string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := m.nodes[id]
	n.Connected, n.LastSeenAt = false, &at
	m.nodes[id] = n
	return nil
}

func (m *memRegistry) RenewCertificate(_ context.Context, id, old string, iss store.Issued) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	n, ok := m.nodes[id]
	if !ok || n.CertSerial != old || n.RevokedAt != nil {
		return store.ErrNotFound
	}
	n.CertSerial, n.CertNotAfter = iss.Serial, &iss.NotAfter
	m.nodes[id] = n
	return nil
}

func (m *memRegistry) revoke(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := m.nodes[id]
	now := time.Now()
	n.RevokedAt = &now
	m.nodes[id] = n
}

func (p *pki) nodeCA(t *testing.T) *CA {
	t.Helper()
	der, _ := x509.MarshalECPrivateKey(p.caKey)
	ca, err := NewCA(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.ca.Raw}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

type enrollEnv struct {
	p    *pki
	reg  *memRegistry
	srv  *Server
	addr string
}

func newEnrollEnv(t *testing.T) *enrollEnv {
	t.Helper()
	p := newPKI(t)
	reg := newMemRegistry()
	e := &enrollEnv{p: p, reg: reg}
	cfg := Config{Ingest: nopIngest{}, Registry: reg, CA: p.nodeCA(t), TrustBundle: []byte("trust"), BundlePubKey: []byte("bundle-pub"), Presence: NewPresence()}
	e.srv = NewServer(cfg)
	e.addr = serveServer(t, p, e.srv)
	return e
}

func csrFor(t *testing.T, key any, tmpl *x509.CertificateRequest) []byte {
	t.Helper()
	if tmpl == nil {
		tmpl = &x509.CertificateRequest{Subject: pkix.Name{CommonName: "edge-01"}}
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// enroll returns the node certificate as a TLS pair.
func (e *enrollEnv) enroll(t *testing.T, tok string) (*fleetv1.EnrollResponse, tls.Certificate, error) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	resp, err := dial(t, e.p, e.addr, nil).Enroll(context.Background(), &fleetv1.EnrollRequest{
		Token: tok, Csr: csrFor(t, key, nil), Node: &fleetv1.NodeInfo{Hostname: "edge-01"},
	})
	if err != nil {
		return nil, tls.Certificate{}, err
	}
	block, _ := pem.Decode(resp.GetCertificate())
	return resp, tls.Certificate{Certificate: [][]byte{block.Bytes}, PrivateKey: key}, nil
}

func TestEnroll_IssuesA24HourNodeCertificate(t *testing.T) {
	e := newEnrollEnv(t)
	e.reg.addToken("tok-a", time.Hour)
	resp, pair, err := e.enroll(t, "tok-a")
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(pair.Certificate[0])
	if life := cert.NotAfter.Sub(cert.NotBefore); life < 24*time.Hour || life > 24*time.Hour+2*time.Minute {
		t.Errorf("lifetime %s, want 24 h", life)
	}
	if len(cert.URIs) != 1 || cert.URIs[0].String() != spiffePrefix+resp.GetNodeId() {
		t.Errorf("URIs %v for node %s", cert.URIs, resp.GetNodeId())
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Errorf("EKU %v", cert.ExtKeyUsage)
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: e.p.pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Errorf("does not chain to the node CA: %v", err)
	}
	if string(resp.GetCaBundle()) != "trust" || string(resp.GetBundlePubkey()) != "bundle-pub" {
		t.Errorf("response %v", resp)
	}
	if n := e.reg.nodes[resp.GetNodeId()]; n.GroupID != "lab" || n.Hostname != "edge-01" || n.CertSerial != cert.SerialNumber.Text(16) {
		t.Errorf("registry node %+v", n)
	}
}

func TestEnroll_TokenOnceAndNotExpired(t *testing.T) {
	e := newEnrollEnv(t)
	e.reg.addToken("tok-a", time.Hour)
	e.reg.addToken("tok-old", -time.Second)
	if _, _, err := e.enroll(t, "tok-a"); err != nil {
		t.Fatal(err)
	}
	for _, tok := range []string{"tok-a", "tok-old", "tok-unknown", ""} {
		_, _, err := e.enroll(t, tok)
		if c := status.Code(err); c != codes.PermissionDenied && (tok != "" || c != codes.InvalidArgument) {
			t.Errorf("token %q: %v", tok, err)
		}
	}
}

func TestEnroll_BadCSRKeepsTheToken(t *testing.T) {
	e := newEnrollEnv(t)
	e.reg.addToken("tok-a", time.Hour)
	cl := dial(t, e.p, e.addr, nil)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	bad := csrFor(t, key, nil)
	bad[len(bad)-3] ^= 0xff // break the signature
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	for name, csr := range map[string][]byte{"broken signature": bad, "RSA 2048": csrFor(t, rsaKey, nil), "empty": nil} {
		if _, err := cl.Enroll(context.Background(), &fleetv1.EnrollRequest{Token: "tok-a", Csr: csr}); status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, _, err := e.enroll(t, "tok-a"); err != nil {
		t.Fatalf("token was used up by a refused CSR: %v", err)
	}
}

// The control plane chooses the identity; names in the CSR are ignored.
func TestEnroll_IgnoresNamesInTheCSR(t *testing.T) {
	e := newEnrollEnv(t)
	e.reg.addToken("tok-a", time.Hour)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	u, _ := url.Parse(spiffePrefix + "node-admin")
	resp, err := dial(t, e.p, e.addr, nil).Enroll(context.Background(), &fleetv1.EnrollRequest{
		Token: "tok-a", Csr: csrFor(t, key, &x509.CertificateRequest{URIs: []*url.URL{u}, DNSNames: []string{"cp.example.test"}}),
	})
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(resp.GetCertificate())
	cert, _ := x509.ParseCertificate(block.Bytes)
	if len(cert.URIs) != 1 || cert.URIs[0].String() != spiffePrefix+resp.GetNodeId() || len(cert.DNSNames) != 0 {
		t.Fatalf("certificate names: %v %v", cert.URIs, cert.DNSNames)
	}
}

func connect(t *testing.T, cl fleetv1.FleetServiceClient, hello bool) (fleetv1.FleetService_ConnectClient, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	st, err := cl.Connect(ctx)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if hello {
		if err := st.Send(&fleetv1.AgentMessage{Msg: &fleetv1.AgentMessage_Hello{Hello: &fleetv1.Hello{
			Node: &fleetv1.NodeInfo{Hostname: "edge-01b"}, ActiveBundleVersion: 1,
		}}}); err != nil {
			t.Fatal(err)
		}
	}
	return st, cancel
}

func eventually(t *testing.T, what string, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !f() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestConnect_OnlineWhileTheStreamIsOpen(t *testing.T) {
	e := newEnrollEnv(t)
	e.reg.addToken("tok-a", time.Hour)
	resp, pair, err := e.enroll(t, "tok-a")
	if err != nil {
		t.Fatal(err)
	}
	id := resp.GetNodeId()
	_, cancel := connect(t, dial(t, e.p, e.addr, &pair), true)
	eventually(t, "online", func() bool { return e.srv.Presence().Connected(id) })
	eventually(t, "Hello recorded", func() bool {
		n, _ := e.reg.GetNode(context.Background(), id)
		return n.Hostname == "edge-01b" && n.LastSeenAt != nil
	})
	cancel()
	eventually(t, "offline after disconnect", func() bool { return !e.srv.Presence().Connected(id) })
	// The stream end is recorded: offline at once, not 30 s later.
	eventually(t, "disconnect recorded", func() bool {
		n, _ := e.reg.GetNode(context.Background(), id)
		return !n.Connected
	})
	n, _ := e.reg.GetNode(context.Background(), id)
	if e.srv.Presence().Online(id, n.Connected, n.LastSeenAt, false, time.Now()) {
		t.Error("online right after the stream ended")
	}
	// Reported connected elsewhere: online until heartbeats stop for 30 s.
	if !e.srv.Presence().Online(id, true, n.LastSeenAt, false, time.Now()) {
		t.Error("connected elsewhere, seen now, but offline")
	}
	if e.srv.Presence().Online(id, true, n.LastSeenAt, false, time.Now().Add(OnlineWindow+time.Second)) {
		t.Error("online 31 s after the last heartbeat")
	}
}

func TestConnect_NeedsHello(t *testing.T) {
	old := helloTimeout
	helloTimeout = 200 * time.Millisecond
	defer func() { helloTimeout = old }()
	e := newEnrollEnv(t)
	e.reg.addToken("tok-a", time.Hour)
	_, pair, _ := e.enroll(t, "tok-a")
	st, cancel := connect(t, dial(t, e.p, e.addr, &pair), false)
	defer cancel()
	if _, err := st.Recv(); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("no Hello: %v", err)
	}
}

func TestRevocationCutsStreamsAndRefusesNewOnes(t *testing.T) {
	e := newEnrollEnv(t)
	e.reg.addToken("tok-a", time.Hour)
	resp, pair, _ := e.enroll(t, "tok-a")
	id := resp.GetNodeId()
	cl := dial(t, e.p, e.addr, &pair)
	st, cancel := connect(t, cl, true)
	defer cancel()
	eventually(t, "online", func() bool { return e.srv.Presence().Connected(id) })

	e.reg.revoke(id)
	e.srv.Presence().Cut(id)
	if _, err := st.Recv(); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("open stream after revocation: %v", err)
	}
	st2, cancel2 := connect(t, cl, true)
	defer cancel2()
	if _, err := st2.Recv(); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("new stream after revocation: %v", err)
	}
	if _, err := push(t, cl, batch(1, "STR-AAAA-BBBB-CCCC-DDDD")); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("PushEvents after revocation: %v", err)
	}
}

func TestRenewSupersedesTheOldCertificate(t *testing.T) {
	e := newEnrollEnv(t)
	e.reg.addToken("tok-a", time.Hour)
	_, oldPair, _ := e.enroll(t, "tok-a")
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rr, err := dial(t, e.p, e.addr, &oldPair).RenewCertificate(context.Background(), &fleetv1.RenewRequest{Csr: csrFor(t, key, nil)})
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(rr.GetCertificate())
	newPair := tls.Certificate{Certificate: [][]byte{block.Bytes}, PrivateKey: key}

	st, cancel := connect(t, dial(t, e.p, e.addr, &oldPair), true)
	defer cancel()
	if _, err := st.Recv(); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("old certificate after renewal: %v", err)
	}
	st2, cancel2 := connect(t, dial(t, e.p, e.addr, &newPair), true)
	defer cancel2()
	recvErr := make(chan error, 1)
	go func() { _, err := st2.Recv(); recvErr <- err }()
	select {
	case err := <-recvErr:
		t.Fatalf("renewed certificate refused: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
}

func TestUnknownNodeIsRefused(t *testing.T) {
	e := newEnrollEnv(t)
	stranger := e.p.nodeCert(t, "node-never-enrolled")
	st, cancel := connect(t, dial(t, e.p, e.addr, &stranger), true)
	defer cancel()
	if _, err := st.Recv(); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("unknown node: %v", err)
	}
	// Enroll itself needs no certificate.
	if _, err := dial(t, e.p, e.addr, nil).Enroll(context.Background(), &fleetv1.EnrollRequest{Token: "x", Csr: []byte{1}}); status.Code(err) == codes.Unauthenticated {
		t.Fatalf("Enroll asked for a certificate: %v", err)
	}
}

type nopIngest struct{}

func (nopIngest) ProcessBatch(_ context.Context, b ingest.EventBatch) (*ingest.EventAck, error) {
	return &ingest.EventAck{NodeID: b.NodeID, AckedSeq: b.Seq, Success: true}, nil
}

func serveServer(t *testing.T, p *pki, srv *Server) string {
	t.Helper()
	return serveConfig(t, p, srv.cfg, srv)
}

func batch(seq uint64, ids ...string) *fleetv1.EventBatch {
	b := &fleetv1.EventBatch{Seq: seq}
	for _, id := range ids {
		b.Events = append(b.Events, event(id))
	}
	return b
}
