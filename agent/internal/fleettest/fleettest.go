// Package fleettest is a stand-in for the control plane's PushEvents in
// agent tests: mTLS with a CA made for the test, dedup by seq the way the
// control plane does it (a batch whose seq is not above the last
// committed one is dropped), and a switch to take it down and bring it
// back on the same address.
package fleettest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	fleetv1 "github.com/strata/strata/agent/gen/strata/fleet/v1"
)

// Server is a fake FleetService.
type Server struct {
	fleetv1.UnimplementedFleetServiceServer

	t    testing.TB
	addr string
	tls  *tls.Config

	mu         sync.Mutex
	gs         *grpc.Server
	lastSeq    uint64
	ids        map[string]int // Block ID -> times committed
	batches    int
	duplicates int // batches dropped by seq
	exhaust    int // reject the next n streams with RESOURCE_EXHAUSTED
}

// Certs holds the PEM files of a test PKI.
type Certs struct {
	CA, ServerCert, ServerKey, ClientCert, ClientKey string
}

// NewServer starts a fake control plane on 127.0.0.1 and writes the test
// PKI into t.TempDir().
func NewServer(t testing.TB) (*Server, Certs) {
	t.Helper()
	certs, serverTLS := makePKI(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fleettest: listen: %v", err)
	}
	s := &Server{t: t, addr: ln.Addr().String(), tls: serverTLS, ids: map[string]int{}}
	s.serve(ln)
	t.Cleanup(s.Stop)
	return s, certs
}

// Addr is the host:port the agent dials.
func (s *Server) Addr() string { return s.addr }

func (s *Server) serve(ln net.Listener) {
	gs := grpc.NewServer(grpc.Creds(credentials.NewTLS(s.tls)))
	fleetv1.RegisterFleetServiceServer(gs, s)
	s.mu.Lock()
	s.gs = gs
	s.mu.Unlock()
	go func() { _ = gs.Serve(ln) }()
}

// Stop takes the control plane down, cutting open streams.
func (s *Server) Stop() {
	s.mu.Lock()
	gs := s.gs
	s.gs = nil
	s.mu.Unlock()
	if gs != nil {
		gs.Stop()
	}
}

// Start brings it back on the same address.
func (s *Server) Start() {
	var ln net.Listener
	var err error
	for i := 0; i < 50; i++ {
		if ln, err = net.Listen("tcp", s.addr); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		s.t.Fatalf("fleettest: relisten %s: %v", s.addr, err)
	}
	s.serve(ln)
}

// Exhaust makes the next n streams fail with RESOURCE_EXHAUSTED.
func (s *Server) Exhaust(n int) {
	s.mu.Lock()
	s.exhaust = n
	s.mu.Unlock()
}

// PushEvents commits each batch whose seq is above the last committed one
// and acks it; other batches are counted as duplicates and acked with the
// last committed seq.
func (s *Server) PushEvents(st fleetv1.FleetService_PushEventsServer) error {
	s.mu.Lock()
	if s.exhaust > 0 {
		s.exhaust--
		s.mu.Unlock()
		return status.Error(codes.ResourceExhausted, "fleettest: busy")
	}
	s.mu.Unlock()
	for {
		b, err := st.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		s.mu.Lock()
		if b.GetSeq() <= s.lastSeq {
			s.duplicates++
		} else {
			s.lastSeq = b.GetSeq()
			s.batches++
			for _, ev := range b.GetEvents() {
				s.ids[ev.GetBlockId()]++
			}
		}
		ack := s.lastSeq
		s.mu.Unlock()
		if err := st.Send(&fleetv1.EventAck{AckedSeq: ack}); err != nil {
			return err
		}
	}
}

// Snapshot is what the server committed so far.
type Snapshot struct {
	IDs        map[string]int
	LastSeq    uint64
	Batches    int
	Duplicates int
}

// Snapshot copies the committed state.
func (s *Server) Snapshot() Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := make(map[string]int, len(s.ids))
	for k, v := range s.ids {
		ids[k] = v
	}
	return Snapshot{IDs: ids, LastSeq: s.lastSeq, Batches: s.batches, Duplicates: s.duplicates}
}

func makePKI(t testing.TB) (Certs, *tls.Config) {
	t.Helper()
	dir := t.TempDir()
	caKey, caDER := newCert(t, &x509.Certificate{
		Subject:               pkix.Name{CommonName: "strata test CA"},
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}, nil, nil)
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("fleettest: parse CA: %v", err)
	}
	srvKey, srvDER := newCert(t, &x509.Certificate{
		Subject:     pkix.Name{CommonName: "cp.example.test"},
		DNSNames:    []string{"cp.example.test"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, ca, caKey)
	cliKey, cliDER := newCert(t, &x509.Certificate{
		Subject:     pkix.Name{CommonName: "node-example-1"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, ca, caKey)

	c := Certs{
		CA:         writePEM(t, dir, "ca.pem", "CERTIFICATE", caDER),
		ServerCert: writePEM(t, dir, "server.pem", "CERTIFICATE", srvDER),
		ServerKey:  writePEM(t, dir, "server-key.pem", "EC PRIVATE KEY", marshalKey(t, srvKey)),
		ClientCert: writePEM(t, dir, "client.pem", "CERTIFICATE", cliDER),
		ClientKey:  writePEM(t, dir, "client-key.pem", "EC PRIVATE KEY", marshalKey(t, cliKey)),
	}
	pair, err := tls.LoadX509KeyPair(c.ServerCert, c.ServerKey)
	if err != nil {
		t.Fatalf("fleettest: server key pair: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return c, &tls.Config{
		Certificates: []tls.Certificate{pair},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}
}

func newCert(t testing.TB, tmpl, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("fleettest: key: %v", err)
	}
	sn, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		t.Fatalf("fleettest: serial: %v", err)
	}
	tmpl.SerialNumber = sn
	tmpl.NotBefore = time.Now().Add(-time.Hour)
	tmpl.NotAfter = time.Now().Add(24 * time.Hour)
	if parent == nil {
		parent, parentKey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatalf("fleettest: certificate: %v", err)
	}
	return key, der
}

func marshalKey(t testing.TB, k *ecdsa.PrivateKey) []byte {
	t.Helper()
	b, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		t.Fatalf("fleettest: marshal key: %v", err)
	}
	return b
}

func writePEM(t testing.TB, dir, name, typ string, der []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatalf("fleettest: write %s: %v", name, err)
	}
	return p
}
