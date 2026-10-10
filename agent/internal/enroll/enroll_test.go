package enroll

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	fleetv1 "github.com/strata/strata/agent/gen/strata/fleet/v1"
)

func mode(t *testing.T, p string) os.FileMode {
	t.Helper()
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return st.Mode().Perm()
}

func TestSave_KeyIs0600AndCSRVerifies(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "identity")
	id, err := NewIdentity("edge-01.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if err := id.Save(dir, false); err != nil {
		t.Fatal(err)
	}
	if m := mode(t, dir); m != 0o700 {
		t.Errorf("dir mode %o, want 700", m)
	}
	if m := mode(t, filepath.Join(dir, KeyFile)); m != 0o600 {
		t.Errorf("key mode %o, want 600", m)
	}

	raw, err := os.ReadFile(filepath.Join(dir, CSRFile))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(raw)
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CSR signature: %v", err)
	}
	if csr.Subject.CommonName != "edge-01.example.test" || len(csr.URIs) != 0 {
		t.Errorf("CSR subject %q URIs %v", csr.Subject.CommonName, csr.URIs)
	}
	// The key on disk is the CSR's key.
	kraw, _ := os.ReadFile(filepath.Join(dir, KeyFile))
	kb, _ := pem.Decode(kraw)
	k, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !k.(*ecdsa.PrivateKey).PublicKey.Equal(csr.PublicKey) {
		t.Error("key and CSR do not match")
	}

	// openssl agrees (W03-G1-01: "CSR hợp lệ (openssl req -verify)").
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Fatal("openssl is needed for this test")
	}
	out, err := exec.Command("openssl", "req", "-in", filepath.Join(dir, CSRFile), "-noout", "-verify").CombinedOutput()
	if err != nil || !strings.Contains(strings.ToLower(string(out)), "verify ok") {
		t.Fatalf("openssl req -verify: %v: %s", err, out)
	}
}

func TestSave_RefusesToReplaceAKey(t *testing.T) {
	dir := t.TempDir()
	a, _ := NewIdentity("h")
	b, _ := NewIdentity("h")
	if err := a.Save(dir, false); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(dir, KeyFile))
	if err := b.Save(dir, false); !errors.Is(err, ErrExists) {
		t.Fatalf("second save: %v, want ErrExists", err)
	}
	after, _ := os.ReadFile(filepath.Join(dir, KeyFile))
	if string(before) != string(after) {
		t.Fatal("key replaced without --force")
	}
	if err := b.Save(dir, true); err != nil {
		t.Fatalf("save with overwrite: %v", err)
	}
	if m := mode(t, filepath.Join(dir, KeyFile)); m != 0o600 {
		t.Errorf("key mode after overwrite %o", m)
	}
}

// pki is a throwaway CA with a server certificate for 127.0.0.1.
type pki struct {
	ca     *x509.Certificate
	caKey  *ecdsa.PrivateKey
	caPEM  []byte
	server tls.Certificate
}

func newPKI(t *testing.T) *pki {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(der)
	srvKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	srvDER, _ := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "cp"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, ca, &srvKey.PublicKey, caKey)
	return &pki{
		ca: ca, caKey: caKey,
		caPEM:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		server: tls.Certificate{Certificate: [][]byte{srvDER}, PrivateKey: srvKey},
	}
}

// sign issues a node certificate for the CSR's key (or for other, when set).
func (p *pki) sign(t *testing.T, csrDER []byte, nodeID string, other *ecdsa.PublicKey) []byte {
	t.Helper()
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatal(err)
	}
	pub := csr.PublicKey
	if other != nil {
		pub = other
	}
	u, _ := url.Parse("spiffe://strata/node/" + nodeID)
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: nodeID},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(24 * time.Hour),
		URIs: []*url.URL{u}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, p.ca, pub, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

type fakeFleet struct {
	fleetv1.UnimplementedFleetServiceServer
	enroll func(*fleetv1.EnrollRequest) (*fleetv1.EnrollResponse, error)
}

func (f *fakeFleet) Enroll(_ context.Context, r *fleetv1.EnrollRequest) (*fleetv1.EnrollResponse, error) {
	return f.enroll(r)
}

func serve(t *testing.T, p *pki, f *fakeFleet) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{p.server}, MinVersion: tls.VersionTLS13})))
	fleetv1.RegisterFleetServiceServer(gs, f)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	return lis.Addr().String()
}

func setupEnroll(t *testing.T, f func(p *pki, r *fleetv1.EnrollRequest) (*fleetv1.EnrollResponse, error)) (string, *Identity, Options) {
	t.Helper()
	p := newPKI(t)
	addr := serve(t, p, &fakeFleet{enroll: func(r *fleetv1.EnrollRequest) (*fleetv1.EnrollResponse, error) { return f(p, r) }})
	dir := t.TempDir()
	caFile := filepath.Join(t.TempDir(), "bootstrap-ca.pem")
	if err := os.WriteFile(caFile, p.caPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	id, _ := NewIdentity("edge-01")
	if err := id.Save(dir, false); err != nil {
		t.Fatal(err)
	}
	return dir, id, Options{Server: addr, CAFile: caFile, Token: "tok-1", Node: &fleetv1.NodeInfo{Hostname: "edge-01"}}
}

func TestEnroll_StoresCertificateForOurKey(t *testing.T) {
	var gotToken string
	dir, id, opt := setupEnroll(t, func(p *pki, r *fleetv1.EnrollRequest) (*fleetv1.EnrollResponse, error) {
		gotToken = r.GetToken()
		return &fleetv1.EnrollResponse{NodeId: "node-7", Certificate: p.sign(t, r.GetCsr(), "node-7", nil), CaBundle: p.caPEM, BundlePubkey: []byte("pub")}, nil
	})
	resp, err := Enroll(context.Background(), dir, id, opt)
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetNodeId() != "node-7" || gotToken != "tok-1" {
		t.Fatalf("node %q token %q", resp.GetNodeId(), gotToken)
	}
	for _, f := range []string{CertFile, CAFile, BundleKeyFile, NodeIDFile} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
	// The stored pair works as a TLS client certificate.
	if _, err := tls.LoadX509KeyPair(filepath.Join(dir, CertFile), filepath.Join(dir, KeyFile)); err != nil {
		t.Fatalf("stored key pair: %v", err)
	}
}

func TestEnroll_Refusals(t *testing.T) {
	stranger, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for name, f := range map[string]func(p *pki, r *fleetv1.EnrollRequest) (*fleetv1.EnrollResponse, error){
		"token rejected": func(*pki, *fleetv1.EnrollRequest) (*fleetv1.EnrollResponse, error) {
			return nil, status.Error(codes.PermissionDenied, "token used")
		},
		"certificate for another key": func(p *pki, r *fleetv1.EnrollRequest) (*fleetv1.EnrollResponse, error) {
			return &fleetv1.EnrollResponse{NodeId: "node-7", Certificate: p.sign(t, r.GetCsr(), "node-7", &stranger.PublicKey)}, nil
		},
		"certificate for another node": func(p *pki, r *fleetv1.EnrollRequest) (*fleetv1.EnrollResponse, error) {
			return &fleetv1.EnrollResponse{NodeId: "node-7", Certificate: p.sign(t, r.GetCsr(), "node-8", nil)}, nil
		},
		"no certificate": func(*pki, *fleetv1.EnrollRequest) (*fleetv1.EnrollResponse, error) {
			return &fleetv1.EnrollResponse{NodeId: "node-7"}, nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir, id, opt := setupEnroll(t, f)
			if _, err := Enroll(context.Background(), dir, id, opt); err == nil {
				t.Fatal("accepted")
			}
			if _, err := os.Stat(filepath.Join(dir, CertFile)); err == nil {
				t.Fatal("certificate stored after a refusal")
			}
		})
	}
}

// A control plane whose certificate the bootstrap CA did not sign is not
// sent the token.
func TestEnroll_UntrustedServer(t *testing.T) {
	called := false
	dir, id, opt := setupEnroll(t, func(p *pki, r *fleetv1.EnrollRequest) (*fleetv1.EnrollResponse, error) {
		called = true
		return nil, errors.New("unreachable")
	})
	other := newPKI(t)
	if err := os.WriteFile(opt.CAFile, other.caPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	opt.Timeout = 3 * time.Second
	if _, err := Enroll(context.Background(), dir, id, opt); err == nil {
		t.Fatal("enrolled with an untrusted server")
	}
	if called {
		t.Fatal("token sent to an untrusted server")
	}
}
