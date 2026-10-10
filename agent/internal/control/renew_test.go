package control

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	fleetv1 "github.com/strata/strata/agent/gen/strata/fleet/v1"
	"github.com/strata/strata/agent/internal/enroll"
	"github.com/strata/strata/agent/internal/identity"
)

type renewFleet struct {
	fakeFleet
	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey
	calls  atomic.Int32
}

func (r *renewFleet) sign(pub any, from, to time.Time) []byte {
	u, _ := url.Parse("spiffe://strata/node/node-1")
	sn, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	der, _ := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: sn, URIs: []*url.URL{u},
		NotBefore: from, NotAfter: to, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}, r.caCert, pub, r.caKey)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func (r *renewFleet) RenewCertificate(_ context.Context, req *fleetv1.RenewRequest) (*fleetv1.RenewResponse, error) {
	r.calls.Add(1)
	csr, err := x509.ParseCertificateRequest(req.GetCsr())
	if err != nil {
		return nil, err
	}
	return &fleetv1.RenewResponse{Certificate: r.sign(csr.PublicKey, time.Now(), time.Now().Add(24*time.Hour))}, nil
}

// A certificate past two thirds of its life is renewed, written to the
// identity directory and used from then on.
func TestRenewsInTime(t *testing.T) {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(72 * time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(der)
	f := &renewFleet{caCert: caCert, caKey: caKey}

	dir := t.TempDir()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	k, _ := x509.MarshalPKCS8PrivateKey(key)
	// 24 h certificate issued 17 h ago: past 2/3, renew now.
	for name, data := range map[string][]byte{
		enroll.KeyFile:    pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: k}),
		enroll.CertFile:   f.sign(&key.PublicKey, time.Now().Add(-17*time.Hour), time.Now().Add(7*time.Hour)),
		enroll.NodeIDFile: []byte("node-1\n"),
		enroll.CAFile:     pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw}),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	id, err := identity.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	oldSerial := id.Certificate().Leaf.SerialNumber.String()

	c := New(client(t, f), Options{Identity: id, Node: &fleetv1.NodeInfo{Hostname: "edge-01"}, BackoffMin: time.Millisecond, BackoffMax: time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = c.Run(ctx) }()
	eventually(t, "renewal", func() bool { return id.Certificate().Leaf.SerialNumber.String() != oldSerial })
	if n := f.calls.Load(); n != 1 {
		t.Errorf("%d renewals, want 1 (the new certificate is good for 16 h)", n)
	}
	reloaded, err := identity.Load(dir)
	if err != nil || reloaded.Certificate().Leaf.SerialNumber.String() == oldSerial {
		t.Fatalf("renewed certificate not on disk: %v", err)
	}
}
