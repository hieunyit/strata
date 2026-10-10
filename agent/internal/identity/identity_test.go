package identity

import (
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
	"testing"
	"time"

	"github.com/strata/strata/agent/internal/enroll"
)

type ca struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newCA(t *testing.T) *ca {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"}, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(72 * time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	c, _ := x509.ParseCertificate(der)
	return &ca{cert: c, key: key}
}

// pair returns PEM key and certificate for node id, valid [from, to].
func (c *ca) pair(t *testing.T, id string, from, to time.Time) (keyPEM, certPEM []byte) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	u, _ := url.Parse("spiffe://strata/node/" + id)
	sn, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: sn, URIs: []*url.URL{u},
		NotBefore: from, NotAfter: to, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}, c.cert, &key.PublicKey, c.key)
	if err != nil {
		t.Fatal(err)
	}
	k, _ := x509.MarshalPKCS8PrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: k}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func writeDir(t *testing.T, c *ca, keyPEM, certPEM []byte) string {
	t.Helper()
	dir := t.TempDir()
	for name, data := range map[string][]byte{
		enroll.KeyFile: keyPEM, enroll.CertFile: certPEM, enroll.NodeIDFile: []byte("node-1\n"),
		enroll.CAFile: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.cert.Raw}),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func serial(t *testing.T, id *Identity) string {
	t.Helper()
	return id.Certificate().Leaf.SerialNumber.String()
}

func TestLoadAndReplace(t *testing.T) {
	c := newCA(t)
	now := time.Now()
	k1, c1 := c.pair(t, "node-1", now.Add(-time.Hour), now.Add(23*time.Hour))
	dir := writeDir(t, c, k1, c1)
	id, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if id.NodeID != "node-1" {
		t.Fatalf("node id %q", id.NodeID)
	}
	if want := now.Add(-time.Hour).Add(16 * time.Hour); id.RenewAt().Sub(want).Abs() > time.Second {
		t.Errorf("RenewAt %s, want %s (2/3 of the lifetime)", id.RenewAt(), want)
	}
	old := serial(t, id)
	k2, c2 := c.pair(t, "node-1", now, now.Add(24*time.Hour))
	if err := id.Replace(k2, c2); err != nil {
		t.Fatal(err)
	}
	if serial(t, id) == old {
		t.Fatal("certificate in use was not replaced")
	}
	again, err := Load(dir)
	if err != nil || serial(t, again) != serial(t, id) {
		t.Fatalf("reload: %v", err)
	}
	if st, _ := os.Stat(filepath.Join(dir, enroll.KeyFile)); st.Mode().Perm() != 0o600 {
		t.Errorf("key mode %o", st.Mode().Perm())
	}
	// A key that does not belong to the certificate is refused.
	if err := id.Replace(k1, c2); err == nil {
		t.Fatal("mismatched pair accepted")
	}
}

// A crash at any point of Replace leaves an identity that loads.
func TestLoadFinishesAnInterruptedRenewal(t *testing.T) {
	c := newCA(t)
	now := time.Now()
	k1, c1 := c.pair(t, "node-1", now.Add(-time.Hour), now.Add(23*time.Hour))
	k2, c2 := c.pair(t, "node-1", now, now.Add(24*time.Hour))
	certSerial := func(certPEM []byte) string {
		b, _ := pem.Decode(certPEM)
		x, _ := x509.ParseCertificate(b.Bytes)
		return x.SerialNumber.String()
	}
	for name, tc := range map[string]struct {
		setup func(dir string)
		want  string
	}{
		"both .next written": {func(dir string) {
			_ = os.WriteFile(filepath.Join(dir, enroll.KeyFile+".next"), k2, 0o600)
			_ = os.WriteFile(filepath.Join(dir, enroll.CertFile+".next"), c2, 0o644)
		}, certSerial(c2)},
		"key moved, certificate not": {func(dir string) {
			_ = os.WriteFile(filepath.Join(dir, enroll.KeyFile), k2, 0o600)
			_ = os.WriteFile(filepath.Join(dir, enroll.CertFile+".next"), c2, 0o644)
		}, certSerial(c2)},
		"only the key .next": {func(dir string) {
			_ = os.WriteFile(filepath.Join(dir, enroll.KeyFile+".next"), k2, 0o600)
		}, certSerial(c1)},
		"torn .next pair": {func(dir string) {
			_ = os.WriteFile(filepath.Join(dir, enroll.KeyFile+".next"), k1, 0o600)
			_ = os.WriteFile(filepath.Join(dir, enroll.CertFile+".next"), c2, 0o644)
		}, certSerial(c1)},
	} {
		t.Run(name, func(t *testing.T) {
			dir := writeDir(t, c, k1, c1)
			tc.setup(dir)
			id, err := Load(dir)
			if err != nil {
				t.Fatal(err)
			}
			if got := serial(t, id); got != tc.want {
				t.Fatalf("serial %s, want %s", got, tc.want)
			}
			for _, f := range []string{enroll.KeyFile + ".next", enroll.CertFile + ".next"} {
				if _, err := os.Stat(filepath.Join(dir, f)); err == nil {
					t.Errorf("%s left behind", f)
				}
			}
		})
	}
}

func TestLoadNeedsEnrollment(t *testing.T) {
	if _, err := Load(t.TempDir()); err == nil {
		t.Fatal("empty directory loaded")
	}
}
