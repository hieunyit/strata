// Package enroll creates the node's identity (nginx-module.md › "Đăng ký
// node"): a private key that never leaves the node, a CSR for it, and the
// exchange of a one-time enrollment token for a client certificate.
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
	"fmt"
	"os"
	"path/filepath"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	fleetv1 "github.com/strata/strata/agent/gen/strata/fleet/v1"
)

// Files of an identity directory.
const (
	KeyFile       = "node.key"   // PKCS#8 PEM, 0600
	CSRFile       = "node.csr"   // PEM
	CertFile      = "node.crt"   // PEM, from Enroll
	CAFile        = "ca.pem"     // PEM, CA trusted for the control plane
	BundleKeyFile = "bundle.pub" // Ed25519 public key that signs bundles
	NodeIDFile    = "node-id"
)

// ErrExists is returned when an identity is already there and overwriting
// was not asked for.
var ErrExists = errors.New("enroll: identity already exists")

// Identity is a key and its CSR.
type Identity struct {
	Key    *ecdsa.PrivateKey
	CSRDER []byte
}

// NewIdentity generates a P-256 key and a CSR whose subject CN is
// hostname. The CSR carries no node id: the control plane chooses it and
// puts it in the certificate as spiffe://strata/node/<id>.
func NewIdentity(hostname string) (*Identity, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("enroll: key: %w", err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: hostname},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}, key)
	if err != nil {
		return nil, fmt.Errorf("enroll: CSR: %w", err)
	}
	return &Identity{Key: key, CSRDER: csr}, nil
}

// CSRPEM returns the CSR as PEM.
func (id *Identity) CSRPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: id.CSRDER})
}

// Save writes the key (0600) and CSR into dir (created 0700). Without
// overwrite it refuses to replace an existing key.
func (id *Identity) Save(dir string, overwrite bool) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("enroll: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("enroll: %w", err)
	}
	if !overwrite {
		if _, err := os.Stat(filepath.Join(dir, KeyFile)); err == nil {
			return fmt.Errorf("%w in %s (use --force to replace it)", ErrExists, dir)
		}
	}
	der, err := x509.MarshalPKCS8PrivateKey(id.Key)
	if err != nil {
		return fmt.Errorf("enroll: %w", err)
	}
	if err := writeFile(dir, KeyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return err
	}
	return writeFile(dir, CSRFile, id.CSRPEM(), 0o644)
}

// writeFile replaces dir/name atomically: a temporary file, fsync, rename,
// fsync of the directory.
func writeFile(dir, name string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(dir, "."+name+".*")
	if err != nil {
		return fmt.Errorf("enroll: %w", err)
	}
	defer os.Remove(tmp.Name()) // no-op after the rename
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return fmt.Errorf("enroll: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("enroll: write %s: %w", name, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("enroll: sync %s: %w", name, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("enroll: %w", err)
	}
	if err := os.Rename(tmp.Name(), filepath.Join(dir, name)); err != nil {
		return fmt.Errorf("enroll: %w", err)
	}
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("enroll: %w", err)
	}
	defer d.Close()
	return d.Sync()
}

// Options of a real enrollment.
type Options struct {
	Server     string // control plane host:port (FleetService)
	ServerName string // TLS name; default: host of Server
	CAFile     string // CA trusted for the control plane before enrollment
	Token      string
	Node       *fleetv1.NodeInfo
	Timeout    time.Duration
}

// Enroll sends the CSR with the token and stores what the control plane
// returns next to the key. The token is never logged or stored.
func Enroll(ctx context.Context, dir string, id *Identity, opt Options) (*fleetv1.EnrollResponse, error) {
	if opt.Server == "" || opt.Token == "" || opt.CAFile == "" {
		return nil, errors.New("enroll: server, token and CA are required")
	}
	pemCA, err := os.ReadFile(opt.CAFile)
	if err != nil {
		return nil, fmt.Errorf("enroll: read CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemCA) {
		return nil, fmt.Errorf("enroll: no certificate in %s", opt.CAFile)
	}
	tlsCfg := &tls.Config{RootCAs: pool, ServerName: opt.ServerName, MinVersion: tls.VersionTLS13}
	conn, err := grpc.NewClient(opt.Server, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	if err != nil {
		return nil, fmt.Errorf("enroll: %w", err)
	}
	defer conn.Close()
	if opt.Timeout <= 0 {
		opt.Timeout = 30 * time.Second
	}
	cctx, cancel := context.WithTimeout(ctx, opt.Timeout)
	defer cancel()
	resp, err := fleetv1.NewFleetServiceClient(conn).Enroll(cctx, &fleetv1.EnrollRequest{
		Token: opt.Token, Csr: id.CSRDER, Node: opt.Node,
	})
	if err != nil {
		return nil, fmt.Errorf("enroll: %w", err)
	}
	if err := checkCertificate(resp.GetCertificate(), &id.Key.PublicKey, resp.GetNodeId()); err != nil {
		return nil, err
	}
	for _, f := range []struct {
		name string
		data []byte
	}{
		{CertFile, resp.GetCertificate()},
		{CAFile, resp.GetCaBundle()},
		{BundleKeyFile, resp.GetBundlePubkey()},
		{NodeIDFile, []byte(resp.GetNodeId() + "\n")},
	} {
		if err := writeFile(dir, f.name, f.data, 0o644); err != nil {
			return nil, err
		}
	}
	return resp, nil
}

// checkCertificate refuses a certificate that is not for our key or does
// not name the node id it came with.
func checkCertificate(certPEM []byte, pub *ecdsa.PublicKey, nodeID string) error {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return errors.New("enroll: the control plane returned no PEM certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("enroll: certificate: %w", err)
	}
	got, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !got.Equal(pub) {
		return errors.New("enroll: the certificate is not for this node's key")
	}
	want := "spiffe://strata/node/" + nodeID
	for _, u := range cert.URIs {
		if u.String() == want {
			return nil
		}
	}
	return fmt.Errorf("enroll: the certificate does not name %s", want)
}
