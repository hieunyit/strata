package fleet

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"time"
)

// CertLifetime of node certificates (nginx-module.md › Đăng ký node).
const CertLifetime = 24 * time.Hour

// CA signs node certificates.
type CA struct {
	cert    *x509.Certificate
	key     crypto.Signer
	certPEM []byte
	now     func() time.Time
}

// LoadCA reads the node CA's certificate and key (PEM).
func LoadCA(certFile, keyFile string) (*CA, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("fleet: node CA: %w", err)
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("fleet: node CA key: %w", err)
	}
	return NewCA(certPEM, keyPEM)
}

// NewCA builds a CA from PEM data.
func NewCA(certPEM, keyPEM []byte) (*CA, error) {
	cb, _ := pem.Decode(certPEM)
	if cb == nil {
		return nil, errors.New("fleet: node CA: no certificate")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("fleet: node CA: %w", err)
	}
	if !cert.IsCA {
		return nil, errors.New("fleet: node CA certificate is not a CA")
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return nil, errors.New("fleet: node CA key: no key")
	}
	var key any
	switch kb.Type {
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(kb.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(kb.Bytes)
	default:
		key, err = x509.ParsePKCS8PrivateKey(kb.Bytes)
	}
	if err != nil {
		return nil, fmt.Errorf("fleet: node CA key: %w", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("fleet: node CA key cannot sign")
	}
	return &CA{cert: cert, key: signer, certPEM: certPEM, now: time.Now}, nil
}

// CertPEM is the CA certificate, sent to agents as the node CA.
func (c *CA) CertPEM() []byte { return c.certPEM }

// checkCSR accepts a correctly signed CSR for a key Strata considers strong.
func checkCSR(der []byte) (*x509.CertificateRequest, error) {
	if len(der) == 0 || len(der) > 16<<10 {
		return nil, errors.New("CSR missing or too large")
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, fmt.Errorf("CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature: %w", err)
	}
	switch k := csr.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() && k.Curve != elliptic.P384() {
			return nil, errors.New("CSR: ECDSA key must be P-256 or P-384")
		}
	case ed25519.PublicKey:
	case *rsa.PublicKey:
		if k.N.BitLen() < 3072 {
			return nil, errors.New("CSR: RSA key shorter than 3072 bits")
		}
	default:
		return nil, errors.New("CSR: unsupported key type")
	}
	return csr, nil
}

// Sign issues a client certificate for the CSR's key naming
// spiffe://strata/node/<nodeID>. Whatever names the CSR asks for are
// ignored: the control plane decides the identity.
func (c *CA) Sign(csrDER []byte, nodeID string) (certPEM []byte, serial string, notAfter time.Time, err error) {
	csr, err := checkCSR(csrDER)
	if err != nil {
		return nil, "", time.Time{}, err
	}
	sn, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, "", time.Time{}, err
	}
	u, err := url.Parse(spiffePrefix + nodeID)
	if err != nil {
		return nil, "", time.Time{}, err
	}
	now := c.now()
	notAfter = now.Add(CertLifetime)
	if notAfter.After(c.cert.NotAfter) {
		return nil, "", time.Time{}, errors.New("fleet: node CA expires before the certificate would")
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: sn,
		Subject:      pkix.Name{CommonName: nodeID},
		URIs:         []*url.URL{u},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, c.cert, csr.PublicKey, c.key)
	if err != nil {
		return nil, "", time.Time{}, fmt.Errorf("fleet: sign: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), sn.Text(16), notAfter, nil
}
