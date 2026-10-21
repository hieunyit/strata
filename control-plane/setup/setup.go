// Package setup makes what a new control plane needs on disk (CP-A05,
// `strata-control-plane init`): the PKI (a CA and the control plane's
// certificate for Fleet mTLS, the node CA that signs agents' certificates),
// the bundle signing key, and a configuration file. Everything is created
// only when missing and never overwritten: running it again reports what
// exists.
package setup

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// Layout of a data directory.
const (
	PKIDir       = "pki"
	KeysDir      = "keys"
	SecretsDir   = "secrets"
	ObjectsDir   = "objects"                 // artifacts without an object store (CP-A07)
	BundleKey    = "keys/bundle-signing.key" // Ed25519 seed, 32 bytes
	BundlePub    = "keys/bundle.pub"         // Ed25519 public key, 32 bytes
	CACert       = "pki/ca.pem"
	CAKey        = "pki/ca-key.pem"
	ServerCert   = "pki/cp.pem"
	ServerKey    = "pki/cp-key.pem"
	NodeCACert   = "pki/node-ca.pem"
	NodeCAKey    = "pki/node-ca-key.pem"
	ConfigFile   = "config.yaml"
	DSNFile      = "secrets/postgres-dsn"
	CHPassword   = "secrets/clickhouse-password"
	lockFile     = ".init.lock"
	caLifetime   = 10 * 365 * 24 * time.Hour
	certLifetime = 365 * 24 * time.Hour
)

// Result says what init created and what it found already there.
type Result struct {
	Created []string
	Kept    []string
}

func (r *Result) add(created bool, path string) {
	if created {
		r.Created = append(r.Created, path)
	} else {
		r.Kept = append(r.Kept, path)
	}
}

// Lock takes an exclusive lock on dir for the length of init: two inits
// at once would make two different keys. Release with the returned func.
func Lock(dir string) (func(), error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, lockFile), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("setup: another init runs on %s", dir)
	}
	return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }, nil
}

func exists(path string) (bool, error) {
	_, err := os.Lstat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}

// writeNew creates path with data and mode, failing if it exists (O_EXCL:
// a concurrent writer or a file created meanwhile is never overwritten).
func writeNew(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func pemOf(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

func newKey() (*ecdsa.PrivateKey, []byte, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, nil, err
	}
	return k, pemOf("PRIVATE KEY", der), nil
}

func serial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 126))
}

func selfSigned(cn string, pathLen int, now time.Time) (*x509.Certificate, *ecdsa.PrivateKey, []byte, []byte, error) {
	k, keyPEM, err := newKey()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	tmpl := &x509.Certificate{SerialNumber: sn, Subject: pkix.Name{CommonName: cn}, NotBefore: now.Add(-time.Hour),
		NotAfter: now.Add(caLifetime), IsCA: true, BasicConstraintsValid: true, MaxPathLen: pathLen, MaxPathLenZero: pathLen == 0,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	return cert, k, pemOf("CERTIFICATE", der), keyPEM, err
}

// PKI makes the CA and the control plane's server certificate (for names:
// DNS names or IP addresses agents use to reach Fleet), and the node CA,
// each pair only when its certificate is missing. A pair half present (a
// certificate without its key or the reverse) is an error, not repaired.
func PKI(dir string, names []string, now time.Time, r *Result) error {
	if len(names) == 0 {
		return errors.New("setup: the control plane needs at least one name for its certificate")
	}
	pair := func(cert, key string) (bool, error) {
		c, err := exists(filepath.Join(dir, cert))
		if err != nil {
			return false, err
		}
		k, err := exists(filepath.Join(dir, key))
		if err != nil {
			return false, err
		}
		if c != k {
			return false, fmt.Errorf("setup: %s and %s must both exist or both be missing", cert, key)
		}
		return c, nil
	}
	have, err := pair(CACert, CAKey)
	if err != nil {
		return err
	}
	haveServer, err := pair(ServerCert, ServerKey)
	if err != nil {
		return err
	}
	if have != haveServer {
		return fmt.Errorf("setup: %s and %s go together: remove both to make them again", CACert, ServerCert)
	}
	if !have {
		ca, caKey, caPEM, caKeyPEM, err := selfSigned("strata control plane CA", 1, now)
		if err != nil {
			return err
		}
		k, keyPEM, err := newKey()
		if err != nil {
			return err
		}
		sn, err := serial()
		if err != nil {
			return err
		}
		tmpl := &x509.Certificate{SerialNumber: sn, Subject: pkix.Name{CommonName: names[0]}, NotBefore: now.Add(-time.Hour),
			NotAfter: now.Add(certLifetime), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		for _, n := range names {
			if ip := net.ParseIP(n); ip != nil {
				tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
			} else {
				tmpl.DNSNames = append(tmpl.DNSNames, n)
			}
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &k.PublicKey, caKey)
		if err != nil {
			return err
		}
		for _, w := range []struct {
			path string
			data []byte
			mode os.FileMode
		}{{CAKey, caKeyPEM, 0o600}, {CACert, caPEM, 0o644}, {ServerKey, keyPEM, 0o600}, {ServerCert, pemOf("CERTIFICATE", der), 0o644}} {
			if err := writeNew(filepath.Join(dir, w.path), w.data, w.mode); err != nil {
				return err
			}
		}
	}
	r.add(!have, CACert)
	r.add(!have, ServerCert)

	haveNode, err := pair(NodeCACert, NodeCAKey)
	if err != nil {
		return err
	}
	if !haveNode {
		_, _, certPEM, keyPEM, err := selfSigned("strata node CA", 0, now)
		if err != nil {
			return err
		}
		if err := writeNew(filepath.Join(dir, NodeCAKey), keyPEM, 0o600); err != nil {
			return err
		}
		if err := writeNew(filepath.Join(dir, NodeCACert), certPEM, 0o644); err != nil {
			return err
		}
	}
	r.add(!haveNode, NodeCACert)
	return nil
}

// ErrSigningKeyLost: bundles exist but the signing key is gone. A new key
// would sign bundles the nodes do not trust; restore the key from backup
// (or rotate it the documented way) instead.
var ErrSigningKeyLost = errors.New("setup: bundles were deployed with a signing key that is missing; restore it from backup, never make a new one here")

// BundleKeys makes the Ed25519 bundle signing key (raw 32-byte seed) and
// its public key when both are missing. bundlesExist (deploys were already
// recorded) with no key is ErrSigningKeyLost.
func BundleKeys(dir string, bundlesExist bool, r *Result) error {
	seed, pub := filepath.Join(dir, BundleKey), filepath.Join(dir, BundlePub)
	hs, err := exists(seed)
	if err != nil {
		return err
	}
	hp, err := exists(pub)
	if err != nil {
		return err
	}
	switch {
	case hs && hp:
		r.add(false, BundleKey)
		return nil
	case hs != hp:
		return fmt.Errorf("setup: %s and %s must both exist or both be missing", BundleKey, BundlePub)
	case bundlesExist:
		return ErrSigningKeyLost
	}
	pubKey, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := writeNew(seed, key.Seed(), 0o600); err != nil {
		return err
	}
	if err := writeNew(pub, pubKey, 0o644); err != nil {
		return err
	}
	r.add(true, BundleKey)
	return nil
}

// Config writes a configuration file for this data directory when there is
// none: local accounts, the generated PKI and signing key, the DSN and
// ClickHouse password from secret files, artifacts in s3Endpoint or, when
// empty, in ObjectsDir.
func Config(dir, clickhouse, s3Endpoint string, r *Result) error {
	path := filepath.Join(dir, ConfigFile)
	ok, err := exists(path)
	if err != nil || ok {
		r.add(false, ConfigFile)
		return err
	}
	var b strings.Builder
	fmt.Fprintf(&b, `# Made by strata-control-plane init (CP-A05). See control-plane/config/example.yaml.
version: 1

server:
  fleet:
    listen: ":8443"
    tls_ca: %s
    tls_cert: %s
    tls_key: %s
    node_ca_cert: %s
    node_ca_key: %s
  single_control_plane: true

database:
  dsn_file: %s

auth:
  local:
    enabled: true
    mfa_key_file: keys/local-mfa.key

events:
  clickhouse:
    address: %q
    password_file: %s

bundles:
  signer:
    type: file
    key_file: %s
    public_key: %s
`, CACert, ServerCert, ServerKey, NodeCACert, NodeCAKey, DSNFile, clickhouse, CHPassword, BundleKey, BundlePub)
	if s3Endpoint != "" {
		fmt.Fprintf(&b, "  storage:\n    s3:\n      endpoint: %q\n", s3Endpoint)
	} else {
		fmt.Fprintf(&b, "  storage:\n    local:\n      path: %s\n", ObjectsDir)
	}
	if err := writeNew(path, []byte(b.String()), 0o600); err != nil {
		return err
	}
	r.add(true, ConfigFile)
	return nil
}

// Secret writes a secret file (0600) when it is missing and value is set.
func Secret(dir, rel, value string, r *Result) error {
	path := filepath.Join(dir, rel)
	ok, err := exists(path)
	if err != nil {
		return err
	}
	if ok {
		r.add(false, rel)
		return nil
	}
	if value == "" {
		return nil
	}
	if err := writeNew(path, []byte(value+"\n"), 0o600); err != nil {
		return err
	}
	r.add(true, rel)
	return nil
}
