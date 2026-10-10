// Package identity is the node's enrolled identity at run time: the
// certificate and key in the identity directory (written by enroll), served
// to TLS through GetClientCertificate so that a renewed certificate is used
// by new connections without a restart.
package identity

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/strata/strata/agent/internal/enroll"
)

// Identity is a loaded identity directory.
type Identity struct {
	Dir    string
	NodeID string
	CAPool *x509.CertPool // CAs trusted for the control plane
	pair   atomic.Pointer[tls.Certificate]
}

// Load reads dir, first finishing a renewal a crash interrupted.
func Load(dir string) (*Identity, error) {
	if err := finishRenewal(dir); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(filepath.Join(dir, enroll.NodeIDFile))
	if err != nil {
		return nil, fmt.Errorf("identity: not enrolled (%w); run strata-agent enroll", err)
	}
	id := &Identity{Dir: dir, NodeID: strings.TrimSpace(string(raw))}
	if id.NodeID == "" {
		return nil, errors.New("identity: empty node-id file")
	}
	caPEM, err := os.ReadFile(filepath.Join(dir, enroll.CAFile))
	if err != nil {
		return nil, fmt.Errorf("identity: %w", err)
	}
	id.CAPool = x509.NewCertPool()
	if !id.CAPool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("identity: no certificate in %s", enroll.CAFile)
	}
	pair, err := tls.LoadX509KeyPair(filepath.Join(dir, enroll.CertFile), filepath.Join(dir, enroll.KeyFile))
	if err != nil {
		return nil, fmt.Errorf("identity: %w", err)
	}
	if pair.Leaf == nil {
		if pair.Leaf, err = x509.ParseCertificate(pair.Certificate[0]); err != nil {
			return nil, fmt.Errorf("identity: %w", err)
		}
	}
	id.pair.Store(&pair)
	return id, nil
}

// Certificate is the current client certificate.
func (id *Identity) Certificate() *tls.Certificate { return id.pair.Load() }

// GetClientCertificate is a tls.Config callback.
func (id *Identity) GetClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return id.pair.Load(), nil
}

// RenewAt is when two thirds of the certificate's lifetime have passed
// (nginx-module.md: renewal with a third left).
func (id *Identity) RenewAt() time.Time {
	leaf := id.pair.Load().Leaf
	life := leaf.NotAfter.Sub(leaf.NotBefore)
	return leaf.NotBefore.Add(life * 2 / 3)
}

// Replace stores a renewed key and certificate and starts using them. The
// files are first written as .next, then renamed (key, then certificate),
// so a crash leaves either the old pair or something Load completes.
func (id *Identity) Replace(keyPEM, certPEM []byte) error {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("identity: renewed pair: %w", err)
	}
	if pair.Leaf, err = x509.ParseCertificate(pair.Certificate[0]); err != nil {
		return fmt.Errorf("identity: %w", err)
	}
	if err := enroll.WriteFile(id.Dir, enroll.KeyFile+".next", keyPEM, 0o600); err != nil {
		return err
	}
	if err := enroll.WriteFile(id.Dir, enroll.CertFile+".next", certPEM, 0o644); err != nil {
		return err
	}
	if err := finishRenewal(id.Dir); err != nil {
		return err
	}
	id.pair.Store(&pair)
	return nil
}

// finishRenewal moves node.key.next / node.crt.next into place when both
// are present and match; a half-written pair is discarded.
func finishRenewal(dir string) error {
	key, crt := filepath.Join(dir, enroll.KeyFile), filepath.Join(dir, enroll.CertFile)
	keyNext, crtNext := key+".next", crt+".next"
	_, kerr := os.Stat(keyNext)
	_, cerr := os.Stat(crtNext)
	switch {
	case kerr == nil && cerr == nil:
		if _, err := tls.LoadX509KeyPair(crtNext, keyNext); err != nil {
			// Not a usable pair: keep the current one.
			_ = os.Remove(keyNext)
			_ = os.Remove(crtNext)
			return nil
		}
		if err := os.Rename(keyNext, key); err != nil {
			return fmt.Errorf("identity: %w", err)
		}
		if err := os.Rename(crtNext, crt); err != nil {
			return fmt.Errorf("identity: %w", err)
		}
	case kerr != nil && cerr == nil:
		// The key was already moved; the certificate must follow.
		if _, err := tls.LoadX509KeyPair(crtNext, key); err == nil {
			if err := os.Rename(crtNext, crt); err != nil {
				return fmt.Errorf("identity: %w", err)
			}
		} else {
			_ = os.Remove(crtNext)
		}
	case kerr == nil && cerr != nil:
		_ = os.Remove(keyNext) // the certificate never got written
	}
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("identity: %w", err)
	}
	defer d.Close()
	return d.Sync()
}
