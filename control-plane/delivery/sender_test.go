package delivery

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
)

type resolverFunc func(context.Context, string, string) ([]netip.Addr, error)

func (f resolverFunc) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return f(ctx, network, host)
}

func TestHTTPSHMACSSRFRedirectAndRebinding(t *testing.T) {
	var hits atomic.Int32
	key := bytes.Repeat([]byte{8}, 32)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		h := hmac.New(sha256.New, key)
		_, _ = h.Write([]byte(r.Header.Get("X-Strata-Timestamp") + "\n" + r.Header.Get("X-Strata-Delivery") + "\n"))
		_, _ = h.Write(body)
		if r.Header.Get("X-Strata-Signature") != "sha256="+hex.EncodeToString(h.Sum(nil)) {
			t.Error("invalid signature")
		}
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "https://169.254.169.254/metadata", http.StatusFound)
		} else {
			w.WriteHeader(204)
		}
	}))
	defer server.Close()
	tlsConfig := server.Client().Transport.(*http.Transport).TLSClientConfig
	blocked, err := New(Config{URL: server.URL, Key: key, TLS: tlsConfig})
	if err != nil {
		t.Fatal(err)
	}
	defer blocked.Close()
	if err := blocked.Send(context.Background(), "example-delivery", []byte(`{}`)); !errors.Is(err, ErrPermanent) {
		t.Fatal("loopback not blocked", err)
	}
	if hits.Load() != 0 {
		t.Fatal("SSRF reached receiver")
	}
	allow := []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}
	var lookups atomic.Int32
	resolver := resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
		if lookups.Add(1) == 1 {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("169.254.169.254")}, nil
	})
	s, err := New(Config{URL: server.URL, Key: key, TLS: tlsConfig, Allow: allow, Resolver: resolver})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Send(context.Background(), "example-delivery", []byte(`{"type":"audit"}`)); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if err := s.Send(context.Background(), "example-delivery", []byte(`{}`)); !errors.Is(err, ErrPermanent) {
		t.Fatal("rebound DNS accepted", err)
	}
	redirect, err := New(Config{URL: server.URL + "/redirect", Key: key, TLS: tlsConfig, Allow: allow})
	if err != nil {
		t.Fatal(err)
	}
	defer redirect.Close()
	if err := redirect.Send(context.Background(), "example-delivery", []byte(`{}`)); !errors.Is(err, ErrPermanent) {
		t.Fatal("redirect followed", err)
	}
	if hits.Load() != 2 {
		t.Fatal("unexpected receiver hits", hits.Load())
	}
	for _, bad := range []string{"http://example.test/", "https://user:pass@example.test/", "https://example.test/?token=secret", "https://example.test/#secret"} {
		if _, err := New(Config{URL: bad, Key: key}); err == nil {
			t.Fatal("unsafe URL", bad)
		}
	}
	for _, ip := range []string{"127.0.0.1", "::1", "::ffff:127.0.0.1", "169.254.169.254", "10.1.2.3", "192.168.1.1", "fc00::1", "100.64.0.1", "0.0.0.0"} {
		if allowed(netip.MustParseAddr(ip), nil) {
			t.Fatal("nonpublic allowed", ip)
		}
	}
	if !allowed(netip.MustParseAddr("8.8.8.8"), nil) {
		t.Fatal("public IP rejected")
	}
}
