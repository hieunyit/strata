// Package delivery sends bounded signed diagnostic copies to configured HTTPS
// receivers. Destination validation applies again to each connection's DNS result.
package delivery

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"time"
)

var ErrPermanent = errors.New("webhook: destination or request rejected")
var ErrUnavailable = errors.New("webhook: receiver unavailable")
var deliveryID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,80}$`)

type Resolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}
type Sender struct {
	endpoint string
	key      []byte
	client   *http.Client
	now      func() time.Time
}
type Config struct {
	URL      string
	Key      []byte
	Allow    []netip.Prefix
	Resolver Resolver
	TLS      *tls.Config
}

var nonPublic = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("240.0.0.0/4"), netip.MustParsePrefix("2001:db8::/32"),
}

func allowed(ip netip.Addr, allow []netip.Prefix) bool {
	ip = ip.Unmap()
	if !ip.IsValid() {
		return false
	}
	for _, p := range allow {
		if p.Contains(ip) {
			return true
		}
	}
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	for _, p := range nonPublic {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

func New(c Config) (*Sender, error) {
	u, err := url.Parse(c.URL)
	if err != nil || len(c.URL) > 2048 || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || len(c.Key) < 32 {
		return nil, ErrPermanent
	}
	if len(c.Allow) > 64 {
		return nil, ErrPermanent
	}
	if c.TLS != nil && c.TLS.InsecureSkipVerify {
		return nil, ErrPermanent
	}
	if c.TLS == nil {
		c.TLS = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		c.TLS = c.TLS.Clone()
		c.TLS.MinVersion = max(c.TLS.MinVersion, tls.VersionTLS12)
	}
	if c.Resolver == nil {
		c.Resolver = net.DefaultResolver
	}
	// Never honor proxy environment variables: the checked literal IP is dialed.
	t := &http.Transport{TLSClientConfig: c.TLS, ForceAttemptHTTP2: true, MaxIdleConns: 2, MaxConnsPerHost: 2, IdleConnTimeout: 30 * time.Second, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second, MaxResponseHeaderBytes: 16 << 10}
	t.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, ErrPermanent
		}
		addresses, err := c.Resolver.LookupNetIP(ctx, "ip", host)
		if err != nil || len(addresses) == 0 || len(addresses) > 32 {
			return nil, ErrUnavailable
		}
		for _, ip := range addresses {
			if !allowed(ip, c.Allow) {
				return nil, ErrPermanent
			}
		}
		dialer := net.Dialer{Timeout: 5 * time.Second}
		for _, ip := range addresses {
			conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.Unmap().String(), port))
			if err == nil {
				return conn, nil
			}
		}
		return nil, ErrUnavailable
	}
	return &Sender{endpoint: c.URL, key: append([]byte(nil), c.Key...), now: time.Now, client: &http.Client{Transport: t, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func Signature(key []byte, timestamp, id string, body []byte) string {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write([]byte(timestamp + "\n" + id + "\n"))
	_, _ = h.Write(body)
	return "sha256=" + hex.EncodeToString(h.Sum(nil))
}

func (s *Sender) Send(ctx context.Context, id string, body []byte) error {
	if !deliveryID.MatchString(id) || len(body) > 64<<10 {
		return ErrPermanent
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint, bytes.NewReader(body))
	if err != nil {
		return ErrPermanent
	}
	ts := strconv.FormatInt(s.now().Unix(), 10)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Strata-Delivery", id)
	request.Header.Set("X-Strata-Timestamp", ts)
	request.Header.Set("X-Strata-Signature", Signature(s.key, ts, id, body))
	response, err := s.client.Do(request)
	if err != nil {
		if errors.Is(err, ErrPermanent) {
			return ErrPermanent
		}
		return ErrUnavailable
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		return nil
	}
	if response.StatusCode == 429 || response.StatusCode >= 500 {
		return ErrUnavailable
	}
	return ErrPermanent
}

func (s *Sender) Close() { s.client.CloseIdleConnections() }
