package localauth

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// TrustedProxies are the reverse proxies whose X-Forwarded-For gives the
// client IP of a login (throttling and the audit log). Entries are CIDRs,
// addresses, or host names: a name (the UI container of a compose stack,
// "ui") is resolved again every refresh, so a proxy that restarts with
// another address stays trusted, and only it.
type TrustedProxies struct {
	prefixes []netip.Prefix
	hosts    []string
	lookup   func(ctx context.Context, host string) ([]netip.Addr, error)

	mu       sync.RWMutex
	resolved []netip.Addr
}

// ParseTrustedProxies reads a comma-separated list; empty gives nil (no
// proxy is trusted).
func ParseTrustedProxies(list string) (*TrustedProxies, error) {
	p := &TrustedProxies{lookup: func(ctx context.Context, host string) ([]netip.Addr, error) {
		return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	}}
	for _, e := range strings.Split(list, ",") {
		e = strings.TrimSpace(e)
		switch {
		case e == "":
			continue
		case strings.Contains(e, "/"):
			pfx, err := netip.ParsePrefix(e)
			if err != nil {
				return nil, fmt.Errorf("trusted proxy %q: %w", e, err)
			}
			p.prefixes = append(p.prefixes, pfx.Masked())
		default:
			if a, err := netip.ParseAddr(e); err == nil {
				p.prefixes = append(p.prefixes, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
			} else if validHost(e) {
				p.hosts = append(p.hosts, e)
			} else {
				return nil, fmt.Errorf("trusted proxy %q: not a CIDR, an address or a host name", e)
			}
		}
	}
	if len(p.prefixes) == 0 && len(p.hosts) == 0 {
		return nil, nil
	}
	return p, nil
}

func validHost(h string) bool {
	if len(h) > 253 {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			alnum := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
			if !alnum && c != '-' {
				return false
			}
		}
	}
	return true
}

// Refresh resolves the host names again. A name that does not resolve
// (the proxy is down) is trusted for no address until it does.
func (p *TrustedProxies) Refresh(ctx context.Context) {
	if p == nil || len(p.hosts) == 0 {
		return
	}
	var addrs []netip.Addr
	for _, h := range p.hosts {
		rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		as, err := p.lookup(rctx, h)
		cancel()
		if err != nil {
			log.Printf("[WARN] trusted proxy %q does not resolve: %v", h, err)
			continue
		}
		for _, a := range as {
			addrs = append(addrs, a.Unmap())
		}
	}
	p.mu.Lock()
	p.resolved = addrs
	p.mu.Unlock()
}

// Run refreshes the names now and every interval until ctx ends.
func (p *TrustedProxies) Run(ctx context.Context, every time.Duration) {
	if p == nil || len(p.hosts) == 0 {
		return
	}
	p.Refresh(ctx)
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				p.Refresh(ctx)
			}
		}
	}()
}

// Contains tells whether addr is a trusted proxy.
func (p *TrustedProxies) Contains(addr netip.Addr) bool {
	if p == nil {
		return false
	}
	addr = addr.Unmap()
	for _, pfx := range p.prefixes {
		if pfx.Contains(addr) {
			return true
		}
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, a := range p.resolved {
		if a == addr {
			return true
		}
	}
	return false
}
