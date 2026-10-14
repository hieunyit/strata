// Package stats holds the tests the automatic fallback shares between the
// node tier (agent) and the cluster tier (control plane).
package stats

import (
	"math"
	"net/netip"
)

// PoissonTail is P(X >= k) for X ~ Poisson(lambda): how likely a count of
// at least k is when lambda is expected (#65, #74).
func PoissonTail(k uint64, lambda float64) float64 {
	if k == 0 {
		return 1
	}
	if lambda <= 0 {
		return 0
	}
	lg, _ := math.Lgamma(float64(k) + 1)
	term := math.Exp(-lambda + float64(k)*math.Log(lambda) - lg)
	sum := 0.0
	for i := k; term > sum*1e-15 && i < k+100000; i++ {
		sum += term
		term *= lambda / float64(i+1)
	}
	return min(sum, 1)
}

// SourceKey: a client address as the fallback counts it, IPv6 by /64 (one
// host easily has many addresses of its /64); anything else as it is.
func SourceKey(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	a = a.Unmap()
	if a.Is6() {
		p, _ := a.Prefix(64)
		return p.String()
	}
	return a.String()
}
