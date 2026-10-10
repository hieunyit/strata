//go:build soak

package agent

import (
	"testing"
	"time"

	"github.com/strata/strata/agent/internal/pusher"
)

// TestOutageTenMinutes is the "Xong khi" of W06-G1-01: the control plane
// is down for 10 minutes under 1,000 events/s with the production backoff
// (1 s -> 60 s), and no event is lost when it comes back.
//
//	go test -tags soak -run TestOutageTenMinutes -timeout 20m ./internal/agent/
func TestOutageTenMinutes(t *testing.T) {
	outage(t, 10*time.Minute, 1000, pusher.Options{BackoffMin: time.Second, BackoffMax: time.Minute})
}
