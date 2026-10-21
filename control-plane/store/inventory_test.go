package store_test

import (
	"strings"
	"testing"
	"time"

	"github.com/strata/strata/control-plane/store"
)

func TestInventoryValidationAndCertificateStatus(t *testing.T) {
	for _, i := range []store.Inventory{{AgentVersion: strings.Repeat("x", 129)}, {OS: "linux\n"}, {Capabilities: []string{"../escape"}}, {Capabilities: make([]string, 65)}} {
		if i.Validate() == nil {
			t.Errorf("accepted %+v", i)
		}
	}
	now := time.Now()
	past := now.Add(-time.Second)
	soon := now.Add(7 * 24 * time.Hour)
	later := soon.Add(time.Second)
	for _, tc := range []struct {
		at   *time.Time
		want string
	}{{nil, "unknown"}, {&past, "expired"}, {&soon, "expiring"}, {&later, "healthy"}} {
		if got := store.CertificateStatus(tc.at, now); got != tc.want {
			t.Errorf("%s != %s", got, tc.want)
		}
	}
}
