package apidiscovery

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestNormalizeDedicatedSuccessPrivacyAndEligibility(t *testing.T) {
	now := time.Now().UTC()
	key := bytes.Repeat([]byte{7}, 32)
	v := Observation{ID: "00000000-0000-0000-0000-000000000001", RouteID: "api", Method: "POST", Path: "/api/users/alice@example.test/orders/123?token=private", ContentType: "application/json; charset=utf-8", BodyBytes: 420, BackendStatus: 201, BackendResponse: true, SourceIP: "198.51.100.47", At: now}
	got, err := Normalize(v, key, "example-api/test", now)
	if err != nil || got.Path != "/api/users/{param1}/orders/{param2}" || got.ContentType != "application/json" || len(got.Source) != 64 {
		t.Fatalf("normalization %+v %v", got, err)
	}
	if path, err := NormalizePath("/api/users/admin"); err != nil || path != "/api/users/{param1}" {
		t.Fatal("resource identifier leaked", path, err)
	}
	retry, _ := Normalize(v, key, "example-api/test", now)
	if retry.Source != got.Source {
		t.Fatal("unstable source")
	}
	other, _ := Normalize(v, key, "other/test", now)
	if other.Source == got.Source {
		t.Fatal("cross tenant source correlation")
	}
	for _, change := range []func(*Observation){func(v *Observation) { v.BackendStatus = 403 }, func(v *Observation) { v.BackendResponse = false }, func(v *Observation) { v.SourceIP = "invalid" }, func(v *Observation) { v.At = now.Add(-25 * time.Hour) }, func(v *Observation) { v.BodyBytes = 17 << 20 }, func(v *Observation) { v.Method = "TRACE" }} {
		bad := v
		change(&bad)
		if _, err := Normalize(bad, key, "scope", now); err == nil {
			t.Fatal("ineligible sample accepted")
		}
	}
	for _, bad := range []string{"/api/../private", "/api//users", "/api/%zz", "/api/\nsecret", "/" + strings.Repeat("x/", 40)} {
		if _, err := NormalizePath(bad); err == nil {
			t.Fatalf("path accepted %q", bad)
		}
	}
	gate := Gate{Enabled: true, ApprovalReference: "approval-example", ApprovalExpires: now.Add(time.Hour), TrustedCollectors: map[string]bool{"sa:example": true}, Key: key}
	if !gate.Approved(now) || gate.Approved(now.Add(2*time.Hour)) {
		t.Fatal("legal expiry gate")
	}
	gate.Enabled = false
	if gate.Approved(now) {
		t.Fatal("collection not opt in")
	}
}
