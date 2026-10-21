package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDiscoveryRequiresApprovalPrivateKeyAndMachineCollector(t *testing.T) {
	if gate, err := loadDiscoveryGate(false, "", "", "", ""); err != nil || gate.Approved(time.Now()) {
		t.Fatal("default enabled", err)
	}
	dir := t.TempDir()
	key := filepath.Join(dir, "discovery.key")
	if err := os.WriteFile(key, []byte(strings.Repeat("12", 32)), 0600); err != nil {
		t.Fatal(err)
	}
	expiry := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	gate, err := loadDiscoveryGate(true, "synthetic-approval-only", expiry, "sa:example-collector", key)
	if err != nil || !gate.Approved(time.Now()) {
		t.Fatal("valid synthetic gate", err)
	}
	for _, v := range []struct{ ref, expiry, collector, key string }{{"", expiry, "sa:example", key}, {"synthetic", time.Now().Add(-time.Hour).UTC().Format(time.RFC3339), "sa:example", key}, {"synthetic", expiry, "oidc:operator", key}, {"synthetic", expiry, "sa:example", filepath.Join(dir, "missing")}} {
		if _, err := loadDiscoveryGate(true, v.ref, v.expiry, v.collector, v.key); err == nil {
			t.Fatal("incomplete gate enabled")
		}
	}
	if err := os.Chmod(key, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadDiscoveryGate(true, "synthetic", expiry, "sa:example", key); err == nil {
		t.Fatal("world-readable key accepted")
	}
}
