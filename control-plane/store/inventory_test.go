package store_test

import (
	"context"
	"errors"
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

func TestInventoryCompatibilityBeforeRolloutInPostgres(t *testing.T) {
	pool := migratedPool(t)
	s := store.New(pool)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `INSERT INTO connector_groups (id,name) VALUES ('edge','Edge'); INSERT INTO nodes (id,group_id) VALUES ('node-a','edge')`); err != nil {
		t.Fatal(err)
	}
	_, err := s.RecordBundle(ctx, store.Bundle{Version: 1, SizeBytes: 1, SHA256: make([]byte, 32), ObjectKey: "bundles/1", RequiredCapabilities: []string{"section.9"}}, store.Audit{Actor: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.CreateRollout(ctx, 1, []string{"node-a"}, nil, 0, store.Audit{Actor: "test"}); !errors.Is(err, store.ErrIncompatible) {
		t.Fatalf("missing capabilities: %v", err)
	}
	var count int
	if err = pool.QueryRow(ctx, "SELECT count(*) FROM rollouts").Scan(&count); err != nil || count != 0 {
		t.Fatalf("rejected rollout mutated: %d %v", count, err)
	}
	inv := store.Inventory{AgentVersion: "test", OS: "linux/amd64", ABI: 0x10008, Capabilities: []string{"section.9"}}
	if err = s.RecordInventory(ctx, "node-a", inv, time.Now()); err != nil {
		t.Fatal(err)
	}
	n, err := s.GetNode(ctx, "node-a")
	if err != nil || n.Inventory.OS != inv.OS || n.InventoryAt == nil {
		t.Fatalf("inventory lost: %+v %v", n, err)
	}
	if _, _, err = s.CreateRollout(ctx, 1, []string{"node-a"}, nil, 0, store.Audit{Actor: "test"}); err != nil {
		t.Fatal(err)
	}
	if err = s.RecordInventory(ctx, "node-a", store.Inventory{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.CreateRollout(ctx, 1, []string{"node-a"}, nil, 0, store.Audit{Actor: "test"}); !errors.Is(err, store.ErrIncompatible) {
		t.Fatal(err)
	}
	if _, err = s.DesiredBundle(ctx, "node-a"); !errors.Is(err, store.ErrIncompatible) {
		t.Fatalf("late downgrade can fetch: %v", err)
	}
	var state string
	if err = pool.QueryRow(ctx, "SELECT state FROM rollouts").Scan(&state); err != nil || state != "RUNNING" {
		t.Fatalf("previous rollout changed: %s %v", state, err)
	}
}
