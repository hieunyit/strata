package ingest

import (
	"context"
	"testing"
	"time"
)

func TestNodeDeduplicator(t *testing.T) {
	d := NewNodeDeduplicator(1 * time.Hour)
	defer d.Close()

	ctx := context.Background()
	nodeA := "node-alpha"
	nodeB := "node-beta"

	// 1. Initial batch from nodeA with seq 1
	isDup, lastSeq := d.CheckBatch(ctx, nodeA, 1)
	if isDup {
		t.Errorf("expected batch seq 1 to not be duplicate")
	}
	if lastSeq != 0 {
		t.Errorf("expected lastSeq 0, got %d", lastSeq)
	}

	// Commit batch 1
	d.Commit(ctx, nodeA, 1)
	if d.GetLastSeq(nodeA) != 1 {
		t.Errorf("expected lastSeq 1, got %d", d.GetLastSeq(nodeA))
	}

	// 2. Duplicate batch from nodeA with seq 1
	isDup, lastSeq = d.CheckBatch(ctx, nodeA, 1)
	if !isDup {
		t.Errorf("expected batch seq 1 to be detected as duplicate")
	}
	if lastSeq != 1 {
		t.Errorf("expected lastSeq 1, got %d", lastSeq)
	}

	// 3. Stale batch with seq 0
	isDup, _ = d.CheckBatch(ctx, nodeA, 0)
	if !isDup {
		t.Errorf("expected batch seq 0 to be detected as duplicate")
	}

	// 4. Newer batch with seq 2
	isDup, _ = d.CheckBatch(ctx, nodeA, 2)
	if isDup {
		t.Errorf("expected batch seq 2 to not be duplicate")
	}
	d.Commit(ctx, nodeA, 2)
	if d.GetLastSeq(nodeA) != 2 {
		t.Errorf("expected lastSeq 2, got %d", d.GetLastSeq(nodeA))
	}

	// 5. Independent nodeB with seq 1 should not conflict with nodeA
	isDup, _ = d.CheckBatch(ctx, nodeB, 1)
	if isDup {
		t.Errorf("expected nodeB seq 1 to not be duplicate")
	}
	d.Commit(ctx, nodeB, 1)
	if d.GetLastSeq(nodeB) != 1 {
		t.Errorf("expected nodeB lastSeq 1, got %d", d.GetLastSeq(nodeB))
	}

	// 6. Prune expired nodes
	future := time.Now().Add(2 * time.Hour)
	removed := d.Prune(future)
	if removed != 2 {
		t.Errorf("expected 2 nodes pruned, got %d", removed)
	}
	if d.GetLastSeq(nodeA) != 0 {
		t.Errorf("expected nodeA to be pruned")
	}
}

func TestNodeDeduplicator_PersistenceAcrossRestart(t *testing.T) {
	ctx := context.Background()
	store := NewMockEventStore()

	// Instance 1 commits sequence 42
	d1 := NewNodeDeduplicatorWithStore(1*time.Hour, store)
	nodeID := "edge-node-99"

	isDup, lastSeq := d1.CheckBatch(ctx, nodeID, 42)
	if isDup || lastSeq != 0 {
		t.Fatalf("expected not duplicate, got isDup=%v lastSeq=%d", isDup, lastSeq)
	}
	d1.Commit(ctx, nodeID, 42)
	d1.Close()

	// Instance 2 simulates process restart with same persistent store
	d2 := NewNodeDeduplicatorWithStore(1*time.Hour, store)
	defer d2.Close()

	// Old sequence 40 should be flagged as duplicate
	isDup, lastSeq = d2.CheckBatch(ctx, nodeID, 40)
	if !isDup || lastSeq != 42 {
		t.Errorf("expected duplicate detected from store, got isDup=%v lastSeq=%d", isDup, lastSeq)
	}

	// Exactly seq 42 should also be duplicate
	isDup, lastSeq = d2.CheckBatch(ctx, nodeID, 42)
	if !isDup || lastSeq != 42 {
		t.Errorf("expected duplicate for seq 42, got isDup=%v lastSeq=%d", isDup, lastSeq)
	}

	// New seq 43 should be accepted
	isDup, lastSeq = d2.CheckBatch(ctx, nodeID, 43)
	if isDup || lastSeq != 42 {
		t.Errorf("expected seq 43 accepted, got isDup=%v lastSeq=%d", isDup, lastSeq)
	}
}
