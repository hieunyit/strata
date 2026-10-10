package ingest

import (
	"testing"
	"time"
)

func TestNodeDeduplicator(t *testing.T) {
	d := NewNodeDeduplicator(1 * time.Hour)
	defer d.Close()

	nodeA := "node-alpha"
	nodeB := "node-beta"

	// 1. Initial batch from nodeA with seq 1
	isDup, lastSeq := d.CheckBatch(nodeA, 1)
	if isDup {
		t.Errorf("expected batch seq 1 to not be duplicate")
	}
	if lastSeq != 0 {
		t.Errorf("expected lastSeq 0, got %d", lastSeq)
	}

	// Commit batch 1
	d.Commit(nodeA, 1)
	if d.GetLastSeq(nodeA) != 1 {
		t.Errorf("expected lastSeq 1, got %d", d.GetLastSeq(nodeA))
	}

	// 2. Duplicate batch from nodeA with seq 1
	isDup, lastSeq = d.CheckBatch(nodeA, 1)
	if !isDup {
		t.Errorf("expected batch seq 1 to be detected as duplicate")
	}
	if lastSeq != 1 {
		t.Errorf("expected lastSeq 1, got %d", lastSeq)
	}

	// 3. Stale batch with seq 0
	isDup, _ = d.CheckBatch(nodeA, 0)
	if !isDup {
		t.Errorf("expected batch seq 0 to be detected as duplicate")
	}

	// 4. Newer batch with seq 2
	isDup, _ = d.CheckBatch(nodeA, 2)
	if isDup {
		t.Errorf("expected batch seq 2 to not be duplicate")
	}
	d.Commit(nodeA, 2)
	if d.GetLastSeq(nodeA) != 2 {
		t.Errorf("expected lastSeq 2, got %d", d.GetLastSeq(nodeA))
	}

	// 5. Independent nodeB with seq 1 should not conflict with nodeA
	isDup, _ = d.CheckBatch(nodeB, 1)
	if isDup {
		t.Errorf("expected nodeB seq 1 to not be duplicate")
	}
	d.Commit(nodeB, 1)
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
