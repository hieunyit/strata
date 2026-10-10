package ingest

import (
	"sync"
	"time"
)

type nodeState struct {
	lastSeq    uint64
	lastActive time.Time
}

// NodeDeduplicator tracks sequence numbers per node_id to prevent duplicate batch processing.
type NodeDeduplicator struct {
	mu         sync.RWMutex
	nodes      map[string]*nodeState
	ttl        time.Duration
	stopPruner chan struct{}
}

// NewNodeDeduplicator initializes a new deduplicator with node TTL.
func NewNodeDeduplicator(ttl time.Duration) *NodeDeduplicator {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	d := &NodeDeduplicator{
		nodes:      make(map[string]*nodeState),
		ttl:        ttl,
		stopPruner: make(chan struct{}),
	}
	return d
}

// CheckBatch checks whether a batch with nodeID and seq is a duplicate.
// Returns (isDuplicate, lastCommittedSeq).
func (d *NodeDeduplicator) CheckBatch(nodeID string, seq uint64) (bool, uint64) {
	d.mu.RLock()
	state, exists := d.nodes[nodeID]
	if !exists {
		d.mu.RUnlock()
		return false, 0
	}
	lastSeq := state.lastSeq
	d.mu.RUnlock()

	// If received seq is <= last committed seq, it has already been processed.
	if seq <= lastSeq {
		return true, lastSeq
	}
	return false, lastSeq
}

// Commit records that the batch with nodeID and seq has been processed.
func (d *NodeDeduplicator) Commit(nodeID string, seq uint64) {
	d.mu.Lock()
	defer d.mu.Unlock()

	state, exists := d.nodes[nodeID]
	if !exists {
		d.nodes[nodeID] = &nodeState{
			lastSeq:    seq,
			lastActive: time.Now(),
		}
		return
	}

	if seq > state.lastSeq {
		state.lastSeq = seq
	}
	state.lastActive = time.Now()
}

// GetLastSeq returns the last committed sequence number for nodeID.
func (d *NodeDeduplicator) GetLastSeq(nodeID string) uint64 {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if state, ok := d.nodes[nodeID]; ok {
		return state.lastSeq
	}
	return 0
}

// Prune removes inactive nodes that have not sent batches within TTL.
func (d *NodeDeduplicator) Prune(now time.Time) int {
	d.mu.Lock()
	defer d.mu.Unlock()

	removed := 0
	for id, state := range d.nodes {
		if now.Sub(state.lastActive) > d.ttl {
			delete(d.nodes, id)
			removed++
		}
	}
	return removed
}

// Close stops any background routines if present.
func (d *NodeDeduplicator) Close() {
	select {
	case <-d.stopPruner:
	default:
		close(d.stopPruner)
	}
}
