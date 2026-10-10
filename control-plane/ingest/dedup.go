package ingest

import (
	"context"
	"log"
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
	store      EventStore
	stopPruner chan struct{}
}

// NewNodeDeduplicator initializes a new deduplicator with node TTL.
func NewNodeDeduplicator(ttl time.Duration) *NodeDeduplicator {
	return NewNodeDeduplicatorWithStore(ttl, nil)
}

// NewNodeDeduplicatorWithStore initializes a deduplicator backed by an EventStore for persistent sequence watermarks.
func NewNodeDeduplicatorWithStore(ttl time.Duration, store EventStore) *NodeDeduplicator {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	d := &NodeDeduplicator{
		nodes:      make(map[string]*nodeState),
		ttl:        ttl,
		store:      store,
		stopPruner: make(chan struct{}),
	}
	return d
}

// CheckBatch checks whether a batch with nodeID and seq is a duplicate.
// If the node is not in memory, it queries the persistent store if available.
// Returns (isDuplicate, lastCommittedSeq).
func (d *NodeDeduplicator) CheckBatch(ctx context.Context, nodeID string, seq uint64) (bool, uint64) {
	d.mu.RLock()
	state, exists := d.nodes[nodeID]
	d.mu.RUnlock()

	if !exists {
		if d.store != nil {
			persistedSeq, err := d.store.GetNodeSeq(ctx, nodeID)
			if err != nil {
				log.Printf("[WARN] dedup: loading seq for node %q: %v", nodeID, err)
			}
			if err == nil && persistedSeq > 0 {
				d.mu.Lock()
				d.nodes[nodeID] = &nodeState{
					lastSeq:    persistedSeq,
					lastActive: time.Now(),
				}
				d.mu.Unlock()
				return seq <= persistedSeq, persistedSeq
			}
		}
		return false, 0
	}

	lastSeq := state.lastSeq
	if seq <= lastSeq {
		return true, lastSeq
	}
	return false, lastSeq
}

// Commit records that the batch with nodeID and seq has been processed.
// Also persists the sequence watermark to the store if available.
func (d *NodeDeduplicator) Commit(ctx context.Context, nodeID string, seq uint64) {
	d.mu.Lock()
	state, exists := d.nodes[nodeID]
	if !exists {
		d.nodes[nodeID] = &nodeState{
			lastSeq:    seq,
			lastActive: time.Now(),
		}
	} else {
		if seq > state.lastSeq {
			state.lastSeq = seq
		}
		state.lastActive = time.Now()
	}
	d.mu.Unlock()

	if d.store != nil {
		// The in-memory watermark still holds; a lost write only means a
		// resent batch after a control plane restart is stored twice.
		if err := d.store.SetNodeSeq(ctx, nodeID, seq); err != nil {
			log.Printf("[WARN] dedup: persisting seq %d for node %q: %v", seq, nodeID, err)
		}
	}
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
