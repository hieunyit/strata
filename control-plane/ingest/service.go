package ingest

import (
	"context"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"
)

// IngestStats provides aggregated metrics for the IngestService.
type IngestStats struct {
	TotalBatchesReceived uint64
	TotalBatchesAccepted uint64
	TotalBatchesDropped  uint64 // duplicate batches
	TotalEventsReceived  uint64
	TotalEventsValid     uint64
	TotalEventsInvalid   uint64
	TotalEventsFlushed   uint64
	BufferQueueLen       int
	InvalidEventsByNode  map[string]uint64
}

// IngestService coordinates deduplication, schema validation, batching, and persistence.
type IngestService struct {
	dedup   *NodeDeduplicator
	batcher *Batcher
	store   EventStore

	// Metrics
	batchesReceived atomic.Uint64
	batchesAccepted atomic.Uint64
	batchesDropped  atomic.Uint64
	eventsReceived  atomic.Uint64
	eventsValid     atomic.Uint64
	eventsInvalid   atomic.Uint64

	nodeMu              sync.RWMutex
	invalidEventsByNode map[string]uint64

	// nodeLocks serializes batches of one node (node id -> *sync.Mutex), so
	// an old and a new stream after a reconnect cannot both pass the seq
	// check before either commits.
	nodeLocks sync.Map
}

// NewIngestService creates a fully configured IngestService with persistent deduplication.
func NewIngestService(store EventStore, batcherCfg BatcherConfig, nodeTTL time.Duration) *IngestService {
	dedup := NewNodeDeduplicatorWithStore(nodeTTL, store)
	batcher := NewBatcher(batcherCfg, store)

	return &IngestService{
		dedup:               dedup,
		batcher:             batcher,
		store:               store,
		invalidEventsByNode: make(map[string]uint64),
	}
}

// ProcessBatch processes an incoming EventBatch from a connector/agent.
// It performs deduplication, schema validation, and persists events before returning ACK.
func (s *IngestService) ProcessBatch(ctx context.Context, batch EventBatch) (*EventAck, error) {
	s.batchesReceived.Add(1)
	s.eventsReceived.Add(uint64(len(batch.Events)))

	mu, _ := s.nodeLocks.LoadOrStore(batch.NodeID, &sync.Mutex{})
	mu.(*sync.Mutex).Lock()
	defer mu.(*sync.Mutex).Unlock()

	// 1. Deduplication check by sequence number (cached in RAM, backed by store)
	isDup, lastSeq := s.dedup.CheckBatch(ctx, batch.NodeID, batch.Seq)
	if isDup {
		s.batchesDropped.Add(1)
		// Return ACK for the duplicate batch so agent can clear its spool
		return &EventAck{
			NodeID:    batch.NodeID,
			AckedSeq:  batch.Seq,
			Success:   true,
			Duplicate: true,
		}, nil
	}

	// 2. Validate and normalize schema for each event
	now := time.Now().UTC()
	validEvents := make([]Event, 0, len(batch.Events))

	for i := range batch.Events {
		evt := &batch.Events[i]
		if err := ValidateEvent(evt, now); err != nil {
			s.eventsInvalid.Add(1)
			s.nodeMu.Lock()
			s.invalidEventsByNode[batch.NodeID]++
			s.nodeMu.Unlock()
			log.Printf("[WARN] IngestService: invalid event from node %q (seq %d, block_id %q): %v", batch.NodeID, batch.Seq, evt.BlockID, err)
			continue
		}
		s.eventsValid.Add(1)
		validEvents = append(validEvents, *evt)
	}

	// 3. Submit valid events and wait for persistence before acking!
	if len(validEvents) > 0 {
		if err := s.batcher.SubmitAndAwait(ctx, validEvents); err != nil {
			return &EventAck{
				NodeID:   batch.NodeID,
				AckedSeq: lastSeq,
				Success:  false,
				Error:    "failed to persist events: " + err.Error(),
			}, fmt.Errorf("persisting events: %w", err)
		}
	}

	// 4. Update sequence watermark ONLY after persistence succeeded!
	s.dedup.Commit(ctx, batch.NodeID, batch.Seq)
	s.batchesAccepted.Add(1)

	return &EventAck{
		NodeID:   batch.NodeID,
		AckedSeq: batch.Seq,
		Success:  true,
	}, nil
}

// StoreErrors counts the writes to the event store that failed.
func (s *IngestService) StoreErrors() uint64 {
	_, _, _, errs, _ := s.batcher.Stats()
	return errs
}

// Store returns the underlying EventStore.
func (s *IngestService) Store() EventStore {
	return s.store
}

// Flush triggers an immediate synchronous flush of all queued events.
func (s *IngestService) Flush(ctx context.Context) error {
	return s.batcher.Flush(ctx)
}

// Close gracefully stops the ingest service and flushes remaining buffers.
func (s *IngestService) Close(ctx context.Context) error {
	s.dedup.Close()
	return s.batcher.Close(ctx)
}

// Stats returns a snapshot of ingest metrics.
func (s *IngestService) Stats() IngestStats {
	_, flushed, _, _, qLen := s.batcher.Stats()

	s.nodeMu.RLock()
	nodeInvalid := make(map[string]uint64, len(s.invalidEventsByNode))
	for k, v := range s.invalidEventsByNode {
		nodeInvalid[k] = v
	}
	s.nodeMu.RUnlock()

	return IngestStats{
		TotalBatchesReceived: s.batchesReceived.Load(),
		TotalBatchesAccepted: s.batchesAccepted.Load(),
		TotalBatchesDropped:  s.batchesDropped.Load(),
		TotalEventsReceived:  s.eventsReceived.Load(),
		TotalEventsValid:     s.eventsValid.Load(),
		TotalEventsInvalid:   s.eventsInvalid.Load(),
		TotalEventsFlushed:   flushed,
		BufferQueueLen:       qLen,
		InvalidEventsByNode:  nodeInvalid,
	}
}
