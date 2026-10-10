package ingest

import (
	"context"
	"fmt"
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
}

// NewIngestService creates a fully configured IngestService.
func NewIngestService(store EventStore, batcherCfg BatcherConfig, nodeTTL time.Duration) *IngestService {
	dedup := NewNodeDeduplicator(nodeTTL)
	batcher := NewBatcher(batcherCfg, store)

	return &IngestService{
		dedup:   dedup,
		batcher: batcher,
		store:   store,
	}
}

// ProcessBatch processes an incoming EventBatch from a connector/agent.
// It performs deduplication, schema validation, and submits to the batch queue.
func (s *IngestService) ProcessBatch(ctx context.Context, batch EventBatch) (*EventAck, error) {
	s.batchesReceived.Add(1)
	s.eventsReceived.Add(uint64(len(batch.Events)))

	// 1. Deduplication check by sequence number
	isDup, lastSeq := s.dedup.CheckBatch(batch.NodeID, batch.Seq)
	if isDup {
		s.batchesDropped.Add(1)
		// Return ACK for the duplicate batch so agent can clear its spool
		return &EventAck{
			NodeID:   batch.NodeID,
			AckedSeq: batch.Seq,
			Success:  true,
		}, nil
	}

	// 2. Validate and normalize schema for each event
	now := time.Now().UTC()
	validEvents := make([]Event, 0, len(batch.Events))

	for i := range batch.Events {
		evt := &batch.Events[i]
		if err := ValidateEvent(evt, now); err != nil {
			s.eventsInvalid.Add(1)
			// Skip corrupt event, proceed with remaining valid ones
			continue
		}
		s.eventsValid.Add(1)
		validEvents = append(validEvents, *evt)
	}

	// 3. Submit valid events to batcher queue
	if len(validEvents) > 0 {
		if err := s.batcher.SubmitBatch(validEvents); err != nil {
			return &EventAck{
				NodeID:   batch.NodeID,
				AckedSeq: lastSeq,
				Success:  false,
				Error:    err.Error(),
			}, fmt.Errorf("queueing events: %w", err)
		}
	}

	// 4. Update sequence watermark
	s.dedup.Commit(batch.NodeID, batch.Seq)
	s.batchesAccepted.Add(1)

	return &EventAck{
		NodeID:   batch.NodeID,
		AckedSeq: batch.Seq,
		Success:  true,
	}, nil
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
	return IngestStats{
		TotalBatchesReceived: s.batchesReceived.Load(),
		TotalBatchesAccepted: s.batchesAccepted.Load(),
		TotalBatchesDropped:  s.batchesDropped.Load(),
		TotalEventsReceived:  s.eventsReceived.Load(),
		TotalEventsValid:     s.eventsValid.Load(),
		TotalEventsInvalid:   s.eventsInvalid.Load(),
		TotalEventsFlushed:   flushed,
		BufferQueueLen:       qLen,
	}
}
