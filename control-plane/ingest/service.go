package ingest

import (
	"context"
	"fmt"
	"github.com/strata/strata/agent/pkg/privacy"
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
	TotalGeoIPErrors     uint64 // enrichment failures; security events still persist
	TotalEventsFlushed   uint64
	BufferQueueLen       int
	InvalidEventsByNode  map[string]uint64
}

// BatchGate serializes a node's writes and commits its watermark across replicas.
// A failed write or watermark commit must return an error, never a successful ACK.
type BatchGate interface {
	WithIngestBatch(context.Context, string, uint64, func(context.Context) error) (bool, error)
}

// IngestService coordinates deduplication, schema validation, batching, and persistence.
type IngestService struct {
	Privacy func(context.Context, string, uint64) (*privacy.Filter, error)
	// Gate must be configured before serving when PostgreSQL is available.
	Gate BatchGate
	// GeoIP must be configured before serving; readers may then be atomically reloaded.
	GeoIP *GeoIPEnricher

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
	geoIPErrors     atomic.Uint64

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

	if s.Gate != nil {
		bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		duplicate, err := s.Gate.WithIngestBatch(bounded, batch.NodeID, batch.Seq, func(ctx context.Context) error {
			return s.persistBatch(ctx, batch)
		})
		if err != nil {
			return &EventAck{NodeID: batch.NodeID, Success: false}, fmt.Errorf("ingest transaction: %w", err)
		}
		if duplicate {
			s.batchesDropped.Add(1)
		} else {
			s.batchesAccepted.Add(1)
		}
		return &EventAck{NodeID: batch.NodeID, AckedSeq: batch.Seq, Success: true, Duplicate: duplicate}, nil
	}

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

	if err := s.persistBatch(ctx, batch); err != nil {
		return &EventAck{NodeID: batch.NodeID, AckedSeq: lastSeq, Success: false, Error: err.Error()}, err
	}
	s.dedup.Commit(ctx, batch.NodeID, batch.Seq)
	s.batchesAccepted.Add(1)
	return &EventAck{NodeID: batch.NodeID, AckedSeq: batch.Seq, Success: true}, nil
}

func (s *IngestService) persistBatch(ctx context.Context, batch EventBatch) error {
	now := time.Now().UTC()
	type key struct {
		name    string
		version uint64
	}
	filters := map[key]*privacy.Filter{}
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
		s.enrichGeoIP(evt)
		k := key{evt.PolicyID, evt.PolicyVersion}
		filter, found := filters[k]
		if !found && s.Privacy != nil {
			var err error
			filter, err = s.Privacy(ctx, k.name, k.version)
			if err != nil {
				return fmt.Errorf("ingest: privacy settings unavailable: %w", err)
			}
			filters[k] = filter
		}
		s.eventsValid.Add(1)
		validEvents = append(validEvents, RedactEvent(*evt, filter))
	}
	if len(validEvents) > 0 {
		if err := s.batcher.SubmitAndAwait(ctx, validEvents); err != nil {
			return fmt.Errorf("persisting events: %w", err)
		}
	}
	return nil
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
		TotalGeoIPErrors:     s.geoIPErrors.Load(),
		TotalEventsFlushed:   flushed,
		BufferQueueLen:       qLen,
		InvalidEventsByNode:  nodeInvalid,
	}
}
