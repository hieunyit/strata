package ingest

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestIngestService_Flow(t *testing.T) {
	mockStore := NewMockEventStore()
	cfg := BatcherConfig{
		MaxBatchSize:  5,
		FlushInterval: 50 * time.Millisecond,
		BufferSize:    100,
	}
	svc := NewIngestService(mockStore, cfg, 1*time.Hour)
	ctx := context.Background()
	defer svc.Close(ctx)

	nodeID := "node-test"
	now := time.Now().UTC()

	// 1. Send first batch with 3 events
	events := []Event{
		{
			BlockID:       "STR-0000-0000-0000-0001",
			Timestamp:     now.Add(-10 * time.Second),
			NodeID:        nodeID,
			Action:        "block",
			ScoreProtocol: 10,
		},
		{
			BlockID:       "STR-0000-0000-0000-0002",
			Timestamp:     now.Add(-9 * time.Second),
			NodeID:        nodeID,
			Action:        "block",
			ScoreProtocol: 20,
		},
		{
			BlockID:       "STR-0000-0000-0000-0003",
			Timestamp:     now.Add(-8 * time.Second),
			NodeID:        nodeID,
			Action:        "shadow",
			ScoreProtocol: 5,
		},
	}

	ack, err := svc.ProcessBatch(ctx, EventBatch{
		NodeID: nodeID,
		Seq:    1,
		Events: events,
	})
	if err != nil {
		t.Fatalf("ProcessBatch failed: %v", err)
	}
	if !ack.Success || ack.AckedSeq != 1 {
		t.Fatalf("expected success ack with seq 1, got %+v", ack)
	}

	// 2. Duplicate batch with same seq 1 should be dropped and acked
	ack, err = svc.ProcessBatch(ctx, EventBatch{
		NodeID: nodeID,
		Seq:    1,
		Events: events,
	})
	if err != nil {
		t.Fatalf("ProcessBatch failed: %v", err)
	}
	if !ack.Success || ack.AckedSeq != 1 {
		t.Fatalf("expected success ack for duplicate batch, got %+v", ack)
	}

	stats := svc.Stats()
	if stats.TotalBatchesReceived != 2 {
		t.Errorf("expected 2 batches received, got %d", stats.TotalBatchesReceived)
	}
	if stats.TotalBatchesDropped != 1 {
		t.Errorf("expected 1 batch dropped as duplicate, got %d", stats.TotalBatchesDropped)
	}

	// 3. Flush and verify store
	if err := svc.Flush(ctx); err != nil {
		t.Fatalf("Flush failed: %v", err)
	}

	if mockStore.Count() != 3 {
		t.Fatalf("expected 3 events stored, got %d", mockStore.Count())
	}

	// 4. Point lookup for Block ID
	e, err := svc.Store().GetEvent(ctx, "STR-0000-0000-0000-0002")
	if err != nil {
		t.Fatalf("GetEvent failed: %v", err)
	}
	if e.BlockID != "STR-0000-0000-0000-0002" {
		t.Errorf("expected BlockID STR-0000-0000-0000-0002, got %s", e.BlockID)
	}

	// Non-existent Block ID returns ErrEventNotFound
	_, err = svc.Store().GetEvent(ctx, "STR-9999-9999-9999-9999")
	if err != ErrEventNotFound {
		t.Errorf("expected ErrEventNotFound, got %v", err)
	}
}

func TestIngestService_InvalidEventFilter(t *testing.T) {
	mockStore := NewMockEventStore()
	cfg := BatcherConfig{
		MaxBatchSize:  5,
		FlushInterval: 50 * time.Millisecond,
		BufferSize:    100,
	}
	svc := NewIngestService(mockStore, cfg, 1*time.Hour)
	ctx := context.Background()
	defer svc.Close(ctx)

	nodeID := "node-corrupt"
	now := time.Now().UTC()

	// Batch contains 1 valid and 1 invalid event
	events := []Event{
		{
			BlockID:   "STR-0000-0000-0000-0001",
			Timestamp: now.Add(-10 * time.Second),
			NodeID:    nodeID,
			Action:    "block",
		},
		{
			BlockID:   "INVALID_BLOCK_ID",
			Timestamp: now.Add(-10 * time.Second),
			NodeID:    nodeID,
			Action:    "block",
		},
	}

	ack, err := svc.ProcessBatch(ctx, EventBatch{
		NodeID: nodeID,
		Seq:    1,
		Events: events,
	})
	if err != nil {
		t.Fatalf("ProcessBatch failed: %v", err)
	}
	if !ack.Success {
		t.Fatalf("expected success ack even with 1 invalid event, got %+v", ack)
	}

	stats := svc.Stats()
	if stats.TotalEventsValid != 1 {
		t.Errorf("expected 1 valid event, got %d", stats.TotalEventsValid)
	}
	if stats.TotalEventsInvalid != 1 {
		t.Errorf("expected 1 invalid event, got %d", stats.TotalEventsInvalid)
	}
	if stats.InvalidEventsByNode[nodeID] != 1 {
		t.Errorf("expected 1 invalid event for node %s, got %d", nodeID, stats.InvalidEventsByNode[nodeID])
	}

	_ = svc.Flush(ctx)
	if mockStore.Count() != 1 {
		t.Errorf("expected only 1 valid event stored, got %d", mockStore.Count())
	}
}

func TestIngestService_StoreErrorNoAck(t *testing.T) {
	mockStore := NewMockEventStore()
	cfg := BatcherConfig{
		MaxBatchSize:  5,
		FlushInterval: 50 * time.Millisecond,
		BufferSize:    100,
	}
	svc := NewIngestService(mockStore, cfg, 1*time.Hour)
	ctx := context.Background()
	defer svc.Close(ctx)

	nodeID := "node-retry"
	now := time.Now().UTC()
	events := []Event{
		{
			BlockID:   "STR-0000-0000-0000-0010",
			Timestamp: now.Add(-5 * time.Second),
			NodeID:    nodeID,
			Action:    "block",
		},
	}

	// 1. Simulate ClickHouse down: SaveEvents returns error
	simErr := fmt.Errorf("clickhouse connection refused")
	mockStore.SetSaveError(simErr)

	ack, err := svc.ProcessBatch(ctx, EventBatch{
		NodeID: nodeID,
		Seq:    1,
		Events: events,
	})
	if err == nil {
		t.Fatalf("expected ProcessBatch to return error when store fails")
	}
	if ack.Success {
		t.Fatalf("expected ack.Success=false when store fails, got %+v", ack)
	}
	if ack.AckedSeq == 1 {
		t.Fatalf("expected sequence 1 NOT to be acked on failure, got %d", ack.AckedSeq)
	}

	// Deduplicator watermark must NOT be updated
	if svc.dedup.GetLastSeq(nodeID) != 0 {
		t.Errorf("dedup watermark should remain 0, got %d", svc.dedup.GetLastSeq(nodeID))
	}

	// 2. ClickHouse recovers: Clear error and retry identical batch
	mockStore.SetSaveError(nil)

	ack, err = svc.ProcessBatch(ctx, EventBatch{
		NodeID: nodeID,
		Seq:    1,
		Events: events,
	})
	if err != nil {
		t.Fatalf("ProcessBatch retry failed: %v", err)
	}
	if !ack.Success || ack.AckedSeq != 1 {
		t.Fatalf("expected successful ack on retry with seq 1, got %+v", ack)
	}
	if svc.dedup.GetLastSeq(nodeID) != 1 {
		t.Errorf("expected watermark 1 after recovery, got %d", svc.dedup.GetLastSeq(nodeID))
	}
	if mockStore.Count() != 1 {
		t.Errorf("expected 1 event stored in ClickHouse, got %d", mockStore.Count())
	}
}
