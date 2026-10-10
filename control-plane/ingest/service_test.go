package ingest

import (
	"context"
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

	_ = svc.Flush(ctx)
	if mockStore.Count() != 1 {
		t.Errorf("expected only 1 valid event stored, got %d", mockStore.Count())
	}
}
