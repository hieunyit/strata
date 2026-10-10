package ingest

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func sampleEvent(id int) Event {
	return Event{
		BlockID:       fmt.Sprintf("STR-0000-0000-0000-%04d", id),
		Timestamp:     time.Now().UTC(),
		NodeID:        "node-01",
		ConnectorType: "nginx",
		PolicyID:      "default",
		PolicyVersion: 1,
		ClientIP:      "192.0.2.1",
		HTTPMethod:    "GET",
		HTTPHost:      "example.test",
		HTTPPath:      "/",
		StatusCode:    403,
		Action:        "block",
		ScoreProtocol: 10,
		MatchedRules:  []uint32{100001},
	}
}

func TestBatcher_SizeFlush(t *testing.T) {
	mockStore := NewMockEventStore()
	cfg := BatcherConfig{
		MaxBatchSize:  10,
		FlushInterval: 1 * time.Second, // Long interval so size triggers first
		BufferSize:    100,
	}
	batcher := NewBatcher(cfg, mockStore)
	ctx := context.Background()
	defer batcher.Close(ctx)

	// Submit exactly 10 events
	for i := 0; i < 10; i++ {
		if err := batcher.Submit(sampleEvent(i)); err != nil {
			t.Fatalf("failed to submit event %d: %v", i, err)
		}
	}

	// Wait up to 200ms for size flush
	deadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) {
		if mockStore.Count() == 10 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if mockStore.Count() != 10 {
		t.Fatalf("expected 10 events flushed by size, got %d", mockStore.Count())
	}
}

func TestBatcher_IntervalFlush(t *testing.T) {
	mockStore := NewMockEventStore()
	cfg := BatcherConfig{
		MaxBatchSize:  100, // High size threshold
		FlushInterval: 40 * time.Millisecond,
		BufferSize:    100,
	}
	batcher := NewBatcher(cfg, mockStore)
	ctx := context.Background()
	defer batcher.Close(ctx)

	// Submit 3 events (< 100)
	for i := 0; i < 3; i++ {
		if err := batcher.Submit(sampleEvent(i)); err != nil {
			t.Fatalf("failed to submit: %v", err)
		}
	}

	// Should not be flushed immediately
	if mockStore.Count() > 0 {
		t.Logf("Flushed early: %d", mockStore.Count())
	}

	// Wait for interval
	time.Sleep(100 * time.Millisecond)

	if mockStore.Count() != 3 {
		t.Fatalf("expected 3 events flushed by interval, got %d", mockStore.Count())
	}
}

func TestBatcher_ExplicitFlushAndClose(t *testing.T) {
	mockStore := NewMockEventStore()
	cfg := BatcherConfig{
		MaxBatchSize:  1000,
		FlushInterval: 10 * time.Second,
		BufferSize:    100,
	}
	batcher := NewBatcher(cfg, mockStore)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		_ = batcher.Submit(sampleEvent(i))
	}

	// Explicit Flush
	if err := batcher.Flush(ctx); err != nil {
		t.Fatalf("Flush failed: %v", err)
	}
	if mockStore.Count() != 5 {
		t.Fatalf("expected 5 events flushed, got %d", mockStore.Count())
	}

	// Submit more and Close
	for i := 5; i < 12; i++ {
		_ = batcher.Submit(sampleEvent(i))
	}
	if err := batcher.Close(ctx); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	if mockStore.Count() != 12 {
		t.Fatalf("expected all 12 events flushed upon close, got %d", mockStore.Count())
	}
}

func TestBatcher_BufferFull(t *testing.T) {
	// Custom store that blocks saves
	blockingStore := NewMockEventStore()
	saveBlocker := make(chan struct{})
	blockingStore.SetOnSave(func(events []Event) {
		<-saveBlocker
	})

	cfg := BatcherConfig{
		MaxBatchSize:  2,
		FlushInterval: 10 * time.Second,
		BufferSize:    3,
	}
	batcher := NewBatcher(cfg, blockingStore)
	ctx := context.Background()
	defer func() {
		close(saveBlocker)
		_ = batcher.Close(ctx)
	}()

	// Fill buffer until ErrBufferFull
	var gotBufferFull bool
	for i := 0; i < 20; i++ {
		err := batcher.Submit(sampleEvent(i))
		if err == ErrBufferFull {
			gotBufferFull = true
			break
		}
	}

	if !gotBufferFull {
		t.Errorf("expected ErrBufferFull when submitting to saturated queue")
	}
}
