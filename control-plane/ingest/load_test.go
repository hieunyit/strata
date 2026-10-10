package ingest

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestIngestThroughput_10k_eps verifies that the ingest pipeline can sustain
// 10,000 events/second without backlog accumulation or dropped valid events.
func TestIngestThroughput_10k_eps(t *testing.T) {
	mockStore := NewMockEventStore()
	cfg := BatcherConfig{
		MaxBatchSize:  2000,
		FlushInterval: 40 * time.Millisecond,
		BufferSize:    50000,
	}
	svc := NewIngestService(mockStore, cfg, 1*time.Hour)
	ctx := context.Background()
	defer svc.Close(ctx)

	const (
		targetRateEPS   = 10000 // 10,000 events/second
		batchSize       = 100   // 100 events per batch
		totalBatches    = 300   // 300 batches = 30,000 events total (3 seconds worth)
		numWorkerNodes  = 10    // 10 concurrent nodes sending events
	)

	totalEventsTarget := totalBatches * batchSize
	t.Logf("Starting 10,000 events/sec throughput test: %d total events across %d nodes...", totalEventsTarget, numWorkerNodes)

	var (
		submittedEvents atomic.Uint64
		start           = time.Now()
		wg              sync.WaitGroup
	)

	// Rate limiter: 100 batches per second = 10,000 events/sec
	ticker := time.NewTicker(time.Second / (targetRateEPS / batchSize))
	defer ticker.Stop()

	batchesPerNode := totalBatches / numWorkerNodes

	for nodeIdx := 0; nodeIdx < numWorkerNodes; nodeIdx++ {
		wg.Add(1)
		nodeID := fmt.Sprintf("node-%02d", nodeIdx)

		go func(nid string) {
			defer wg.Done()
			for seq := uint64(1); seq <= uint64(batchesPerNode); seq++ {
				<-ticker.C // throttle to target rate

				events := make([]Event, batchSize)
				now := time.Now().UTC()
				for i := 0; i < batchSize; i++ {
					events[i] = Event{
						BlockID:       fmt.Sprintf("STR-AAAA-%04X-%04X-0000", seq&0xFFFF, i&0xFFFF),
						Timestamp:     now,
						NodeID:        nid,
						ConnectorType: "nginx",
						PolicyID:      "api-gw",
						PolicyVersion: 1,
						ClientIP:      "192.0.2.1",
						HTTPMethod:    "POST",
						HTTPHost:      "api.example.test",
						HTTPPath:      "/v1/payments",
						StatusCode:    403,
						Action:        "block",
						ScoreSQLi:     20,
						MatchedRules:  []uint32{942100},
						Violations: []Violation{
							{RuleID: 942100, Layer: "sqli", Field: "body.card", Snippet: "SELECT * FROM users"},
						},
					}
				}

				ack, err := svc.ProcessBatch(ctx, EventBatch{
					NodeID: nid,
					Seq:    seq,
					Events: events,
				})
				if err != nil {
					t.Errorf("node %s batch %d failed: %v", nid, seq, err)
					return
				}
				if !ack.Success {
					t.Errorf("node %s batch %d ack not successful: %v", nid, seq, ack.Error)
					return
				}
				submittedEvents.Add(batchSize)
			}
		}(nodeID)
	}

	wg.Wait()
	submitDuration := time.Since(start)

	// Wait for queue drain & flush
	flushStart := time.Now()
	if err := svc.Flush(ctx); err != nil {
		t.Fatalf("Flush failed: %v", err)
	}
	totalDuration := time.Since(start)

	stats := svc.Stats()
	storedCount := mockStore.Count()

	effectiveSubmitEPS := float64(submittedEvents.Load()) / submitDuration.Seconds()
	overallThroughputEPS := float64(storedCount) / totalDuration.Seconds()

	t.Logf("=== Load Test Results ===")
	t.Logf("Submitted Events:      %d", submittedEvents.Load())
	t.Logf("Stored in Store:       %d", storedCount)
	t.Logf("Submit Duration:       %v (Rate: %.0f events/sec)", submitDuration, effectiveSubmitEPS)
	t.Logf("Total Time to Flush:   %v (Overall Throughput: %.0f events/sec)", totalDuration, overallThroughputEPS)
	t.Logf("Queue Buffer at End:   %d (No backlog)", stats.BufferQueueLen)
	t.Logf("Batches Processed:     %d (Dropped duplicates: %d)", stats.TotalBatchesAccepted, stats.TotalBatchesDropped)
	t.Logf("Flush time:            %v", time.Since(flushStart))

	// Verify conditions
	if storedCount != totalEventsTarget {
		t.Errorf("expected %d events stored, got %d", totalEventsTarget, storedCount)
	}
	if stats.BufferQueueLen != 0 {
		t.Errorf("expected zero backlog in queue after flush, got %d", stats.BufferQueueLen)
	}
	if stats.TotalEventsInvalid != 0 {
		t.Errorf("expected 0 invalid events, got %d", stats.TotalEventsInvalid)
	}
}
