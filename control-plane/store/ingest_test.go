package store_test

import (
	"context"
	"errors"
	"math"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/strata/strata/control-plane/ingest"
	"github.com/strata/strata/control-plane/localauth/localauthtest"
	"github.com/strata/strata/control-plane/store"
)

func TestIngestAcrossReplicasInPostgres(t *testing.T) {
	p := localauthtest.Pool(t)
	ctx := t.Context()
	if _, err := p.Exec(ctx, `INSERT INTO connector_groups(id,name) VALUES ('edge','Edge'); INSERT INTO nodes(id,group_id) VALUES ('n','edge')`); err != nil {
		t.Fatal(err)
	}
	a, b := store.New(p), store.New(p)
	var writes atomic.Int64
	write := func(context.Context) error { writes.Add(1); return nil }
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s := a
			if i%2 == 0 {
				s = b
			}
			if _, err := s.WithIngestBatch(ctx, "n", 1, write); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	if n := writes.Load(); n != 1 {
		t.Fatalf("writes=%d, want 1", n)
	}
	failed := errors.New("ClickHouse unavailable")
	if _, err := a.WithIngestBatch(ctx, "n", 2, func(context.Context) error { return failed }); !errors.Is(err, failed) {
		t.Fatal(err)
	}
	if dup, err := b.WithIngestBatch(ctx, "n", 2, write); err != nil || dup {
		t.Fatalf("retry: duplicate=%v err=%v", dup, err)
	}
	if dup, err := store.New(p).WithIngestBatch(ctx, "n", 1, write); err != nil || !dup {
		t.Fatalf("restart: duplicate=%v err=%v", dup, err)
	}
	for _, seq := range []uint64{0, math.MaxUint64} {
		if _, err := a.WithIngestBatch(ctx, "n", seq, write); err == nil {
			t.Fatalf("accepted invalid seq %d", seq)
		}
	}
	if _, err := a.WithIngestBatch(ctx, "unknown", 1, write); err == nil {
		t.Fatal("accepted unenrolled node")
	}
	// A queued writer must honor cancellation rather than hold a stream forever.
	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := a.WithIngestBatch(ctx, "n", 3, func(context.Context) error { close(entered); <-release; return nil })
		done <- err
	}()
	<-entered
	short, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
	defer cancel()
	_, err := b.WithIngestBatch(short, "n", 3, write)
	close(release)
	if err == nil {
		t.Fatal("lock wait ignored timeout")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	// Real service instances must use the common gate, not their stale RAM cache.
	events := ingest.NewMockEventStore()
	cfg := ingest.BatcherConfig{MaxBatchSize: 1, FlushInterval: time.Millisecond, BufferSize: 8}
	one, two := ingest.NewIngestService(events, cfg, time.Hour), ingest.NewIngestService(events, cfg, time.Hour)
	defer one.Close(ctx)
	defer two.Close(ctx)
	one.Gate, two.Gate = a, b
	batch := ingest.EventBatch{NodeID: "n", Seq: 4, Events: []ingest.Event{{BlockID: "STR-0000-0000-0000-0001", Timestamp: time.Now(), NodeID: "n", Action: "block"}}}
	if ack, err := one.ProcessBatch(ctx, batch); err != nil || !ack.Success || ack.Duplicate {
		t.Fatalf("first: %+v %v", ack, err)
	}
	if ack, err := two.ProcessBatch(ctx, batch); err != nil || !ack.Success || !ack.Duplicate {
		t.Fatalf("second: %+v %v", ack, err)
	}
	if got := two.Stats().TotalEventsValid; got != 0 {
		t.Fatalf("duplicate persisted: %d valid", got)
	}
}
