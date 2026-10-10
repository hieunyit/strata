package batch

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	eventv1 "github.com/strata/strata/agent/gen/strata/event/v1"
	fleetv1 "github.com/strata/strata/agent/gen/strata/fleet/v1"
)

type memSpool struct {
	mu      sync.Mutex
	batches []*fleetv1.EventBatch
	counts  []uint32
}

func (m *memSpool) Append(p []byte, n uint32) (uint64, error) {
	b := &fleetv1.EventBatch{}
	if err := proto.Unmarshal(p, b); err != nil {
		return 0, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.batches = append(m.batches, b)
	m.counts = append(m.counts, n)
	return uint64(len(m.batches)), nil
}

func (m *memSpool) sizes() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var s []string
	for i, b := range m.batches {
		if uint32(len(b.Events)) != m.counts[i] {
			return "count mismatch"
		}
		s = append(s, fmt.Sprint(len(b.Events)))
	}
	return strings.Join(s, " ")
}

func run(t *testing.T, opts Options, feed func(ctx context.Context, b *Batcher)) *memSpool {
	t.Helper()
	m := &memSpool{}
	b := New(m, opts)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- b.Run(ctx) }()
	feed(context.Background(), b)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	return m
}

func ev(i int) *eventv1.Event {
	return &eventv1.Event{BlockId: fmt.Sprintf("STR-%04d", i), NodeId: "worker-said", Path: strings.Repeat("p", 90)}
}

func TestFlushByCountAndOnStop(t *testing.T) {
	m := run(t, Options{MaxEvents: 4, MaxDelay: time.Hour, NodeID: "node-example-1"}, func(ctx context.Context, b *Batcher) {
		for i := 0; i < 10; i++ {
			b.Add(ctx, ev(i))
		}
	})
	if got := m.sizes(); got != "4 4 2" {
		t.Fatalf("batch sizes %q", got)
	}
	for _, b := range m.batches {
		for _, e := range b.Events {
			if e.NodeId != "node-example-1" {
				t.Fatalf("node id %q not replaced", e.NodeId)
			}
		}
	}
}

func TestFlushByDelay(t *testing.T) {
	m := run(t, Options{MaxEvents: 100, MaxDelay: 50 * time.Millisecond}, func(ctx context.Context, b *Batcher) {
		b.Add(ctx, ev(1))
		b.Add(ctx, ev(2))
		time.Sleep(300 * time.Millisecond)
		b.Add(ctx, ev(3))
	})
	if got := m.sizes(); got != "2 1" {
		t.Fatalf("batch sizes %q", got)
	}
}

func TestFlushByBytes(t *testing.T) {
	// Each event is about 110 bytes; 500 bytes hold 4.
	m := run(t, Options{MaxEvents: 100, MaxBytes: 500, MaxDelay: time.Hour}, func(ctx context.Context, b *Batcher) {
		for i := 0; i < 9; i++ {
			b.Add(ctx, ev(i))
		}
	})
	if got := m.sizes(); got != "4 4 1" {
		t.Fatalf("batch sizes %q", got)
	}
}
