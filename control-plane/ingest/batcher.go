package ingest

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

var (
	ErrBufferFull = errors.New("event buffer is full")
	ErrBatcherClosed = errors.New("batcher is closed")
)

// BatcherConfig configures batch aggregation and flush behaviors.
type BatcherConfig struct {
	MaxBatchSize  int           // Max events per batch (e.g. 2000)
	FlushInterval time.Duration // Max time before flushing an incomplete batch (e.g. 50ms)
	BufferSize    int           // Capacity of input channel buffer (e.g. 50000)
}

// DefaultBatcherConfig returns production-tuned defaults.
func DefaultBatcherConfig() BatcherConfig {
	return BatcherConfig{
		MaxBatchSize:  2000,
		FlushInterval: 50 * time.Millisecond,
		BufferSize:    50000,
	}
}

// Batcher aggregates events into batches and flushes them to an EventStore.
type Batcher struct {
	cfg        BatcherConfig
	store      EventStore
	eventChan  chan Event
	flushReq   chan chan error
	stopChan   chan struct{}
	wg         sync.WaitGroup
	isClosed   atomic.Bool

	// Metrics
	eventsReceived atomic.Uint64
	eventsFlushed  atomic.Uint64
	batchesFlushed atomic.Uint64
	flushErrors    atomic.Uint64
}

// NewBatcher starts a background batching loop.
func NewBatcher(cfg BatcherConfig, store EventStore) *Batcher {
	if cfg.MaxBatchSize <= 0 {
		cfg.MaxBatchSize = 2000
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 50 * time.Millisecond
	}
	if cfg.BufferSize <= 0 {
		cfg.BufferSize = 50000
	}

	b := &Batcher{
		cfg:       cfg,
		store:     store,
		eventChan: make(chan Event, cfg.BufferSize),
		flushReq:  make(chan chan error),
		stopChan:  make(chan struct{}),
	}

	b.wg.Add(1)
	go b.runLoop()

	return b
}

// Submit enqueues an event for batching.
// Returns ErrBufferFull if buffer is saturated (backpressure), or ErrBatcherClosed.
func (b *Batcher) Submit(evt Event) error {
	if b.isClosed.Load() {
		return ErrBatcherClosed
	}

	select {
	case b.eventChan <- evt:
		b.eventsReceived.Add(1)
		return nil
	default:
		return ErrBufferFull
	}
}

// SubmitBatch enqueues multiple events atomically or returns error on full.
func (b *Batcher) SubmitBatch(events []Event) error {
	if b.isClosed.Load() {
		return ErrBatcherClosed
	}
	for i, evt := range events {
		if err := b.Submit(evt); err != nil {
			return fmt.Errorf("submitting event %d of %d: %w", i, len(events), err)
		}
	}
	return nil
}

// Flush synchronously flushes all currently buffered events.
func (b *Batcher) Flush(ctx context.Context) error {
	if b.isClosed.Load() {
		return nil
	}
	errChan := make(chan error, 1)
	select {
	case b.flushReq <- errChan:
		select {
		case err := <-errChan:
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Close gracefully stops the batcher and flushes remaining events.
func (b *Batcher) Close(ctx context.Context) error {
	if !b.isClosed.CompareAndSwap(false, true) {
		return nil // already closed
	}

	close(b.stopChan)

	done := make(chan struct{})
	go func() {
		b.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// runLoop is the internal aggregation loop.
func (b *Batcher) runLoop() {
	defer b.wg.Done()

	ticker := time.NewTicker(b.cfg.FlushInterval)
	defer ticker.Stop()

	currentBatch := make([]Event, 0, b.cfg.MaxBatchSize)

	flushCurrent := func() error {
		if len(currentBatch) == 0 {
			return nil
		}
		// Write to store with a 5-second timeout
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := b.store.SaveEvents(ctx, currentBatch)
		cancel()

		if err != nil {
			b.flushErrors.Add(1)
			return err
		}

		b.eventsFlushed.Add(uint64(len(currentBatch)))
		b.batchesFlushed.Add(1)
		currentBatch = make([]Event, 0, b.cfg.MaxBatchSize)
		return nil
	}

	for {
		select {
		case evt := <-b.eventChan:
			currentBatch = append(currentBatch, evt)
			if len(currentBatch) >= b.cfg.MaxBatchSize {
				_ = flushCurrent()
			}

		case <-ticker.C:
			if len(currentBatch) > 0 {
				_ = flushCurrent()
			}

		case respChan := <-b.flushReq:
			// Drain all currently available in channel
			drained := true
			for drained {
				select {
				case evt := <-b.eventChan:
					currentBatch = append(currentBatch, evt)
					if len(currentBatch) >= b.cfg.MaxBatchSize {
						if err := flushCurrent(); err != nil {
							respChan <- err
							continue
						}
					}
				default:
					drained = false
				}
			}
			err := flushCurrent()
			respChan <- err

		case <-b.stopChan:
			// Drain all remaining events from the channel before exiting
			for {
				select {
				case evt := <-b.eventChan:
					currentBatch = append(currentBatch, evt)
					if len(currentBatch) >= b.cfg.MaxBatchSize {
						_ = flushCurrent()
					}
				default:
					_ = flushCurrent()
					return
				}
			}
		}
	}
}

// Stats returns runtime statistics of the batcher.
func (b *Batcher) Stats() (received, flushed, batches, errors uint64, queueLen int) {
	return b.eventsReceived.Load(),
		b.eventsFlushed.Load(),
		b.batchesFlushed.Load(),
		b.flushErrors.Load(),
		len(b.eventChan)
}
