package fleet

import (
	"context"
	"sync"
	"time"
)

// OnlineWindow: a node counts as online when its Connect stream is open on
// this control plane, or when another control plane reported it connected
// and it sent a heartbeat this recently (they come every 15 s, so two
// missed ones turn it offline even if that control plane died).
const OnlineWindow = 30 * time.Second

// Presence tracks the open streams of each node, so that a revocation can
// cut them at once and node status follows a disconnect immediately.
type Presence struct {
	mu      sync.Mutex
	streams map[string]map[*stream]context.CancelFunc
}

// Stream kinds.
const (
	KindConnect = "connect"
	KindEvents  = "events"
)

type stream struct{ kind string }

// NewPresence returns an empty registry.
func NewPresence() *Presence {
	return &Presence{streams: map[string]map[*stream]context.CancelFunc{}}
}

// Attach registers a stream of node; call the returned function when the
// stream ends. The context is cancelled by Cut.
func (p *Presence) Attach(ctx context.Context, node, kind string) (context.Context, func()) {
	ctx, cancel := context.WithCancel(ctx)
	key := &stream{kind: kind}
	p.mu.Lock()
	if p.streams[node] == nil {
		p.streams[node] = map[*stream]context.CancelFunc{}
	}
	p.streams[node][key] = cancel
	p.mu.Unlock()
	return ctx, func() {
		cancel()
		p.mu.Lock()
		delete(p.streams[node], key)
		if len(p.streams[node]) == 0 {
			delete(p.streams, node)
		}
		p.mu.Unlock()
	}
}

// Connected reports whether node has an open stream here.
func (p *Presence) Connected(node string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.streams[node]) > 0
}

// connects counts node's open Connect streams.
func (p *Presence) connects(node string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for s := range p.streams[node] {
		if s.kind == KindConnect {
			n++
		}
	}
	return n
}

// Cut ends every stream of node.
func (p *Presence) Cut(node string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, cancel := range p.streams[node] {
		cancel()
	}
}

// Online is the status shown for a node; connected and lastSeen come from
// the node registry.
func (p *Presence) Online(node string, connected bool, lastSeen *time.Time, revoked bool, now time.Time) bool {
	if revoked {
		return false
	}
	if p.Connected(node) {
		return true
	}
	return connected && lastSeen != nil && now.Sub(*lastSeen) <= OnlineWindow
}
