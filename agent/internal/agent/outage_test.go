package agent

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	eventv1 "github.com/strata/strata/agent/gen/strata/event/v1"
	"github.com/strata/strata/agent/internal/batch"
	"github.com/strata/strata/agent/internal/fleettest"
	"github.com/strata/strata/agent/internal/pusher"
)

type running struct {
	a    *Agent
	stop func() error
}

func start(t *testing.T, cfg Config) running {
	t.Helper()
	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	return running{a: a, stop: func() error {
		cancel()
		err := <-done
		if cerr := a.Close(); err == nil {
			err = cerr
		}
		return err
	}}
}

func testConfig(t *testing.T, srv *fleettest.Server, c fleettest.Certs, push pusher.Options) Config {
	dir := t.TempDir()
	return Config{
		EventSocket: filepath.Join(dir, "events.sock"),
		SpoolDir:    filepath.Join(dir, "spool"),
		Server:      srv.Addr(),
		ServerName:  "cp.example.test",
		CAFile:      c.CA,
		CertFile:    c.ClientCert,
		KeyFile:     c.ClientKey,
		NodeID:      "node-example-1",
		Batch:       batch.Options{MaxEvents: 200, MaxDelay: 100 * time.Millisecond},
		Push:        push,
		noSync:      true,
	}
}

// worker sends events the way an NGINX worker does: one datagram each.
type worker struct {
	t    *testing.T
	conn *net.UnixConn
	next int
}

func newWorker(t *testing.T, path string) *worker {
	t.Helper()
	c, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return &worker{t: t, conn: c}
}

func (w *worker) send(n int) {
	w.t.Helper()
	for i := 0; i < n; i++ {
		b, err := proto.Marshal(&eventv1.Event{
			BlockId: fmt.Sprintf("STR-%019d", w.next), Host: "api.example.test", Path: "/v1/items",
			Method: "POST", Status: 403, Action: eventv1.Action_ACTION_BLOCK, RuleIds: []uint32{100001},
		})
		if err != nil {
			w.t.Fatal(err)
		}
		if _, err := w.conn.Write(b); err != nil {
			w.t.Fatalf("send event %d: %v", w.next, err)
		}
		w.next++
	}
}

// sendFor sends at rate events per second for d.
func (w *worker) sendFor(d time.Duration, rate int) {
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	end := time.Now().Add(d)
	for time.Now().Before(end) {
		<-tick.C
		w.send(rate / 100)
	}
}

func waitDelivered(t *testing.T, srv *fleettest.Server, n int, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for len(srv.Snapshot().IDs) < n {
		if time.Now().After(deadline) {
			t.Fatalf("delivered %d of %d events", len(srv.Snapshot().IDs), n)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func checkExactlyOnce(t *testing.T, srv *fleettest.Server, n int) {
	t.Helper()
	s := srv.Snapshot()
	for i := 0; i < n; i++ {
		if c := s.IDs[fmt.Sprintf("STR-%019d", i)]; c != 1 {
			t.Fatalf("event %d committed %d times", i, c)
		}
	}
	if len(s.IDs) != n {
		t.Fatalf("committed %d events, sent %d", len(s.IDs), n)
	}
	t.Logf("%d events in %d batches, %d duplicate batches dropped", n, s.Batches, s.Duplicates)
}

// outage keeps a worker sending at rate while the control plane is down
// for down, then checks every event arrived exactly once.
func outage(t *testing.T, down time.Duration, rate int, push pusher.Options) {
	srv, certs := fleettest.NewServer(t)
	cfg := testConfig(t, srv, certs, push)
	cfg.SpoolMaxBytes = 2 << 30
	r := start(t, cfg)
	w := newWorker(t, cfg.EventSocket)

	w.sendFor(time.Second, rate)
	srv.Stop()
	w.sendFor(down, rate)
	spooled := r.a.Spool.Stats()
	srv.Start()
	w.sendFor(time.Second, rate)

	// Backoff may have grown to its maximum during the outage.
	waitDelivered(t, srv, w.next, push.BackoffMax+time.Minute)
	if err := r.stop(); err != nil {
		t.Fatalf("agent: %v", err)
	}
	checkExactlyOnce(t, srv, w.next)
	if st := r.a.Spool.Stats(); st.DroppedBatches != 0 {
		t.Fatalf("spool dropped %d batches", st.DroppedBatches)
	}
	if r.a.Socket.C.Invalid.Load() != 0 || r.a.Socket.C.Truncated.Load() != 0 {
		t.Fatal("valid events counted as invalid")
	}
	t.Logf("spool at end of outage: %d bytes, %d batches unacked",
		spooled.Bytes, spooled.LastSeq-spooled.AckedSeq)
}

func TestOutage(t *testing.T) {
	outage(t, 5*time.Second, 2000, pusher.Options{BackoffMin: 50 * time.Millisecond, BackoffMax: time.Second})
}

func TestAgentRestartDuringOutage(t *testing.T) {
	srv, certs := fleettest.NewServer(t)
	cfg := testConfig(t, srv, certs, pusher.Options{BackoffMin: 50 * time.Millisecond, BackoffMax: 500 * time.Millisecond})
	r := start(t, cfg)
	w := newWorker(t, cfg.EventSocket)
	w.send(300)
	waitDelivered(t, srv, 300, 10*time.Second)
	srv.Stop()
	w.send(700)
	time.Sleep(300 * time.Millisecond) // let the socket drain
	if err := r.stop(); err != nil {
		t.Fatalf("agent: %v", err)
	}

	// A new agent on the same spool sends what the first one kept.
	r = start(t, cfg)
	w = &worker{t: t, conn: newWorker(t, cfg.EventSocket).conn, next: w.next}
	w.send(100)
	srv.Start()
	waitDelivered(t, srv, w.next, 30*time.Second)
	if err := r.stop(); err != nil {
		t.Fatalf("agent: %v", err)
	}
	checkExactlyOnce(t, srv, w.next)
}

func TestNeedsMTLS(t *testing.T) {
	if _, err := New(Config{Server: "127.0.0.1:1", SpoolDir: t.TempDir()}); err == nil {
		t.Fatal("agent started without mTLS")
	}
}
