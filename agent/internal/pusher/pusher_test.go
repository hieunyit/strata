package pusher

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/proto"

	eventv1 "github.com/strata/strata/agent/gen/strata/event/v1"
	fleetv1 "github.com/strata/strata/agent/gen/strata/fleet/v1"
	"github.com/strata/strata/agent/internal/fleettest"
	"github.com/strata/strata/agent/internal/spool"
)

func client(t *testing.T, srv *fleettest.Server, c fleettest.Certs) fleetv1.FleetServiceClient {
	t.Helper()
	pair, err := tls.LoadX509KeyPair(c.ClientCert, c.ClientKey)
	if err != nil {
		t.Fatal(err)
	}
	pem, err := os.ReadFile(c.CA)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	conn, err := grpc.NewClient(srv.Addr(), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{pair}, RootCAs: pool, MinVersion: tls.VersionTLS13,
	})))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return fleetv1.NewFleetServiceClient(conn)
}

// fill appends n batches of one event each, with Block IDs from..from+n-1.
func fill(t *testing.T, sp *spool.Spool, from, n int) {
	t.Helper()
	for i := from; i < from+n; i++ {
		p, err := proto.Marshal(&fleetv1.EventBatch{Events: []*eventv1.Event{{BlockId: fmt.Sprintf("STR-%06d", i)}}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := sp.Append(p, 1); err != nil {
			t.Fatal(err)
		}
	}
}

func setup(t *testing.T, opts Options) (*fleettest.Server, *spool.Spool, *Pusher, func()) {
	t.Helper()
	srv, certs := fleettest.NewServer(t)
	sp, err := spool.Open(t.TempDir(), spool.Options{NoSync: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sp.Close() })
	p := New(client(t, srv, certs), sp, opts)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.Run(ctx) }()
	return srv, sp, p, func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Run: %v", err)
		}
	}
}

func waitAcked(t *testing.T, sp *spool.Spool, seq uint64, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for sp.Stats().AckedSeq < seq {
		if time.Now().After(deadline) {
			t.Fatalf("acked %d, want %d", sp.Stats().AckedSeq, seq)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func checkAll(t *testing.T, srv *fleettest.Server, n int) fleettest.Snapshot {
	t.Helper()
	s := srv.Snapshot()
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("STR-%06d", i)
		if s.IDs[id] != 1 {
			t.Fatalf("%s committed %d times", id, s.IDs[id])
		}
	}
	if len(s.IDs) != n {
		t.Fatalf("committed %d ids, want %d", len(s.IDs), n)
	}
	return s
}

func TestPushAndAck(t *testing.T) {
	srv, sp, p, stop := setup(t, Options{Window: 8, BackoffMin: 10 * time.Millisecond, BackoffMax: 50 * time.Millisecond})
	fill(t, sp, 0, 100)
	waitAcked(t, sp, 100, 10*time.Second)
	stop()
	s := checkAll(t, srv, 100)
	if s.Duplicates != 0 || s.LastSeq != 100 {
		t.Fatalf("server %+v", s)
	}
	if p.C.LastAckedSeq.Load() != 100 || sp.Stats().Segments != 1 {
		t.Fatalf("pusher acked %d, spool %+v", p.C.LastAckedSeq.Load(), sp.Stats())
	}
}

func TestOutageResendsUnderSameSeq(t *testing.T) {
	srv, sp, p, stop := setup(t, Options{Window: 8, BackoffMin: 10 * time.Millisecond, BackoffMax: 100 * time.Millisecond})
	fill(t, sp, 0, 50)
	waitAcked(t, sp, 50, 10*time.Second)
	srv.Stop()
	fill(t, sp, 50, 50) // spooled while the control plane is down
	time.Sleep(300 * time.Millisecond)
	if sp.Stats().AckedSeq != 50 {
		t.Fatalf("acked %d while down", sp.Stats().AckedSeq)
	}
	srv.Start()
	waitAcked(t, sp, 100, 10*time.Second)
	stop()
	s := checkAll(t, srv, 100)
	if s.LastSeq != 100 || s.Batches != 100 {
		t.Fatalf("server %+v", s)
	}
	if p.C.Reconnects.Load() == 0 {
		t.Fatal("no reconnect counted")
	}
}

func TestDuplicateSeqDropped(t *testing.T) {
	// The server commits seq 1-20 but the acks are lost: the agent
	// restarts from its last ack and resends seq 1-20 with the same seqs,
	// which the server must drop.
	srv, certs := fleettest.NewServer(t)
	dir := t.TempDir()
	sp, err := spool.Open(dir, spool.Options{NoSync: true})
	if err != nil {
		t.Fatal(err)
	}
	fill(t, sp, 0, 20)
	cl := client(t, srv, certs)
	st, err := cl.PushEvents(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	recs, _ := sp.Read(0, 100)
	for _, r := range recs {
		b := &fleetv1.EventBatch{}
		if err := proto.Unmarshal(r.Payload, b); err != nil {
			t.Fatal(err)
		}
		b.Seq = r.Seq
		if err := st.Send(b); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 20; i++ {
		if _, err := st.Recv(); err != nil {
			t.Fatal(err)
		}
	}
	// Acks never reached the spool; push for real now.
	fill(t, sp, 20, 5)
	p := New(cl, sp, Options{BackoffMin: 10 * time.Millisecond, BackoffMax: 50 * time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.Run(ctx) }()
	waitAcked(t, sp, 25, 10*time.Second)
	cancel()
	<-done
	sp.Close()
	s := checkAll(t, srv, 25)
	if s.Duplicates != 20 || s.Batches != 25 {
		t.Fatalf("server %+v, want 20 duplicates and 25 batches", s)
	}
}

func TestResourceExhaustedHalvesWindow(t *testing.T) {
	srv, sp, p, stop := setup(t, Options{Window: 16, BackoffMin: 10 * time.Millisecond, BackoffMax: 50 * time.Millisecond})
	srv.Stop()
	srv.Exhaust(2)
	srv.Start()
	fill(t, sp, 0, 10)
	waitAcked(t, sp, 10, 10*time.Second)
	stop()
	checkAll(t, srv, 10)
	if p.C.Throttled.Load() != 2 {
		t.Fatalf("throttled %d, want 2", p.C.Throttled.Load())
	}
	if w := p.C.Window.Load(); w < 4 || w > 16 {
		t.Fatalf("window %d", w)
	}
}
