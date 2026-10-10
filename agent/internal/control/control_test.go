package control

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	fleetv1 "github.com/strata/strata/agent/gen/strata/fleet/v1"
)

type fakeFleet struct {
	fleetv1.UnimplementedFleetServiceServer
	mu       sync.Mutex
	streams  int
	first    []string // type of the first message of each stream
	beats    int
	dropNext bool // end the next stream right after Hello
}

func (f *fakeFleet) Connect(st fleetv1.FleetService_ConnectServer) error {
	f.mu.Lock()
	f.streams++
	drop := f.dropNext
	f.dropNext = false
	f.mu.Unlock()
	first := true
	for {
		m, err := st.Recv()
		if err != nil {
			return nil
		}
		f.mu.Lock()
		if first {
			kind := "other"
			if m.GetHello() != nil {
				kind = "hello"
			}
			f.first = append(f.first, kind)
			first = false
		}
		if m.GetHeartbeat() != nil {
			f.beats++
		}
		f.mu.Unlock()
		if drop {
			return status.Error(codes.Unavailable, "restarting")
		}
	}
}

func (f *fakeFleet) snapshot() (int, []string, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.streams, append([]string(nil), f.first...), f.beats
}

func client(t *testing.T, srv fleetv1.FleetServiceServer) fleetv1.FleetServiceClient {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	fleetv1.RegisterFleetServiceServer(gs, srv)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	conn, err := grpc.NewClient("passthrough:///fleet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return fleetv1.NewFleetServiceClient(conn)
}

func eventually(t *testing.T, what string, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !f() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestHelloHeartbeatsAndReconnect(t *testing.T) {
	f := &fakeFleet{dropNext: true}
	c := New(client(t, f), Options{
		Heartbeat: 30 * time.Millisecond, BackoffMin: 10 * time.Millisecond, BackoffMax: 20 * time.Millisecond,
		Node: &fleetv1.NodeInfo{Hostname: "edge-01"},
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()

	// The first stream is dropped by the server; the agent comes back.
	eventually(t, "a reconnect", func() bool { n, _, _ := f.snapshot(); return n >= 2 })
	eventually(t, "heartbeats", func() bool { _, _, b := f.snapshot(); return b >= 3 })
	_, first, _ := f.snapshot()
	for i, k := range first {
		if k != "hello" {
			t.Fatalf("stream %d started with %s, not Hello", i, k)
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

// A control plane without Connect (older lab) does not make the agent spin.
func TestUnimplementedStops(t *testing.T) {
	c := New(client(t, &fleetv1.UnimplementedFleetServiceServer{}), Options{BackoffMin: time.Millisecond, BackoffMax: time.Millisecond})
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := c.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) < 150*time.Millisecond {
		t.Fatal("Run returned before ctx was done")
	}
}
