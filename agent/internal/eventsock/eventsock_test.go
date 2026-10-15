package eventsock

import (
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	eventv1 "github.com/strata/strata/agent/gen/strata/event/v1"
)

func send(t *testing.T, path string, b []byte) {
	t.Helper()
	c, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write(b); err != nil {
		t.Fatal(err)
	}
}

func encode(t *testing.T, ev *eventv1.Event) []byte {
	t.Helper()
	b, err := proto.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestReceive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.sock")
	l, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o660 {
		t.Fatalf("socket mode %v %v", fi.Mode(), err)
	}

	got := make(chan *eventv1.Event, 10)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- l.Run(ctx, func(ev *eventv1.Event) { got <- ev }) }()

	send(t, path, encode(t, &eventv1.Event{BlockId: "STR-8F3K-Q2VD-7XNM-A1PC", Host: "api.example.test",
		Action: eventv1.Action_ACTION_BLOCK, Matches: []*eventv1.Match{{RuleId: 100001, Snippet: []byte("x")}}}))
	send(t, path, []byte{0xff, 0xff, 0xff})                            // not protobuf
	send(t, path, encode(t, &eventv1.Event{Host: "api.example.test"})) // no Block ID
	send(t, path, encode(t, &eventv1.Event{BlockId: string(bytes.Repeat([]byte("A"), 65))}))
	big := encode(t, &eventv1.Event{BlockId: "STR-BIG", Path: string(bytes.Repeat([]byte("/a"), MaxDatagram))})
	send(t, path, big) // above 8 KB
	send(t, path, encode(t, &eventv1.Event{BlockId: "EVT-0000-0000-0000-0002"}))

	for _, want := range []string{"STR-8F3K-Q2VD-7XNM-A1PC", "EVT-0000-0000-0000-0002"} {
		select {
		case ev := <-got:
			if ev.GetBlockId() != want {
				t.Fatalf("got %q, want %q", ev.GetBlockId(), want)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("no event %s", want)
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run: %v", err)
	}
	if r, i, tr := l.C.Received.Load(), l.C.Invalid.Load(), l.C.Truncated.Load(); r != 6 || i != 3 || tr != 1 {
		t.Fatalf("received %d invalid %d truncated %d", r, i, tr)
	}
}

func TestListenReplacesStaleSocketOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.sock")
	l, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	l.conn.Close() // leaves the path behind, like a killed agent
	l2, err := Listen(path)
	if err != nil {
		t.Fatalf("stale socket not replaced: %v", err)
	}
	l2.Close()

	file := filepath.Join(dir, "regular")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(file); err == nil {
		t.Fatal("Listen replaced a regular file")
	}
}

func FuzzDecode(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x0a, 0x03, 'S', 'T', 'R'})
	f.Fuzz(func(t *testing.T, b []byte) {
		ev, ok := Decode(b)
		if ok && (ev.GetBlockId() == "" || len(ev.GetBlockId()) > maxBlockID) {
			t.Fatalf("accepted %q", ev.GetBlockId())
		}
	})
}

// W12-N-01: a datagram that starts with SampleMagic is a replay sample.
func TestSamples(t *testing.T) {
	good, _ := proto.Marshal(&eventv1.ReplaySample{AnonKeyId: "k1", Policy: []byte("example-api"), Method: []byte("GET")})
	if s, ok := DecodeSample(good); !ok || string(s.GetPolicy()) != "example-api" {
		t.Fatalf("%v %v", s, ok)
	}
	for _, bad := range []*eventv1.ReplaySample{{Policy: []byte("p")}, {AnonKeyId: "k1"}, {AnonKeyId: "a-key-id-longer-than-16", Policy: []byte("p")}} {
		b, _ := proto.Marshal(bad)
		if _, ok := DecodeSample(b); ok {
			t.Errorf("%v accepted", bad)
		}
	}
	if _, ok := DecodeSample([]byte{0xff, 0xff}); ok {
		t.Error("garbage accepted")
	}
}

// RV-N-01: per-policy counters datagrams go to OnCounters; without it they
// count as invalid, as on an agent from before them.
func TestCounters(t *testing.T) {
	for _, handled := range []bool{true, false} {
		path := filepath.Join(t.TempDir(), "events.sock")
		l, err := Listen(path)
		if err != nil {
			t.Fatal(err)
		}
		got := make(chan *eventv1.PolicyCounters, 1)
		if handled {
			l.OnCounters = func(c *eventv1.PolicyCounters) { got <- c }
		}
		events := make(chan *eventv1.Event, 1)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- l.Run(ctx, func(ev *eventv1.Event) { events <- ev }) }()
		b, _ := proto.Marshal(&eventv1.PolicyCounters{NodeId: "edge-01",
			Policies: []*eventv1.PolicyCount{{Policy: "example-api", Requests: 7, Partial: 1}}})
		send(t, path, append([]byte(CountersMagic), b...))
		send(t, path, encode(t, &eventv1.Event{BlockId: "EVT-0000-0000-0000-0003"}))
		<-events // the datagram before it was read
		if handled {
			c := <-got
			if p := c.GetPolicies(); len(p) != 1 || p[0].GetRequests() != 7 || p[0].GetPartial() != 1 {
				t.Fatalf("%v", c)
			}
		}
		cancel()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		l.Close()
		want := [2]uint64{1, 0}
		if !handled {
			want = [2]uint64{0, 1}
		}
		if got := [2]uint64{l.C.Policies.Load(), l.C.Invalid.Load()}; got != want {
			t.Fatalf("handled %v: policies, invalid = %v, want %v", handled, got, want)
		}
	}
}
