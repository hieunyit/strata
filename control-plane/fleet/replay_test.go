package fleet

import (
	"context"
	"sync"
	"testing"
	"time"

	eventv1 "github.com/strata/strata/agent/gen/strata/event/v1"
	fleetv1 "github.com/strata/strata/agent/gen/strata/fleet/v1"
	"github.com/strata/strata/control-plane/ingest"
	"github.com/strata/strata/control-plane/store"
)

type sampleSink struct {
	mu  sync.Mutex
	got map[string]int
}

func (s *sampleSink) Add(_ context.Context, node string, samples []*eventv1.ReplaySample) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.got[node] += len(samples)
}

// W12-N-01: the samples of a batch reach the sink once: a resent batch
// (seq seen before) is acked but its samples are not taken again.
func TestSamplesOfNewBatchesOnly(t *testing.T) {
	p := newPKI(t)
	svc := ingest.NewIngestService(ingest.NewMockEventStore(), ingest.DefaultBatcherConfig(), time.Hour)
	t.Cleanup(func() { _ = svc.Close(context.Background()) })
	sink := &sampleSink{got: map[string]int{}}
	addr := serveServer(t, p, NewServer(Config{Ingest: svc, Samples: sink}))
	cert := p.nodeCert(t, "node-1")
	cl := dial(t, p, addr, &cert)
	s := func() *eventv1.ReplaySample {
		return &eventv1.ReplaySample{AnonKeyId: "k1", Policy: []byte("example-api"), Method: []byte("GET")}
	}
	acks, err := push(t, cl,
		&fleetv1.EventBatch{Seq: 1, Events: []*eventv1.Event{event("STR-8F3K-Q2VD-7XNM-A1PC")}, Samples: []*eventv1.ReplaySample{s(), s()}},
		&fleetv1.EventBatch{Seq: 2, Samples: []*eventv1.ReplaySample{s()}},
		&fleetv1.EventBatch{Seq: 1, Samples: []*eventv1.ReplaySample{s(), s()}}, // resent
	)
	if err != nil || len(acks) != 3 {
		t.Fatalf("%v %v", acks, err)
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if sink.got["node-1"] != 3 {
		t.Fatalf("samples %v", sink.got)
	}
}

// replayRegistry adds the replay sampling of the groups to memRegistry.
type replayRegistry struct {
	*memRegistry
	rows map[string]store.ReplaySampling // by node
}

func (r *replayRegistry) NodeReplaySampling(_ context.Context, node string) (store.ReplaySampling, error) {
	return r.rows[node], nil
}

// The key goes to the node when it connects and with a REPLAY_SYNC
// command, read from the store when the command is sent.
func TestReplaySamplingReachesTheNode(t *testing.T) {
	e := newEnrollEnv(t)
	key := []byte("0123456789abcdef0123456789abcdef")
	reg := &replayRegistry{memRegistry: e.reg, rows: map[string]store.ReplaySampling{}}
	e.srv = NewServer(Config{Ingest: nopIngest{}, Registry: reg, CA: e.p.nodeCA(t), TrustBundle: []byte("trust"),
		BundlePubKey: []byte("bundle-pub"), Presence: NewPresence()})
	e.addr = serveServer(t, e.p, e.srv)
	e.reg.addToken("tok-a", time.Hour)
	r, pair, err := e.enroll(t, "tok-a")
	if err != nil {
		t.Fatal(err)
	}
	node := r.GetNodeId()
	reg.rows[node] = store.ReplaySampling{RateBp: 100, KeyID: "kabc", Key: key}
	st, cancel := connect(t, dial(t, e.p, e.addr, &pair), true)
	defer cancel()
	m, err := st.Recv()
	if err != nil {
		t.Fatal(err)
	}
	rs := m.GetCommand().GetReplaySampling()
	if m.GetCommand().GetId() != syncCommandPrefix+"replay-"+node || rs.GetRateBp() != 100 || rs.GetKeyId() != "kabc" || string(rs.GetKey()) != string(key) {
		t.Fatalf("hello: %v", m)
	}

	// the group changes: a REPLAY_SYNC command, filled when sent
	reg.rows[node] = store.ReplaySampling{} // switched off
	e.reg.mu.Lock()
	e.reg.commands = []store.Command{{ID: "cmd-r1", NodeID: node, Kind: store.CommandReplaySync, State: store.CommandPending,
		ExpiresAt: time.Now().Add(time.Minute)}}
	e.reg.mu.Unlock()
	eventually(t, "online", func() bool { return e.srv.Presence().Connected(node) })
	cmds := NewCommands(regCommands{reg}, e.srv.Presence())
	if err := cmds.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	m, err = st.Recv()
	if err != nil {
		t.Fatal(err)
	}
	rs = m.GetCommand().GetReplaySampling()
	if m.GetCommand().GetId() != "cmd-r1" || rs == nil || rs.GetRateBp() != 0 || len(rs.GetKey()) != 0 {
		t.Fatalf("sync: %v", m)
	}
}

// regCommands: the dispatcher's store with the replay source.
type regCommands struct{ *replayRegistry }
