package fleet

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	fleetv1 "github.com/strata/strata/agent/gen/strata/fleet/v1"
	"github.com/strata/strata/control-plane/policy"
	"github.com/strata/strata/control-plane/store"
)

type memObjects map[string][]byte

func (m memObjects) Open(_ context.Context, key string, off int64) (io.ReadCloser, error) {
	b, ok := m[key]
	if !ok {
		return nil, errors.New("no object")
	}
	return io.NopCloser(bytes.NewReader(b[off:])), nil
}

func fetch(t *testing.T, cl fleetv1.FleetServiceClient, version, offset uint64) ([]byte, []uint64, error) {
	t.Helper()
	st, err := cl.FetchBundle(context.Background(), &fleetv1.FetchBundleRequest{Version: version, Offset: offset})
	if err != nil {
		return nil, nil, err
	}
	var data []byte
	var offs []uint64
	for {
		c, err := st.Recv()
		if errors.Is(err, io.EOF) {
			return data, offs, nil
		}
		if err != nil {
			return data, offs, err
		}
		offs = append(offs, c.GetOffset())
		data = append(data, c.GetData()...)
	}
}

func TestFetchBundleChunksResumeAndRefusals(t *testing.T) {
	payload := bytes.Repeat([]byte("strata-bundle-"), 200_000) // 2.8 MB: three chunks
	dir, err := policy.NewFS(t.TempDir(), policy.DefaultMutableKeys)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dir.Close() })
	if err := dir.Put(t.Context(), "bundles/7", payload, ""); err != nil {
		t.Fatal(err)
	}
	// in memory, and in a directory (CP-A07)
	for name, objects := range map[string]BundleObjects{"memory": memObjects{"bundles/7": payload}, "filesystem": dir} {
		t.Run(name, func(t *testing.T) { fetchBundleChunks(t, objects, payload) })
	}
}

func fetchBundleChunks(t *testing.T, objects BundleObjects, payload []byte) {
	p := newPKI(t)
	reg := newMemRegistry()
	sum := sha256.Sum256(payload)
	reg.desired["node-a"] = store.Bundle{Version: 7, SHA256: sum[:], ObjectKey: "bundles/7", SizeBytes: int64(len(payload))}
	srv := NewServer(Config{Ingest: nopIngest{}, Registry: reg, Objects: objects})
	addr := serveServer(t, p, srv)
	cert := p.nodeCert(t, "node-a")
	reg.nodes["node-a"] = store.Node{ID: "node-a", CertSerial: leafSerial(t, cert)}
	cl := dial(t, p, addr, &cert)

	data, offs, err := fetch(t, cl, 7, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, payload) || len(offs) != 3 || offs[1] != ChunkSize {
		t.Fatalf("got %d bytes in chunks at %v", len(data), offs)
	}
	// Resume where an interrupted download stopped.
	rest, offs, err := fetch(t, cl, 7, 1_500_000)
	if err != nil || !bytes.Equal(rest, payload[1_500_000:]) || offs[0] != 1_500_000 {
		t.Fatalf("resume: %d bytes from %v, %v", len(rest), offs, err)
	}
	if _, _, err := fetch(t, cl, 6, 0); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("another version: %v", err)
	}
	if _, _, err := fetch(t, cl, 7, uint64(len(payload))+1); status.Code(err) != codes.OutOfRange {
		t.Fatalf("offset past the end: %v", err)
	}
	other := p.nodeCert(t, "node-b")
	reg.nodes["node-b"] = store.Node{ID: "node-b", CertSerial: leafSerial(t, other)}
	if _, _, err := fetch(t, dial(t, p, addr, &other), 7, 0); status.Code(err) != codes.NotFound {
		t.Fatalf("node with nothing due: %v", err)
	}
}

// Hello gets the desired version back; BundleStatus reaches the registry.
func TestConnectSendsDesiredBundleAndRecordsStatus(t *testing.T) {
	p := newPKI(t)
	reg := newMemRegistry()
	srv := NewServer(Config{Ingest: nopIngest{}, Registry: reg, Presence: NewPresence()})
	addr := serveServer(t, p, srv)
	cert := p.nodeCert(t, "node-a")
	reg.nodes["node-a"] = store.Node{ID: "node-a", CertSerial: leafSerial(t, cert)}
	reg.desired["node-a"] = store.Bundle{Version: 9, SHA256: make([]byte, 32), SizeBytes: 100}

	st, cancel := connect(t, dial(t, p, addr, &cert), true) // Hello says version 1
	defer cancel()
	m, err := st.Recv()
	if err != nil || m.GetBundleAvailable().GetVersion() != 9 || m.GetBundleAvailable().GetRollback() {
		t.Fatalf("after Hello: %v %v", m, err)
	}
	// Pushed while connected.
	srv.Presence().Notify("node-a", BundleAvailable(store.Bundle{Version: 10, SHA256: make([]byte, 32)}, false))
	if m, err := st.Recv(); err != nil || m.GetBundleAvailable().GetVersion() != 10 {
		t.Fatalf("pushed: %v %v", m, err)
	}
	_ = st.Send(&fleetv1.AgentMessage{Msg: &fleetv1.AgentMessage_BundleStatus{BundleStatus: &fleetv1.BundleStatus{
		Version: 9, State: fleetv1.BundleStatus_STATE_ACTIVE}}})
	eventually(t, "status recorded", func() bool {
		reg.mu.Lock()
		defer reg.mu.Unlock()
		return len(reg.statuses) == 1 && reg.statuses[0] == "node-a/9/ACTIVE"
	})
}

// fakeRollouts is an in-memory RolloutStore.
type fakeRollouts struct {
	mu      sync.Mutex
	nodes   []string
	ro      store.Rollout
	desired map[string]uint64
}

func (f *fakeRollouts) EnrolledNodes(context.Context) ([]string, error) { return f.nodes, nil }
func (f *fakeRollouts) CreateRollout(_ context.Context, v uint64, nodes []string, plan []float64, soak time.Duration, _ store.Audit) (store.Rollout, []string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	waves := store.WavePlan(len(nodes), plan)
	f.ro = store.Rollout{ID: 1, BundleVersion: v, State: store.RolloutRunning, Waves: waves, SoakSeconds: int(soak.Seconds())}
	var first []string
	for i, n := range nodes {
		w := 0
		for w < len(waves) && i >= waves[w] {
			w++
		}
		st := "PENDING"
		if w == 0 {
			st, f.desired[n] = "NOTIFIED", v
			first = append(first, n)
		}
		f.ro.Nodes = append(f.ro.Nodes, store.RolloutNode{NodeID: n, Wave: w, State: st})
	}
	return f.ro, first, nil
}
func (f *fakeRollouts) ActiveRollouts(context.Context) ([]store.Rollout, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ro.State != store.RolloutRunning {
		return nil, nil
	}
	r := f.ro
	r.Nodes = append([]store.RolloutNode(nil), f.ro.Nodes...)
	return []store.Rollout{r}, nil
}
func (f *fakeRollouts) AdvanceRollout(_ context.Context, _ int64) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ro.CurrentWave++
	f.ro.WaveDoneAt = nil
	if f.ro.CurrentWave >= len(f.ro.Waves) {
		f.ro.State = store.RolloutDone
		return nil, nil
	}
	var next []string
	for i := range f.ro.Nodes {
		if f.ro.Nodes[i].Wave == f.ro.CurrentWave {
			f.ro.Nodes[i].State = "NOTIFIED"
			f.desired[f.ro.Nodes[i].NodeID] = f.ro.BundleVersion
			next = append(next, f.ro.Nodes[i].NodeID)
		}
	}
	return next, nil
}
func (f *fakeRollouts) MarkWaveDone(_ context.Context, _ int64, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ro.WaveDoneAt == nil {
		f.ro.WaveDoneAt = &at
	}
	return nil
}
func (f *fakeRollouts) SetRolloutState(_ context.Context, _ int64, to, reason string, _ []string, _ store.Audit) (store.Rollout, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ro.State, f.ro.Reason = to, reason
	return f.ro, nil
}
func (f *fakeRollouts) DesiredBundle(_ context.Context, n string) (store.Bundle, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return store.Bundle{Version: f.desired[n]}, nil
}
func (f *fakeRollouts) report(node, state string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.ro.Nodes {
		if f.ro.Nodes[i].NodeID == node {
			f.ro.Nodes[i].State = state
		}
	}
}
func (f *fakeRollouts) has(node string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.desired[node]
	return ok
}

func TestRolloutWavesInOrder(t *testing.T) {
	f := &fakeRollouts{nodes: []string{"n1", "n2", "n3"}, desired: map[string]uint64{}}
	r := NewRollouts(f, NewPresence(), DefaultWaves, 0)
	ctx := context.Background()
	ro, err := r.Start(ctx, store.Bundle{Version: 5}, store.Audit{Actor: "alice"})
	if err != nil || len(ro.Waves) != 3 {
		t.Fatalf("%+v %v", ro, err)
	}
	if !f.has("n1") || f.has("n2") || f.has("n3") {
		t.Fatalf("first wave: %v", f.desired)
	}
	_ = r.Tick(ctx) // n1 not ACTIVE yet: nothing moves
	if f.has("n2") {
		t.Fatal("wave 2 started before wave 1 was ACTIVE")
	}
	f.report("n1", "ACTIVE")
	_ = r.Tick(ctx)
	if !f.has("n2") || f.has("n3") {
		t.Fatalf("second wave: %v", f.desired)
	}
	f.report("n2", "ACTIVE")
	_ = r.Tick(ctx)
	f.report("n3", "ACTIVE")
	_ = r.Tick(ctx)
	if f.ro.State != store.RolloutDone {
		t.Fatalf("state %s", f.ro.State)
	}
}

func TestRolloutStopsOnFailure(t *testing.T) {
	f := &fakeRollouts{nodes: []string{"n1", "n2", "n3"}, desired: map[string]uint64{}}
	r := NewRollouts(f, NewPresence(), DefaultWaves, 0)
	ctx := context.Background()
	_, _ = r.Start(ctx, store.Bundle{Version: 5}, store.Audit{})
	f.report("n1", "FAILED")
	_ = r.Tick(ctx)
	_ = r.Tick(ctx)
	if f.ro.State != store.RolloutFailed || f.has("n2") {
		t.Fatalf("state %s, desired %v", f.ro.State, f.desired)
	}
}

func TestRolloutSoaks(t *testing.T) {
	f := &fakeRollouts{nodes: []string{"n1", "n2"}, desired: map[string]uint64{}}
	r := NewRollouts(f, NewPresence(), DefaultWaves, time.Minute)
	now := time.Unix(1_800_000_000, 0)
	r.Now = func() time.Time { return now }
	ctx := context.Background()
	_, _ = r.Start(ctx, store.Bundle{Version: 5}, store.Audit{})
	f.report("n1", "ACTIVE")
	_ = r.Tick(ctx)
	now = now.Add(30 * time.Second)
	_ = r.Tick(ctx)
	if f.has("n2") {
		t.Fatal("next wave before the soak time")
	}
	now = now.Add(31 * time.Second)
	_ = r.Tick(ctx)
	if !f.has("n2") {
		t.Fatal("next wave not started after the soak time")
	}
}

func leafSerial(t *testing.T, c tls.Certificate) string {
	t.Helper()
	x, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return x.SerialNumber.Text(16)
}
