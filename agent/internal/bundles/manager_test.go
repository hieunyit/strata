package bundles

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"strings"
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

// signed is a bundle with the real header layout, signed with priv.
func signed(priv ed25519.PrivateKey, version uint64, size int) []byte {
	b := make([]byte, size-64)
	copy(b, "STRBNDL\x00")
	binary.LittleEndian.PutUint16(b[8:], 1)
	binary.LittleEndian.PutUint64(b[16:], version)
	for i := 64; i < len(b); i++ {
		b[i] = byte(i)
	}
	return append(b, ed25519.Sign(priv, b)...)
}

type fakeFleet struct {
	fleetv1.UnimplementedFleetServiceServer
	mu      sync.Mutex
	bundles map[uint64][]byte
	cutOnce map[uint64]bool // end the first stream after one chunk
	offsets []uint64
}

func (f *fakeFleet) FetchBundle(req *fleetv1.FetchBundleRequest, st fleetv1.FleetService_FetchBundleServer) error {
	f.mu.Lock()
	data, ok := f.bundles[req.GetVersion()]
	cut := f.cutOnce[req.GetVersion()]
	f.cutOnce[req.GetVersion()] = false
	f.offsets = append(f.offsets, req.GetOffset())
	f.mu.Unlock()
	if !ok {
		return status.Error(codes.NotFound, "no bundle")
	}
	const chunk = 4096
	for off := req.GetOffset(); off < uint64(len(data)); off += chunk {
		end := min(off+chunk, uint64(len(data)))
		if err := st.Send(&fleetv1.BundleChunk{Offset: off, Data: data[off:end]}); err != nil {
			return err
		}
		if cut {
			return status.Error(codes.Unavailable, "network cut")
		}
	}
	return nil
}

type env struct {
	m        *Manager
	fleet    *fakeFleet
	dir, ctl string
	priv     ed25519.PrivateKey
	mu       sync.Mutex
	got      []string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(nil)
	e := &env{fleet: &fakeFleet{bundles: map[uint64][]byte{}, cutOnce: map[uint64]bool{}}, priv: priv}
	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	fleetv1.RegisterFleetServiceServer(gs, e.fleet)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	conn, err := grpc.NewClient("passthrough:///f", grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	root := t.TempDir()
	e.dir, e.ctl = filepath.Join(root, "bundles"), filepath.Join(root, "control")
	e.m, err = New(fleetv1.NewFleetServiceClient(conn), Options{
		Dir: e.dir, ControlFile: e.ctl, PubKey: pub, ActiveDelay: 10 * time.Millisecond,
		BackoffMin: 5 * time.Millisecond, BackoffMax: 10 * time.Millisecond,
	}, func(bs *fleetv1.BundleStatus) {
		e.mu.Lock()
		defer e.mu.Unlock()
		s := bs.GetState().String()
		if bs.GetError() != "" {
			s += ":" + bs.GetError()
		}
		e.got = append(e.got, s)
	})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *env) publish(v uint64, data []byte) *fleetv1.BundleAvailable {
	e.fleet.mu.Lock()
	e.fleet.bundles[v] = data
	e.fleet.mu.Unlock()
	sum := sha256.Sum256(data)
	return &fleetv1.BundleAvailable{Version: v, Sha256: sum[:], SizeBytes: uint64(len(data))}
}

func (e *env) offer(ba *fleetv1.BundleAvailable) []string {
	e.mu.Lock()
	e.got = nil
	e.mu.Unlock()
	e.m.Offer(context.Background(), ba)
	e.m.Wait()
	time.Sleep(20 * time.Millisecond) // statuses sent from goroutines
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.got...)
}

func TestInstall(t *testing.T) {
	e := newEnv(t)
	data := signed(e.priv, 3, 20000)
	got := e.offer(e.publish(3, data))
	want := []string{"STATE_DOWNLOADING", "STATE_VERIFIED", "STATE_ACTIVE"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("statuses %v", got)
	}
	c, err := ReadControl(e.ctl)
	if err != nil || c.Version != 3 || c.Name != "bundle-3.sbn" || c.SHA256 != sha256.Sum256(data) {
		t.Fatalf("control %+v %v", c, err)
	}
	stored, _ := os.ReadFile(filepath.Join(e.dir, "bundle-3.sbn"))
	if string(stored) != string(data) || e.m.Active() != 3 {
		t.Fatal("bundle not stored")
	}
	if left, _ := filepath.Glob(filepath.Join(e.dir, ".*")); len(left) != 0 {
		t.Fatalf("leftovers %v", left)
	}
	// Announced again: already running.
	if got := e.offer(e.publish(3, data)); len(got) != 1 || got[0] != "STATE_ACTIVE" {
		t.Fatalf("again: %v", got)
	}
}

func TestResumesAnInterruptedDownload(t *testing.T) {
	e := newEnv(t)
	data := signed(e.priv, 4, 20000)
	ba := e.publish(4, data)
	e.fleet.cutOnce[4] = true
	if got := e.offer(ba); got[len(got)-1] != "STATE_ACTIVE" {
		t.Fatalf("statuses %v", got)
	}
	if len(e.fleet.offsets) != 2 || e.fleet.offsets[0] != 0 || e.fleet.offsets[1] != 4096 {
		t.Fatalf("fetch offsets %v, want [0 4096]", e.fleet.offsets)
	}
}

func TestRefusals(t *testing.T) {
	e := newEnv(t)
	_ = e.offer(e.publish(5, signed(e.priv, 5, 8192)))
	_, other, _ := ed25519.GenerateKey(nil)
	for name, tc := range map[string]struct {
		ba   func() *fleetv1.BundleAvailable
		want string
	}{
		"signed with another key": {func() *fleetv1.BundleAvailable { return e.publish(6, signed(other, 6, 8192)) }, "signature"},
		"sha256 differs": {func() *fleetv1.BundleAvailable {
			ba := e.publish(7, signed(e.priv, 7, 8192))
			ba.Sha256 = make([]byte, 32)
			return ba
		}, "sha256"},
		"header names another version": {func() *fleetv1.BundleAvailable { return e.publish(8, signed(e.priv, 9, 8192)) }, "version 9"},
		"older and not a rollback":     {func() *fleetv1.BundleAvailable { return e.publish(2, signed(e.priv, 2, 8192)) }, "older"},
	} {
		t.Run(name, func(t *testing.T) {
			got := e.offer(tc.ba())
			last := got[len(got)-1]
			if !strings.HasPrefix(last, "STATE_FAILED") || !strings.Contains(last, tc.want) {
				t.Fatalf("statuses %v", got)
			}
			if c, _ := ReadControl(e.ctl); c.Version != 5 {
				t.Fatalf("control moved to %d", c.Version)
			}
		})
	}
}

func TestKeepsTwoBundles(t *testing.T) {
	e := newEnv(t)
	for v := uint64(1); v <= 4; v++ {
		_ = e.offer(e.publish(v, signed(e.priv, v, 8192)))
	}
	files, _ := filepath.Glob(filepath.Join(e.dir, "bundle-*.sbn"))
	if len(files) != 2 || !strings.HasSuffix(files[0], "bundle-3.sbn") || !strings.HasSuffix(files[1], "bundle-4.sbn") {
		t.Fatalf("kept %v", files)
	}
}

// After a crash: a half-renamed temporary file is removed, a partial
// download is resumed, the control file still names the old bundle.
func TestStartAfterACrash(t *testing.T) {
	e := newEnv(t)
	_ = e.offer(e.publish(1, signed(e.priv, 1, 8192)))
	data := signed(e.priv, 2, 20000)
	_ = os.WriteFile(filepath.Join(e.dir, ".tmp-bundle-2.sbn.123"), data[:100], 0o600)
	_ = os.WriteFile(filepath.Join(e.dir, ".partial-2"), data[:12288], 0o600)
	m2, err := New(e.m.client, e.m.opts, e.m.report)
	if err != nil {
		t.Fatal(err)
	}
	if m2.Active() != 1 {
		t.Fatalf("active %d after restart", m2.Active())
	}
	if left, _ := filepath.Glob(filepath.Join(e.dir, ".tmp-*")); len(left) != 0 {
		t.Fatalf("temporary file kept: %v", left)
	}
	e.m = m2
	if got := e.offer(e.publish(2, data)); got[len(got)-1] != "STATE_ACTIVE" {
		t.Fatalf("statuses %v", got)
	}
	if e.fleet.offsets[len(e.fleet.offsets)-1] != 12288 {
		t.Fatalf("did not resume: offsets %v", e.fleet.offsets)
	}
}
