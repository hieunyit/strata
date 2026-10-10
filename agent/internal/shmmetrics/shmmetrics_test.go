package shmmetrics

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// fixture builds a metrics file the way the module will (control-file.md
// › "Metrics file"); slots maps a slot index to its counters.
type fixture struct {
	slots    int
	slotSize int
	counters int
	values   map[int][]uint64
}

func (f fixture) bytes() []byte {
	if f.counters == 0 {
		f.counters = NumCounters
	}
	if f.slotSize == 0 {
		f.slotSize = (8*f.counters + 63) / 64 * 64
	}
	b := make([]byte, headerSize+f.slots*f.slotSize)
	copy(b, magic)
	le := binary.LittleEndian
	le.PutUint32(b[8:], layoutVersion)
	le.PutUint32(b[12:], uint32(f.slots))
	le.PutUint32(b[16:], uint32(f.slotSize))
	le.PutUint32(b[20:], uint32(f.counters))
	le.PutUint64(b[24:], 1760000000000)
	for i, vals := range f.values {
		for k, v := range vals {
			le.PutUint64(b[headerSize+i*f.slotSize+8*k:], v)
		}
	}
	return b
}

func write(t *testing.T, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "metrics")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// slot: pid, bundle, allow, log, challenge, block, body, open, closed,
// dropped, budget, engine ns, then 9 buckets.
var (
	worker0 = []uint64{1001, 42, 100, 5, 0, 7, 4096, 1, 0, 3, 2, 3_000_000, 50, 30, 20, 10, 2, 0, 0, 0, 0}
	worker2 = []uint64{1003, 41, 50, 0, 1, 3, 1024, 0, 2, 0, 0, 1_000_000, 10, 10, 10, 10, 10, 2, 1, 1, 0}
)

func TestRead(t *testing.T) {
	p := write(t, fixture{slots: 4, values: map[int][]uint64{0: worker0, 2: worker2}}.bytes())
	s, err := Read(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Workers) != 2 || s.Workers[0].Index != 0 || s.Workers[1].Index != 2 {
		t.Fatalf("workers %+v", s.Workers)
	}
	w := s.Workers[1]
	if w.PID != 1003 || w.BundleVersion != 41 || w.Requests != [4]uint64{50, 0, 1, 3} ||
		w.FailClosed != 2 || w.EngineBuckets[5] != 2 || w.EngineBuckets[8] != 0 {
		t.Fatalf("worker 2 %+v", w)
	}
}

func TestReadRejectsBadLayout(t *testing.T) {
	good := fixture{slots: 2, values: map[int][]uint64{0: worker0}}
	for name, b := range map[string][]byte{
		"empty":        {},
		"short header": good.bytes()[:40],
		"magic": func() []byte {
			b := good.bytes()
			b[0] = 'X'
			return b
		}(),
		"version": func() []byte {
			b := good.bytes()
			binary.LittleEndian.PutUint32(b[8:], 2)
			return b
		}(),
		"no slots":         fixture{slots: 0}.bytes(),
		"too few counters": fixture{slots: 1, counters: 20}.bytes(),
		"slot not aligned": fixture{slots: 1, slotSize: 200}.bytes(),
		"slot too small":   fixture{slots: 1, counters: 30, slotSize: 192}.bytes(),
		"truncated":        good.bytes()[:headerSize+100],
		"trailing bytes":   append(good.bytes(), make([]byte, 64)...),
		"slot count lies": func() []byte {
			b := good.bytes()
			binary.LittleEndian.PutUint32(b[12:], 1000)
			return b
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Read(write(t, b)); !errors.Is(err, ErrLayout) {
				t.Fatalf("Read: %v, want ErrLayout", err)
			}
		})
	}
	if _, err := Read(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing file read")
	}
}

func TestReadMoreCounters(t *testing.T) {
	// A newer module appends counters; the agent ignores them.
	vals := append(append([]uint64{}, worker0...), 99, 99)
	p := write(t, fixture{slots: 1, counters: NumCounters + 2, values: map[int][]uint64{0: vals}}.bytes())
	s, err := Read(p)
	if err != nil || len(s.Workers) != 1 || s.Workers[0].Requests[0] != 100 {
		t.Fatalf("Read: %+v %v", s, err)
	}
}

const wantMetrics = `
# HELP strata_bundle_version Bundle version running in each worker.
# TYPE strata_bundle_version gauge
strata_bundle_version{worker="0"} 42
strata_bundle_version{worker="2"} 41
# HELP strata_engine_seconds Time spent in libstrata per request.
# TYPE strata_engine_seconds histogram
strata_engine_seconds_bucket{le="5e-05"} 60
strata_engine_seconds_bucket{le="0.0001"} 100
strata_engine_seconds_bucket{le="0.0002"} 130
strata_engine_seconds_bucket{le="0.0005"} 150
strata_engine_seconds_bucket{le="0.001"} 162
strata_engine_seconds_bucket{le="0.002"} 164
strata_engine_seconds_bucket{le="0.005"} 165
strata_engine_seconds_bucket{le="0.01"} 166
strata_engine_seconds_bucket{le="+Inf"} 166
strata_engine_seconds_sum 0.004
strata_engine_seconds_count 166
# HELP strata_fail_mode_total Requests handled by the fail mode, by mode.
# TYPE strata_fail_mode_total counter
strata_fail_mode_total{mode="closed"} 2
strata_fail_mode_total{mode="open"} 1
# HELP strata_metrics_file_up 1 when the NGINX metrics file was read and follows the layout.
# TYPE strata_metrics_file_up gauge
strata_metrics_file_up 1
# HELP strata_requests_total Requests inspected, by action.
# TYPE strata_requests_total counter
strata_requests_total{action="allow"} 150
strata_requests_total{action="block"} 10
strata_requests_total{action="challenge"} 1
strata_requests_total{action="log"} 5
# HELP strata_workers NGINX workers with a slot in the metrics file.
# TYPE strata_workers gauge
strata_workers 2
`

func TestCollector(t *testing.T) {
	p := write(t, fixture{slots: 4, values: map[int][]uint64{0: worker0, 2: worker2}}.bytes())
	c := NewCollector(p)
	err := testutil.CollectAndCompare(c, strings.NewReader(wantMetrics),
		"strata_bundle_version", "strata_engine_seconds", "strata_fail_mode_total",
		"strata_metrics_file_up", "strata_requests_total", "strata_workers")
	if err != nil {
		t.Fatal(err)
	}
	// Same checks as promtool check metrics.
	problems, err := testutil.CollectAndLint(c)
	if err != nil || len(problems) != 0 {
		t.Fatalf("lint: %v %+v", err, problems)
	}
}

func TestCollectorWithoutFile(t *testing.T) {
	c := NewCollector(filepath.Join(t.TempDir(), "missing"))
	want := "# HELP strata_metrics_file_up 1 when the NGINX metrics file was read and follows the layout.\n" +
		"# TYPE strata_metrics_file_up gauge\nstrata_metrics_file_up 0\n"
	if err := testutil.CollectAndCompare(c, strings.NewReader(want)); err != nil {
		t.Fatal(err)
	}
}

func TestServe(t *testing.T) {
	reg := prometheus.NewRegistry()
	reg.MustRegister(NewCollector(write(t, fixture{slots: 1, values: map[int][]uint64{0: worker0}}.bytes())))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- ServeListener(ctx, ln, reg) }()
	resp, err := http.Get("http://" + ln.Addr().String() + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), `strata_requests_total{action="block"} 7`) {
		t.Fatalf("scrape:\n%s", body)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
