package bundles

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	fleetv1 "github.com/strata/strata/agent/gen/strata/fleet/v1"
	"github.com/strata/strata/agent/internal/shmmetrics"
	"github.com/strata/strata/agent/pkg/bundlefmt"
)

// Options of a Manager.
type Options struct {
	Dir         string // strata_bundle_dir
	ControlFile string // strata_control_file
	PubKey      []byte // Ed25519, 32 bytes: bundles signed otherwise are refused
	// MetricsFile, when set and present, tells when the workers run a
	// bundle (ACTIVE). Without it (the module writes it from W07-N-01)
	// ACTIVE is reported ActiveDelay after the control file changed.
	MetricsFile string
	ActiveDelay time.Duration // default 2 s: workers check the control file every second
	// ActiveTimeout: the workers must run the bundle this soon, else FAILED.
	ActiveTimeout time.Duration // default 30 s
	BackoffMin    time.Duration // default 1 s
	BackoffMax    time.Duration // default 60 s
	Keep          int           // bundles kept, the running one included; default 2
}

// Manager installs one bundle at a time; a newer announcement replaces
// one still downloading.
type Manager struct {
	client fleetv1.FleetServiceClient
	opts   Options
	report func(*fleetv1.BundleStatus)

	mu      sync.Mutex
	active  uint64
	cancel  context.CancelFunc
	pending uint64
	done    chan struct{}
}

// New opens the bundle directory (refusing a network file system) and
// reads the running version from the control file. report sends a
// BundleStatus to the control plane.
func New(client fleetv1.FleetServiceClient, opts Options, report func(*fleetv1.BundleStatus)) (*Manager, error) {
	if len(opts.PubKey) != 32 {
		return nil, errors.New("bundles: the bundle public key must be 32 bytes")
	}
	if opts.ActiveDelay <= 0 {
		opts.ActiveDelay = 2 * time.Second
	}
	if opts.ActiveTimeout <= 0 {
		opts.ActiveTimeout = 30 * time.Second
	}
	if opts.BackoffMin <= 0 {
		opts.BackoffMin = time.Second
	}
	if opts.BackoffMax < opts.BackoffMin {
		opts.BackoffMax = 60 * time.Second
	}
	if opts.Keep < 2 {
		opts.Keep = 2
	}
	if err := os.MkdirAll(opts.Dir, 0o755); err != nil {
		return nil, fmt.Errorf("bundles: %w", err)
	}
	if err := CheckLocal(opts.Dir); err != nil {
		return nil, err
	}
	m := &Manager{client: client, opts: opts, report: report}
	switch c, err := ReadControl(opts.ControlFile); {
	case err == nil:
		m.active = c.Version
	case errors.Is(err, os.ErrNotExist):
	default:
		return nil, err
	}
	// Temporary files of an interrupted rename are garbage; partial
	// downloads are kept to resume.
	tmps, _ := filepath.Glob(filepath.Join(opts.Dir, ".tmp-*"))
	for _, t := range tmps {
		_ = os.Remove(t)
	}
	return m, nil
}

// Active is the version the control file points at.
func (m *Manager) Active() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.active
}

// Offer handles a BundleAvailable: installs it in the background unless it
// is the running version, or older without the rollback flag.
func (m *Manager) Offer(ctx context.Context, ba *fleetv1.BundleAvailable) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v := ba.GetVersion()
	switch {
	case v == m.active:
		go m.send(v, fleetv1.BundleStatus_STATE_ACTIVE, "")
		return
	case v < m.active && !ba.GetRollback():
		go m.send(v, fleetv1.BundleStatus_STATE_FAILED, fmt.Sprintf("older than the running bundle %d and not a rollback", m.active))
		return
	case v == m.pending:
		return // already on it
	}
	if m.cancel != nil {
		m.cancel() // a newer announcement wins
	}
	ictx, cancel := context.WithCancel(ctx)
	m.cancel, m.pending = cancel, v
	done := make(chan struct{})
	m.done = done
	go func() {
		defer close(done)
		m.install(ictx, ba)
		m.mu.Lock()
		if m.pending == v {
			m.pending, m.cancel = 0, nil
		}
		m.mu.Unlock()
	}()
}

// Wait returns when the current install, if any, ends (tests).
func (m *Manager) Wait() {
	m.mu.Lock()
	d := m.done
	m.mu.Unlock()
	if d != nil {
		<-d
	}
}

func (m *Manager) send(v uint64, st fleetv1.BundleStatus_State, msg string) {
	if msg != "" {
		slog.Warn("bundle", "version", v, "state", st.String(), "error", msg)
	} else {
		slog.Info("bundle", "version", v, "state", st.String())
	}
	m.report(&fleetv1.BundleStatus{Version: v, State: st, Error: msg})
}

func (m *Manager) install(ctx context.Context, ba *fleetv1.BundleAvailable) {
	v := ba.GetVersion()
	m.send(v, fleetv1.BundleStatus_STATE_DOWNLOADING, "")
	data, err := m.download(ctx, ba)
	if ctx.Err() != nil {
		return // superseded or shutting down
	}
	if err != nil {
		m.send(v, fleetv1.BundleStatus_STATE_FAILED, err.Error())
		return
	}
	name, err := m.store(v, data)
	if err != nil {
		m.send(v, fleetv1.BundleStatus_STATE_FAILED, err.Error())
		return
	}
	m.send(v, fleetv1.BundleStatus_STATE_VERIFIED, "")
	var sum [32]byte
	copy(sum[:], ba.GetSha256())
	if _, err := WriteControl(m.opts.ControlFile, v, sum, name); err != nil {
		m.send(v, fleetv1.BundleStatus_STATE_FAILED, "control file: "+err.Error())
		return
	}
	m.mu.Lock()
	m.active = v
	m.mu.Unlock()
	if err := m.waitActive(ctx, v); err != nil {
		if ctx.Err() == nil {
			m.send(v, fleetv1.BundleStatus_STATE_FAILED, err.Error())
		}
		return
	}
	m.send(v, fleetv1.BundleStatus_STATE_ACTIVE, "")
	m.prune(name)
}

func (m *Manager) partialPath(v uint64) string {
	return filepath.Join(m.opts.Dir, ".partial-"+strconv.FormatUint(v, 10))
}

// download fetches the bundle into its partial file, resuming at the size
// already there and retrying with backoff, then checks it.
func (m *Manager) download(ctx context.Context, ba *fleetv1.BundleAvailable) ([]byte, error) {
	v, size := ba.GetVersion(), ba.GetSizeBytes()
	if size == 0 || size > 1<<30 {
		return nil, fmt.Errorf("announced size %d", size)
	}
	part := m.partialPath(v)
	f, err := os.OpenFile(part, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	backoff := m.opts.BackoffMin
	for {
		st, err := f.Stat()
		if err != nil {
			return nil, err
		}
		off := uint64(st.Size())
		if off > size {
			if err := f.Truncate(0); err != nil {
				return nil, err
			}
			off = 0
		}
		if off == size {
			break
		}
		slog.Info("fetching bundle", "version", v, "offset", off, "size", size)
		err = m.fetchFrom(ctx, f, v, off, size)
		if err == nil {
			continue
		}
		switch status.Code(err) {
		case codes.PermissionDenied, codes.NotFound, codes.OutOfRange, codes.Unimplemented:
			_ = os.Remove(part)
			return nil, fmt.Errorf("fetch: %w", err)
		}
		slog.Warn("bundle download interrupted, resuming", "version", v, "offset", off, "err", err)
		t := time.NewTimer(backoff/2 + time.Duration(rand.Int64N(int64(backoff/2)+1)))
		select {
		case <-ctx.Done():
			t.Stop()
			return nil, ctx.Err()
		case <-t.C:
		}
		backoff = min(2*backoff, m.opts.BackoffMax)
	}
	if err := f.Sync(); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(part)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	if !bytes.Equal(sum[:], ba.GetSha256()) {
		_ = os.Remove(part) // corrupt: start over next time
		return nil, errors.New("sha256 does not match the announced one")
	}
	h, err := bundlefmt.Verify(data, m.opts.PubKey)
	if err != nil {
		_ = os.Remove(part)
		return nil, err
	}
	if h.Version != v {
		_ = os.Remove(part)
		return nil, fmt.Errorf("the signed header says version %d, announced %d", h.Version, v)
	}
	if ba.GetRollback() && h.Flags&bundlefmt.FlagRollback == 0 && v < m.Active() {
		_ = os.Remove(part)
		return nil, errors.New("a rollback bundle must carry the signed ROLLBACK flag")
	}
	return data, nil
}

func (m *Manager) fetchFrom(ctx context.Context, f *os.File, v, off, size uint64) error {
	st, err := m.client.FetchBundle(ctx, &fleetv1.FetchBundleRequest{Version: v, Offset: off})
	if err != nil {
		return err
	}
	for {
		c, err := st.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if c.GetOffset() != off || off+uint64(len(c.GetData())) > size {
			return status.Error(codes.DataLoss, "chunk out of order or past the announced size")
		}
		if _, err := f.WriteAt(c.GetData(), int64(off)); err != nil {
			return err
		}
		off += uint64(len(c.GetData()))
	}
}

// store writes the verified bundle as bundle-<version>.sbn: a temporary
// file, fsync, rename, fsync of the directory. A crash leaves the old
// bundle and the control file untouched.
func (m *Manager) store(v uint64, data []byte) (string, error) {
	name := "bundle-" + strconv.FormatUint(v, 10) + ".sbn"
	tmp, err := os.CreateTemp(m.opts.Dir, ".tmp-"+name+".*")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name()) // no-op after the rename
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(tmp.Name(), filepath.Join(m.opts.Dir, name)); err != nil {
		return "", err
	}
	if err := syncDir(m.opts.Dir); err != nil {
		return "", err
	}
	_ = os.Remove(m.partialPath(v))
	return name, nil
}

// waitActive returns when every worker runs v (metrics file), or after the
// fixed delay when there is no metrics file.
func (m *Manager) waitActive(ctx context.Context, v uint64) error {
	sleep := func(d time.Duration) error {
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			return nil
		}
	}
	if m.opts.MetricsFile == "" {
		return sleep(m.opts.ActiveDelay)
	}
	deadline := time.Now().Add(m.opts.ActiveTimeout)
	for {
		snap, err := shmmetrics.Read(m.opts.MetricsFile)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				// No metrics file (NGINX not started yet, or a module
				// without strata_metrics_file): the workers pick the
				// control file up within a second.
				slog.Info("no worker metrics: reporting ACTIVE after the reload delay", "version", v)
				return sleep(m.opts.ActiveDelay)
			}
			return fmt.Errorf("worker metrics: %w", err)
		}
		all := len(snap.Workers) > 0
		var behind []string
		for _, w := range snap.Workers {
			if w.BundleVersion != v {
				all = false
				behind = append(behind, fmt.Sprintf("worker %d runs %d", w.Index, w.BundleVersion))
			}
		}
		if all {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("workers did not load the bundle: %s", strings.Join(behind, ", "))
		}
		if err := sleep(200 * time.Millisecond); err != nil {
			return err
		}
	}
}

// prune keeps the newest Keep bundles (the running one among them).
func (m *Manager) prune(running string) {
	files, _ := filepath.Glob(filepath.Join(m.opts.Dir, "bundle-*.sbn"))
	type bv struct {
		name string
		v    uint64
	}
	var all []bv
	for _, f := range files {
		base := filepath.Base(f)
		n, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(base, "bundle-"), ".sbn"), 10, 64)
		if err == nil {
			all = append(all, bv{base, n})
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].v > all[j].v })
	kept := 0
	for _, b := range all {
		if b.name == running || kept < m.opts.Keep-1 {
			if b.name != running {
				kept++
			}
			continue
		}
		// unlink only: a worker still mapping it keeps its pages
		_ = os.Remove(filepath.Join(m.opts.Dir, b.name))
	}
}
