package standalone

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/strata/strata/agent/internal/bundles"
	"github.com/strata/strata/agent/pkg/bundlefmt"
)

// BundleWatcher monitors a local bundle file, directory, or URL and updates the control file.
type BundleWatcher struct {
	mu                 sync.Mutex
	bundleFile         string
	bundleDir          string
	bundleURL          string
	controlFile        string
	pubKey             []byte
	pollInterval       time.Duration
	requiredPolicy     string
	requireFullEnforce bool
	httpClient         *http.Client

	activeVersion uint64
	activeHash    [32]byte
	activeFile    string
}

// PolicyRequirement optionally pins the policy used by a standalone route.
type PolicyRequirement struct {
	Name        string
	FullEnforce bool
}

// NewBundleWatcher creates a new watcher.
func NewBundleWatcher(bundleFile, bundleDir, bundleURL, controlFile, pubKeyFile string, interval time.Duration, policy ...PolicyRequirement) (*BundleWatcher, error) {
	if len(policy) > 1 {
		return nil, errors.New("standalone: at most one policy requirement is allowed")
	}
	var requirement PolicyRequirement
	if len(policy) == 1 {
		requirement = policy[0]
	}
	if (requirement.FullEnforce && requirement.Name == "") || (requirement.Name != "" && !bundles.ValidPolicyName(requirement.Name)) {
		return nil, errors.New("standalone: invalid required policy")
	}
	if bundleFile == "" && bundleDir == "" && bundleURL == "" {
		return nil, errors.New("standalone: one of --bundle-file, --bundle-dir, or --bundle-url must be specified")
	}
	if controlFile == "" {
		controlFile = "/run/strata/control"
	}
	if interval <= 0 {
		interval = 2 * time.Second
	}

	pubKey, err := readTrustedKeys(pubKeyFile)
	if err != nil {
		return nil, fmt.Errorf("standalone: %w", err)
	}

	if bundleDir == "" && bundleFile != "" {
		bundleDir = filepath.Dir(bundleFile)
	}

	if err := os.MkdirAll(bundleDir, 0o755); err != nil {
		return nil, fmt.Errorf("standalone: mkdir bundle-dir %s: %w", bundleDir, err)
	}
	if err := os.MkdirAll(filepath.Dir(controlFile), 0o755); err != nil {
		return nil, fmt.Errorf("standalone: mkdir control-file dir %s: %w", filepath.Dir(controlFile), err)
	}

	w := &BundleWatcher{
		bundleFile:         bundleFile,
		bundleDir:          bundleDir,
		bundleURL:          bundleURL,
		controlFile:        controlFile,
		pubKey:             pubKey,
		pollInterval:       interval,
		requiredPolicy:     requirement.Name,
		requireFullEnforce: requirement.FullEnforce,
		httpClient:         &http.Client{Timeout: 15 * time.Second},
	}

	// A corrupt control file must never silently reset rollback protection.
	if c, err := bundles.ReadControl(controlFile); err == nil {
		if requirement.Name != "" && c.Generation%2 != 0 {
			return nil, errors.New("standalone: incomplete control publication")
		}
		w.activeVersion = c.Version
		w.activeHash = c.SHA256
		w.activeFile = c.Name
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("standalone: read control: %w", err)
	}

	return w, nil
}

// SyncOnce checks the bundle source and updates the control file if changed.
// Returns (updated bool, err error).
func (w *BundleWatcher) SyncOnce(ctx context.Context) (bool, error) {
	data, fileName, err := w.fetchBundle(ctx)
	if err != nil {
		return false, err
	}
	if len(data) == 0 && fileName == "" {
		return false, nil // no bundle found yet
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}

	var header bundlefmt.Header
	if w.requiredPolicy != "" {
		header, err = bundlefmt.VerifyPolicy(data, w.pubKey, w.requiredPolicy, w.requireFullEnforce)
	} else {
		header, err = bundlefmt.Verify(data, w.pubKey)
	}
	if err != nil {
		return false, fmt.Errorf("bundle verification failed: %w", err)
	}
	sha := sha256.Sum256(data)
	// Immutable content-addressed files prevent source replacement from changing
	// bytes already named by the memory-mapped control file.
	fileName = fmt.Sprintf(".strata-%x.sbn", sha)
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.activeVersion == header.Version && w.activeHash == sha && w.activeFile == fileName {
		return false, nil
	}
	if header.Version < w.activeVersion && header.Flags&bundlefmt.FlagRollback == 0 {
		return false, errors.New("standalone: older bundle requires signed rollback flag")
	}
	if header.Version == w.activeVersion && w.activeHash != sha {
		return false, errors.New("standalone: version reused with different content")
	}
	if err := installBundle(w.bundleDir, fileName, data); err != nil {
		return false, err
	}

	// Update control file in place
	gen, err := bundles.WriteControl(w.controlFile, header.Version, sha, fileName)
	if err != nil {
		return false, fmt.Errorf("write control file: %w", err)
	}

	w.activeVersion = header.Version
	w.activeHash = sha
	w.activeFile = fileName

	slog.Info("standalone: updated control file to bundle",
		"version", header.Version,
		"file", fileName,
		"generation", gen,
		"sha256", fmt.Sprintf("%x", sha[:8]),
	)

	return true, nil
}

// Run loops periodically until context canceled.
func (w *BundleWatcher) Run(ctx context.Context) error {
	if w.requiredPolicy != "" {
		if err := w.validateActive(ctx); err != nil {
			return fmt.Errorf("standalone: active policy validation: %w", err)
		}
	}
	if _, err := w.SyncOnce(ctx); err != nil {
		if w.requiredPolicy != "" && !w.hasActive() {
			return fmt.Errorf("standalone: initial required policy sync: %w", err)
		}
		slog.Warn("standalone: initial bundle sync warning", "err", err)
	}
	if w.requiredPolicy != "" && !w.hasActive() {
		return errors.New("standalone: no verified active bundle for required policy")
	}

	ticker := time.NewTicker(w.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if _, err := w.SyncOnce(ctx); err != nil {
				slog.Warn("standalone: bundle sync error", "err", err)
			}
		}
	}
}

// Active returns the currently loaded bundle version.
func (w *BundleWatcher) Active() uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.activeVersion
}

func (w *BundleWatcher) fetchBundle(ctx context.Context) ([]byte, string, error) {
	// 1. Direct file
	if w.bundleFile != "" {
		data, err := readBundleFile(w.bundleFile)
		if err != nil {
			return nil, "", err
		}
		return data, filepath.Base(w.bundleFile), nil
	}

	// 2. URL
	if w.bundleURL != "" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, w.bundleURL, nil)
		if err != nil {
			return nil, "", err
		}
		resp, err := w.httpClient.Do(req)
		if err != nil {
			return nil, "", err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, "", fmt.Errorf("fetch bundle URL returned HTTP %d", resp.StatusCode)
		}
		data, err := readBundle(resp.Body)
		if err != nil {
			return nil, "", err
		}
		fileName := filepath.Base(resp.Request.URL.Path)
		if fileName == "" || fileName == "/" || fileName == "." {
			fileName = "bundle.sbn"
		}
		return data, fileName, nil
	}

	// 3. Directory: look for newest .sbn file
	dir, err := os.Open(w.bundleDir)
	if err != nil {
		return nil, "", err
	}
	defer dir.Close()
	entries, err := dir.ReadDir(4097)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, "", err
	}
	if len(entries) > 4096 {
		return nil, "", errors.New("standalone: bundle directory exceeds 4096 entries")
	}
	var newest os.FileInfo
	for _, e := range entries {
		if !e.Type().IsRegular() || !strings.HasSuffix(e.Name(), ".sbn") || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			return nil, "", err
		}
		if newest == nil || info.ModTime().After(newest.ModTime()) {
			newest = info
		}
	}
	if newest == nil {
		return nil, "", nil
	}
	data, err := readBundleFile(filepath.Join(w.bundleDir, newest.Name()))
	return data, newest.Name(), err
}

// Match the existing fleet download limit; also bound local and streaming input.
const maxBundleBytes = 1 << 30

func readBundle(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxBundleBytes+1))
	if err == nil && len(b) > maxBundleBytes {
		err = errors.New("standalone: bundle exceeds 1 GiB")
	}
	return b, err
}

func readBundleFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() > maxBundleBytes {
		return nil, errors.New("standalone: invalid bundle file type or size")
	}
	return readBundle(f)
}

func installBundle(dir, name string, data []byte) error {
	f, err := os.CreateTemp(dir, ".install-*")
	if err != nil {
		return fmt.Errorf("standalone: create bundle: %w", err)
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err == nil {
		err = f.Chmod(0644)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("standalone: persist bundle: %w", err)
	}
	if err := os.Rename(f.Name(), filepath.Join(dir, name)); err != nil {
		return fmt.Errorf("standalone: publish bundle: %w", err)
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
