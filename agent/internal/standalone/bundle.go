package standalone

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/strata/strata/agent/internal/bundles"
	"github.com/strata/strata/agent/pkg/bundlefmt"
)

// BundleWatcher monitors a local bundle file, directory, or URL and updates the control file.
type BundleWatcher struct {
	mu           sync.Mutex
	bundleFile   string
	bundleDir    string
	bundleURL    string
	controlFile  string
	pubKey       []byte
	pollInterval time.Duration
	httpClient   *http.Client

	activeVersion uint64
	activeHash    [32]byte
	activeFile    string
}

// NewBundleWatcher creates a new watcher.
func NewBundleWatcher(bundleFile, bundleDir, bundleURL, controlFile, pubKeyFile string, interval time.Duration) (*BundleWatcher, error) {
	if bundleFile == "" && bundleDir == "" && bundleURL == "" {
		return nil, errors.New("standalone: one of --bundle-file, --bundle-dir, or --bundle-url must be specified")
	}
	if controlFile == "" {
		controlFile = "/run/strata/control"
	}
	if interval <= 0 {
		interval = 2 * time.Second
	}

	var pubKey []byte
	if pubKeyFile != "" {
		b, err := os.ReadFile(pubKeyFile)
		if err != nil {
			return nil, fmt.Errorf("standalone: read bundle pubkey: %w", err)
		}
		if !bundlefmt.ValidKeys(b) {
			return nil, errors.New("standalone: bundle pubkey must be 32 or 64 bytes")
		}
		pubKey = b
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
		bundleFile:   bundleFile,
		bundleDir:    bundleDir,
		bundleURL:    bundleURL,
		controlFile:  controlFile,
		pubKey:       pubKey,
		pollInterval: interval,
		httpClient:   &http.Client{Timeout: 15 * time.Second},
	}

	// Read existing control file if present
	if c, err := bundles.ReadControl(controlFile); err == nil {
		w.activeVersion = c.Version
		w.activeHash = c.SHA256
		w.activeFile = c.Name
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
	if len(data) == 0 {
		return false, nil // no bundle found yet
	}

	var header bundlefmt.Header
	if len(w.pubKey) > 0 {
		h, err := bundlefmt.Verify(data, w.pubKey)
		if err != nil {
			return false, fmt.Errorf("bundle verification failed: %w", err)
		}
		header = h
	} else {
		// Header without signature verification (test/dev mode)
		if len(data) < 64 || string(data[:8]) != "STRBNDL\x00" {
			return false, errors.New("invalid bundle header or magic")
		}
		header, err = bundlefmt.Verify(data, data[len(data)-64:])
		if err != nil {
			// fallback check
			header = bundlefmt.Header{Version: 1}
		}
	}

	sha := sha256.Sum256(data)

	w.mu.Lock()
	defer w.mu.Unlock()

	if w.activeVersion == header.Version && bytes.Equal(w.activeHash[:], sha[:]) && w.activeFile == fileName {
		return false, nil // Already up-to-date
	}

	// Ensure the bundle file exists in w.bundleDir with name fileName
	targetPath := filepath.Join(w.bundleDir, fileName)
	if _, err := os.Stat(targetPath); err != nil {
		tmpPath := filepath.Join(w.bundleDir, fmt.Sprintf(".tmp-%s-%d", fileName, time.Now().UnixNano()))
		if err := os.WriteFile(tmpPath, data, 0o644); err != nil {
			return false, fmt.Errorf("write bundle file: %w", err)
		}
		if err := os.Rename(tmpPath, targetPath); err != nil {
			_ = os.Remove(tmpPath)
			return false, fmt.Errorf("rename bundle file: %w", err)
		}
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
	// Initial sync
	if _, err := w.SyncOnce(ctx); err != nil {
		slog.Warn("standalone: initial bundle sync warning", "err", err)
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
		data, err := os.ReadFile(w.bundleFile)
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
		data, err := io.ReadAll(resp.Body)
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
	entries, err := os.ReadDir(w.bundleDir)
	if err != nil {
		return nil, "", err
	}

	var candidates []os.FileInfo
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sbn") || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		if info, err := e.Info(); err == nil {
			candidates = append(candidates, info)
		}
	}
	if len(candidates) == 0 {
		return nil, "", nil // no bundle yet
	}

	// Sort by modification time (newest first)
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].ModTime().After(candidates[j].ModTime())
	})

	newest := candidates[0].Name()
	data, err := os.ReadFile(filepath.Join(w.bundleDir, newest))
	if err != nil {
		return nil, "", err
	}
	return data, newest, nil
}
