package standalone

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/strata/strata/agent/pkg/bundlefmt"
)

func (w *BundleWatcher) hasActive() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.activeFile != ""
}

// Validate restored content before treating it as the pinned last-known-good
// bundle. Only this watcher's content-addressed filenames may be read.
func (w *BundleWatcher) validateActive(ctx context.Context) error {
	w.mu.Lock()
	file, version, digest := w.activeFile, w.activeVersion, w.activeHash
	w.mu.Unlock()
	if file == "" {
		return nil
	}
	if file != fmt.Sprintf(".strata-%x.sbn", digest) {
		return errors.New("invalid active bundle filename")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	data, err := readBundleFile(filepath.Join(w.bundleDir, file))
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	h, err := bundlefmt.VerifyPolicy(data, w.pubKey, w.requiredPolicy, w.requireFullEnforce)
	if err != nil {
		return err
	}
	if h.Version != version || sha256.Sum256(data) != digest {
		return errors.New("active control version/digest differs from verified bundle")
	}
	return nil
}
