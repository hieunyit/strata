package standalone

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"github.com/strata/strata/agent/internal/bundles"
	"github.com/strata/strata/agent/pkg/bundlefmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func policyWatchBundle(t *testing.T, key ed25519.PrivateKey, version uint64, name string, mode byte, canary uint16) []byte {
	t.Helper()
	b := make([]byte, 4096)
	copy(b, "STRBNDL\x00")
	binary.LittleEndian.PutUint16(b[8:], 1)
	binary.LittleEndian.PutUint32(b[12:], 1)
	binary.LittleEndian.PutUint64(b[16:], version)
	binary.LittleEndian.PutUint64(b[32:], 4096)
	copy(b[64:], name)
	b[120] = mode
	binary.LittleEndian.PutUint16(b[123:], canary)
	return append(b, ed25519.Sign(key, b)...)
}

func TestWatcherRejectsPolicyLoss(t *testing.T) {
	dir := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	source, key, ctl := filepath.Join(dir, "source.sbn"), filepath.Join(dir, "key"), filepath.Join(dir, "control")
	if err := os.WriteFile(key, pub, 0600); err != nil {
		t.Fatal(err)
	}
	w, err := NewBundleWatcher(source, filepath.Join(dir, "installed"), "", ctl, key, time.Second, PolicyRequirement{Name: "example-api", FullEnforce: true})
	if err != nil {
		t.Fatal(err)
	}
	first := policyWatchBundle(t, priv, 1, "example-api", 1, 0)
	if err := os.WriteFile(source, first, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := w.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(ctl)
	if err != nil {
		t.Fatal(err)
	}
	for i, tt := range []struct {
		name, policy string
		mode         byte
		canary       uint16
	}{
		{"missing", "other-api", 1, 0}, {"shadow", "example-api", 0, 0}, {"canary", "example-api", 1, 100}, {"signed-rollback", "other-api", 1, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			next := policyWatchBundle(t, priv, uint64(i+2), tt.policy, tt.mode, tt.canary)
			if tt.name == "signed-rollback" {
				binary.LittleEndian.PutUint64(next[16:], 0)
				binary.LittleEndian.PutUint16(next[10:], bundlefmt.FlagRollback)
				copy(next[len(next)-64:], ed25519.Sign(priv, next[:len(next)-64]))
			}
			if err := os.WriteFile(source, next, 0600); err != nil {
				t.Fatal(err)
			}
			if changed, err := w.SyncOnce(context.Background()); err == nil || changed {
				t.Fatalf("accepted policy loss: changed=%v err=%v", changed, err)
			}
			after, err := os.ReadFile(ctl)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatal("rejected update changed control")
			}
		})
	}
	rollback := policyWatchBundle(t, priv, 0, "example-api", 1, 0)
	binary.LittleEndian.PutUint16(rollback[10:], bundlefmt.FlagRollback)
	copy(rollback[len(rollback)-64:], ed25519.Sign(priv, rollback[:len(rollback)-64]))
	if err := os.WriteFile(source, rollback, 0600); err != nil {
		t.Fatal(err)
	}
	if changed, err := w.SyncOnce(context.Background()); err != nil || !changed {
		t.Fatalf("valid signed rollback rejected: %v %v", changed, err)
	}
}

func TestPinnedWatcherStartupAndRecovery(t *testing.T) {
	d := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	key, source, ctl := filepath.Join(d, "key"), filepath.Join(d, "source.sbn"), filepath.Join(d, "control")
	if err := os.WriteFile(key, pub, 0600); err != nil {
		t.Fatal(err)
	}
	req := PolicyRequirement{Name: "example-api", FullEnforce: true}
	newWatcher := func() *BundleWatcher {
		t.Helper()
		w, err := NewBundleWatcher(source, filepath.Join(d, "installed"), "", ctl, key, time.Second, req)
		if err != nil {
			t.Fatal(err)
		}
		return w
	}
	bad := policyWatchBundle(t, priv, 2, "other-api", 1, 0)
	if err := os.WriteFile(source, bad, 0600); err != nil {
		t.Fatal(err)
	}
	assertPinnedRunRejected(t, newWatcher())
	if _, err := os.Stat(ctl); !os.IsNotExist(err) {
		t.Fatalf("published failed initial source: %v", err)
	}
	good := policyWatchBundle(t, priv, 1, "example-api", 1, 0)
	if err := os.WriteFile(source, good, 0600); err != nil {
		t.Fatal(err)
	}
	w := newWatcher()
	if _, err := w.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(ctl)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, bad, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err := newWatcher().Run(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("did not retain good bundle: %v", err)
	}
	after, err := os.ReadFile(ctl)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("restart changed LKG: %v", err)
	}
	c, err := bundles.ReadControl(ctl)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(w.bundleDir, c.Name), bad, 0600); err != nil {
		t.Fatal(err)
	}
	assertPinnedRunRejected(t, newWatcher())
	if err := os.WriteFile(filepath.Join(w.bundleDir, c.Name), good, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := bundles.WriteControl(ctl, 99, c.SHA256, c.Name); err != nil {
		t.Fatal(err)
	}
	assertPinnedRunRejected(t, newWatcher())
	if _, err := bundles.WriteControl(ctl, 1, c.SHA256, c.Name); err != nil {
		t.Fatal(err)
	}
	w = newWatcher()
	w.activeFile = "../outside.sbn"
	assertPinnedRunRejected(t, w)
	if _, err := NewBundleWatcher(source, d, "", ctl, key, time.Second, PolicyRequirement{FullEnforce: true}); err == nil {
		t.Fatal("accepted enforce without policy")
	}
	if _, err := NewBundleWatcher(source, d, "", ctl, key, time.Second, req, req); err == nil {
		t.Fatal("accepted ambiguous requirements")
	}
}

func TestPinnedWatcherURLAndDirectory(t *testing.T) {
	for _, mode := range []string{"url", "directory"} {
		t.Run(mode, func(t *testing.T) {
			d := t.TempDir()
			pub, priv, err := ed25519.GenerateKey(nil)
			if err != nil {
				t.Fatal(err)
			}
			key, source, ctl := filepath.Join(d, "key"), filepath.Join(d, "source.sbn"), filepath.Join(d, "control")
			if err := os.WriteFile(key, pub, 0600); err != nil {
				t.Fatal(err)
			}
			var body atomic.Value
			publish := func(b []byte) {
				t.Helper()
				body.Store(b)
				if err := os.WriteFile(source, b, 0600); err != nil {
					t.Fatal(err)
				}
			}
			first := policyWatchBundle(t, priv, 1, "example-api", 1, 0)
			publish(first)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body.Load().([]byte)) }))
			defer srv.Close()
			url := ""
			if mode == "url" {
				url = srv.URL
			}
			w, err := NewBundleWatcher("", d, url, ctl, key, time.Second, PolicyRequirement{Name: "example-api", FullEnforce: true})
			if err != nil {
				t.Fatal(err)
			}
			if changed, err := w.SyncOnce(context.Background()); err != nil || !changed {
				t.Fatalf("initial: %v %v", changed, err)
			}
			before, err := os.ReadFile(ctl)
			if err != nil {
				t.Fatal(err)
			}
			publish(policyWatchBundle(t, priv, 2, "other-api", 1, 0))
			if changed, err := w.SyncOnce(context.Background()); err == nil || changed {
				t.Fatalf("accepted missing policy: %v %v", changed, err)
			}
			after, err := os.ReadFile(ctl)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatalf("changed LKG: %v", err)
			}
			next := policyWatchBundle(t, priv, 3, "example-api", 1, 0)
			publish(next)
			if changed, err := w.SyncOnce(context.Background()); err != nil || !changed {
				t.Fatalf("recovery: %v %v", changed, err)
			}
			c, err := bundles.ReadControl(ctl)
			if err != nil || c.Version != 3 || c.SHA256 != sha256.Sum256(next) {
				t.Fatalf("bad recovery: %+v %v", c, err)
			}
		})
	}
}

func assertPinnedRunRejected(t *testing.T, w *BundleWatcher) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := w.Run(ctx); err == nil || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		t.Fatalf("did not reject invalid pinned state: %v", err)
	}
}
