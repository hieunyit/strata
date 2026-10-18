package standalone

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/strata/strata/agent/internal/bundles"
)

func TestWatcherRequiresTrustedKey(t *testing.T) {
	d := t.TempDir()
	if _, err := NewBundleWatcher("", d, "", filepath.Join(d, "control"), "", time.Second); err == nil {
		t.Fatal("accepted watcher without a trusted signing key")
	}
}

func TestWatcherSignedContentAndRollback(t *testing.T) {
	d := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	key, source, ctl := filepath.Join(d, "key"), filepath.Join(d, "source.sbn"), filepath.Join(d, "control")
	if err := os.WriteFile(key, pub, 0600); err != nil {
		t.Fatal(err)
	}
	w, err := NewBundleWatcher(source, filepath.Join(d, "installed"), "", ctl, key, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	write := func(b []byte) {
		t.Helper()
		if err := os.WriteFile(source, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	check := func(b []byte) {
		t.Helper()
		c, err := bundles.ReadControl(ctl)
		if err != nil {
			t.Fatal(err)
		}
		stored, err := os.ReadFile(filepath.Join(w.bundleDir, c.Name))
		if err != nil {
			t.Fatal(err)
		}
		if c.SHA256 != sha256.Sum256(stored) || sha256.Sum256(b) != c.SHA256 {
			t.Fatal("control digest differs from installed bytes")
		}
	}
	first := makeTestBundleWithKey(2, 1, priv)
	write(first)
	if _, err := w.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	check(first)
	second := makeTestBundleWithKey(3, 2, priv)
	write(second)
	if _, err := w.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	check(second)
	write(first)
	if _, err := w.SyncOnce(context.Background()); err == nil {
		t.Fatal("accepted unsigned rollback authorization")
	}
	check(second)
	// Restart must retain rollback protection from the actual control file.
	w, err = NewBundleWatcher(source, w.bundleDir, "", ctl, key, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.SyncOnce(context.Background()); err == nil {
		t.Fatal("restart forgot active version")
	}
	// A rollback is permitted only when the authorization is signed.
	rollback := makeTestBundleWithKey(1, 3, priv)
	binary.LittleEndian.PutUint16(rollback[10:], 1)
	copy(rollback[len(rollback)-64:], ed25519.Sign(priv, rollback[:len(rollback)-64]))
	write(rollback)
	if _, err := w.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	check(rollback)
	second[40] ^= 1
	write(second)
	if _, err := w.SyncOnce(context.Background()); err == nil {
		t.Fatal("accepted tampered signature")
	}
}

func TestWatcherRejectsCorruptControl(t *testing.T) {
	d := t.TempDir()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	key, ctl := filepath.Join(d, "key"), filepath.Join(d, "control")
	if err := os.WriteFile(key, pub, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ctl, []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewBundleWatcher("", d, "", ctl, key, time.Second); err == nil {
		t.Fatal("ignored corrupt existing control")
	}
}

func TestWatcherHTTPBoundaries(t *testing.T) {
	d := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(d, "key")
	if err := os.WriteFile(key, pub, 0600); err != nil {
		t.Fatal(err)
	}
	status := 200
	data := makeTestBundleWithKey(4, 1, priv)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status); _, _ = w.Write(data) }))
	defer srv.Close()
	w, err := NewBundleWatcher("", d, srv.URL+"/bundle.sbn", filepath.Join(d, "control"), key, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	status = 503
	if _, err := w.SyncOnce(context.Background()); err == nil {
		t.Fatal("accepted failed HTTP response")
	}
	status = 200
	data = nil
	if _, err := w.SyncOnce(context.Background()); err == nil {
		t.Fatal("accepted empty bundle")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := w.SyncOnce(ctx); err == nil {
		t.Fatal("ignored canceled fetch")
	}
	f, err := os.Create(filepath.Join(d, "oversize.sbn"))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxBundleBytes + 1); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := readBundleFile(f.Name()); err == nil {
		t.Fatal("accepted oversized file")
	}
}
