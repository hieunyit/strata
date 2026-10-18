package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/strata/strata/agent/internal/bundles"
)

func TestStandaloneCLIValidation(t *testing.T) {
	for _, tt := range []struct {
		args []string
		want string
	}{
		{[]string{"--standalone"}, "bundle-file"},
		{[]string{"--standalone", "--bundle-file=a"}, "bundle-pubkey"},
		{[]string{"--standalone", "--bundle-url=https://api.example.test/bundle.sbn", "--bundle-pubkey=a"}, "requires --bundle-dir"},
		{[]string{"--standalone", "--bundle-file=a", "--bundle-url=b"}, "bundle-file"},
		{[]string{"--standalone", "--server=127.0.0.1:1"}, "cannot be used"},
		{[]string{"--standalone", "--fallback=false"}, "cannot be used"},
		{[]string{"--events-jsonl=a"}, "requires --standalone"},
	} {
		_, err := execute(t, append([]string{"run"}, tt.args...)...)
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Fatalf("%v: got %v, want %s", tt.args, err, tt.want)
		}
	}
}

func TestStandaloneCLIWithoutControlPlane(t *testing.T) {
	d := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 128)
	copy(b, "STRBNDL\x00")
	binary.LittleEndian.PutUint16(b[8:], 1)
	binary.LittleEndian.PutUint64(b[16:], 7)
	copy(b[64:], ed25519.Sign(priv, b[:64]))
	key, source, ctl := filepath.Join(d, "key"), filepath.Join(d, "bundle.sbn"), filepath.Join(d, "control")
	if err := os.WriteFile(key, pub, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, b, 0600); err != nil {
		t.Fatal(err)
	}
	cmd := newRootCmd()
	cmd.SetArgs([]string{"run", "--standalone", "--bundle-file=" + source, "--bundle-pubkey=" + key, "--control-file=" + ctl, "--event-socket=unix:" + filepath.Join(d, "events.sock"), "--events-jsonl=" + filepath.Join(d, "events.jsonl"), "--metrics-addr=", "--metrics-file="})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- cmd.ExecuteContext(ctx) }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		c, err := bundles.ReadControl(ctl)
		if err == nil && c.Version == 7 && c.SHA256 == sha256.Sum256(b) {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("CLI exited before installing signed bundle: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("CLI failed to install bundle: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("CLI did not stop")
	}
}
