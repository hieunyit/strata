package main

import (
	"crypto/ed25519"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyBundleCommand(t *testing.T) {
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
	file, key := filepath.Join(d, "bundle.sbn"), filepath.Join(d, "key")
	if err := os.WriteFile(file, b, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, pub, 0600); err != nil {
		t.Fatal(err)
	}
	out, err := execute(t, "verify-bundle", "--bundle-file="+file, "--bundle-pubkey="+key)
	if err != nil || !strings.Contains(out, "version 7") {
		t.Fatalf("out=%q err=%v", out, err)
	}
	b[40] ^= 1
	if err := os.WriteFile(file, b, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := execute(t, "verify-bundle", "--bundle-file="+file, "--bundle-pubkey="+key); err == nil {
		t.Fatal("accepted tampered signature")
	}
	for _, args := range [][]string{{"verify-bundle"}, {"verify-bundle", "--bundle-file=" + file}} {
		if _, err := execute(t, args...); err == nil {
			t.Fatal("accepted missing trusted key or file")
		}
	}
}
