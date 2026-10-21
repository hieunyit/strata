package policy_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"reflect"
	"testing"

	"github.com/strata/strata/agent/pkg/bundlefmt"
	"github.com/strata/strata/control-plane/policy"
	"github.com/strata/strata/control-plane/store"
)

// This native fixture contains the real rule/IR/schema sections. Breaking the
// current compiler and rule file must not change a historical rollback.
func TestReleaseRollbackKeepsNativeSectionsAcrossKeyRotation(t *testing.T) {
	f := newStagingWriter(t, false)
	old, err := f.objects.Get(t.Context(), f.source.ObjectKey)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := store.ReleaseSnapshot{Bundle: f.source, PublicKey: f.writer.PubKey}
	seed := bytes.Repeat([]byte{9}, 32)
	compiler := f.writer.Compiler
	if err := os.WriteFile(compiler.KeyFile, seed, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.rules, []byte("broken current rules"), 0600); err != nil {
		t.Fatal(err)
	}
	compiler.Binary = "/unavailable/compiler"
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	d := &policy.Deployer{Builder: compiler, Objects: f.objects, PubKey: pub}
	b, err := d.MaterializeRelease(t.Context(), snapshot, 99)
	if err != nil {
		t.Fatal(err)
	}
	got, err := f.objects.Get(t.Context(), b.ObjectKey)
	if err != nil {
		t.Fatal(err)
	}
	h, err := bundlefmt.Verify(got, pub)
	if err != nil || h.Version != 99 || h.Flags&bundlefmt.FlagRollback != 0 {
		t.Fatalf("header: %+v %v", h, err)
	}
	if !bytes.Equal(old[64:len(old)-64], got[64:len(got)-64]) {
		t.Fatal("rollback changed policy/rule/schema sections")
	}
	requirements, err := bundlefmt.Requirements(old, snapshot.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(b.RequiredCapabilities, requirements) {
		t.Fatal("native capabilities changed")
	}
	sum := sha256.Sum256(got)
	if hex.EncodeToString(sum[:]) != hex.EncodeToString(b.SHA256) {
		t.Fatal("recorded hash mismatch")
	}
	f.objects[f.source.ObjectKey][70] ^= 1
	if _, err := d.MaterializeRelease(t.Context(), snapshot, 100); err == nil {
		t.Fatal("tampered historical artifact accepted")
	}
}
