package setup

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func mode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode().Perm()
}

// init makes the PKI, the signing key and the config once; a second run
// keeps them byte for byte.
func TestCreateOnceThenKeep(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	var r Result
	if err := PKI(dir, []string{"cp.example.test", "192.0.2.10"}, now, &r); err != nil {
		t.Fatal(err)
	}
	if err := BundleKeys(dir, false, &r); err != nil {
		t.Fatal(err)
	}
	if err := Config(dir, "clickhouse:9000", "", &r); err != nil {
		t.Fatal(err)
	}
	if len(r.Created) != 5 || len(r.Kept) != 0 {
		t.Fatalf("first run: %+v", r)
	}
	for _, p := range []string{CAKey, ServerKey, NodeCAKey, BundleKey, ConfigFile} {
		if m := mode(t, filepath.Join(dir, p)); m != 0o600 {
			t.Errorf("%s: mode %o", p, m)
		}
	}
	// the server certificate is signed by the CA, for the names
	raw, _ := os.ReadFile(filepath.Join(dir, ServerCert))
	blk, _ := pem.Decode(raw)
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	caRaw, _ := os.ReadFile(filepath.Join(dir, CACert))
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caRaw)
	if _, err := cert.Verify(x509.VerifyOptions{DNSName: "cp.example.test", Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatal(err)
	}
	if len(cert.IPAddresses) != 1 || cert.IPAddresses[0].String() != "192.0.2.10" {
		t.Fatalf("ip names: %v", cert.IPAddresses)
	}
	if seed, _ := os.ReadFile(filepath.Join(dir, BundleKey)); len(seed) != 32 {
		t.Fatalf("seed %d bytes", len(seed))
	}
	before := map[string][]byte{}
	for _, p := range []string{CAKey, ServerCert, NodeCAKey, BundleKey, ConfigFile} {
		before[p], _ = os.ReadFile(filepath.Join(dir, p))
	}
	var r2 Result
	if err := PKI(dir, []string{"other.example.test"}, now, &r2); err != nil {
		t.Fatal(err)
	}
	if err := BundleKeys(dir, true, &r2); err != nil {
		t.Fatal(err)
	}
	if err := Config(dir, "x:1", "", &r2); err != nil {
		t.Fatal(err)
	}
	if len(r2.Created) != 0 {
		t.Fatalf("second run created %v", r2.Created)
	}
	for p, b := range before {
		if after, _ := os.ReadFile(filepath.Join(dir, p)); string(after) != string(b) {
			t.Errorf("%s changed on the second run", p)
		}
	}
}

// A lost signing key on a system with bundles is never replaced, and half
// pairs are errors, not repaired.
func TestRefusesToRepairOrReplace(t *testing.T) {
	dir := t.TempDir()
	if err := BundleKeys(dir, true, &Result{}); !errors.Is(err, ErrSigningKeyLost) {
		t.Fatalf("lost key: %v", err)
	}
	if err := BundleKeys(dir, false, &Result{}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, BundlePub)); err != nil {
		t.Fatal(err)
	}
	if err := BundleKeys(dir, false, &Result{}); err == nil {
		t.Fatal("half key pair repaired")
	}
	if err := PKI(dir, []string{"cp"}, time.Now(), &Result{}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, ServerKey)); err != nil {
		t.Fatal(err)
	}
	if err := PKI(dir, []string{"cp"}, time.Now(), &Result{}); err == nil {
		t.Fatal("half server pair repaired")
	}
	if err := PKI(t.TempDir(), nil, time.Now(), &Result{}); err == nil {
		t.Fatal("certificate without a name")
	}
}

// Two inits at once: one waits out (the lock), so no two keys are made.
func TestLockExcludesConcurrentInits(t *testing.T) {
	dir := t.TempDir()
	release, err := Lock(dir)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if _, err := Lock(dir); err == nil {
			t.Error("second lock taken while the first is held")
		}
	}()
	wg.Wait()
	release()
	again, err := Lock(dir)
	if err != nil {
		t.Fatalf("after release: %v", err)
	}
	again()
}

func TestSecretFile(t *testing.T) {
	dir := t.TempDir()
	var r Result
	if err := Secret(dir, DSNFile, "postgres://x", &r); err != nil || len(r.Created) != 1 {
		t.Fatalf("%v %+v", err, r)
	}
	if m := mode(t, filepath.Join(dir, DSNFile)); m != 0o600 {
		t.Fatalf("mode %o", m)
	}
	if err := Secret(dir, DSNFile, "postgres://other", &r); err != nil || len(r.Kept) != 1 {
		t.Fatalf("%v %+v", err, r)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, DSNFile)); string(b) != "postgres://x\n" {
		t.Fatalf("overwritten: %q", b)
	}
	if err := Secret(dir, CHPassword, "", &r); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, CHPassword)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("empty secret written")
	}
}
