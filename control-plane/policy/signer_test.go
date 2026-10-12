package policy

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

// fakeVault is Vault's transit engine for one ed25519 key: the private
// key lives here only.
type fakeVault struct {
	mu         sync.Mutex
	priv       ed25519.PrivateKey
	keyType    string
	exportable bool
	badSig     bool
	version    int
	bodies     []string // every request body the signer sent
}

func newFakeVault(t *testing.T) (*fakeVault, *httptest.Server) {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(nil)
	f := &fakeVault{priv: priv, keyType: "ed25519", version: 2}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.Header.Get("X-Vault-Token") != "signer-token" {
			http.Error(w, `{"errors":["permission denied"]}`, http.StatusForbidden)
			return
		}
		body, _ := io.ReadAll(r.Body)
		f.bodies = append(f.bodies, string(body))
		pub := base64.StdEncoding.EncodeToString(f.priv.Public().(ed25519.PublicKey))
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/transit/keys/strata-bundles":
			fmt.Fprintf(w, `{"data":{"type":%q,"exportable":%t,"allow_plaintext_backup":false,"latest_version":%d,"keys":{"%d":{"public_key":%q}}}}`,
				f.keyType, f.exportable, f.version, f.version, pub)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/transit/sign/strata-bundles":
			var req struct {
				Input      string `json:"input"`
				KeyVersion int    `json:"key_version"`
			}
			_ = json.Unmarshal(body, &req)
			msg, _ := base64.StdEncoding.DecodeString(req.Input)
			if f.badSig {
				msg = append(msg, 'x')
			}
			sig := ed25519.Sign(f.priv, msg)
			fmt.Fprintf(w, `{"data":{"signature":"vault:v%d:%s"}}`, req.KeyVersion, base64.StdEncoding.EncodeToString(sig))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return f, srv
}

func TestVaultSigner(t *testing.T) {
	f, srv := newFakeVault(t)
	v := &VaultSigner{Addr: srv.URL, Key: "strata-bundles", Token: "signer-token"}
	if err := v.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	msg := []byte("unsigned bundle bytes")
	sig, err := v.Sign(context.Background(), msg)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := v.PublicKey(context.Background())
	if !ed25519.Verify(pub, msg, sig) || !pub.Equal(f.priv.Public()) {
		t.Fatal("signature does not verify with the Vault key")
	}
	// The signer pins the key version it read.
	if !strings.Contains(f.bodies[len(f.bodies)-1], `"key_version":2`) {
		t.Fatalf("sign request %s", f.bodies[len(f.bodies)-1])
	}
	// A signature that does not verify is refused, not returned.
	f.badSig = true
	if _, err := v.Sign(context.Background(), msg); err == nil {
		t.Fatal("bad signature accepted")
	}
	f.badSig = false
	if _, err := v.Sign(context.Background(), make([]byte, MaxVaultMessage+1)); err == nil {
		t.Fatal("oversized bundle sent")
	}

	// Keys that could leave Vault, or of another type, are refused.
	for name, set := range map[string]func(){
		"exportable": func() { f.exportable = true },
		"rsa":        func() { f.exportable = false; f.keyType = "rsa-2048" },
	} {
		set()
		if err := (&VaultSigner{Addr: srv.URL, Key: "strata-bundles", Token: "signer-token"}).Init(context.Background()); err == nil {
			t.Errorf("%s key accepted", name)
		}
	}
	if err := (&VaultSigner{Addr: srv.URL, Key: "strata-bundles", Token: "wrong"}).Init(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "403") {
		t.Errorf("wrong token: %v", err)
	}
}

// The signing path holds no key: VaultSigner has no private key field, and
// the compiler gets --unsigned, never --key, so no seed is read.
func TestVaultSigningPathReadsNoKey(t *testing.T) {
	ty := reflect.TypeOf(VaultSigner{})
	for i := 0; i < ty.NumField(); i++ {
		if ty.Field(i).Type == reflect.TypeOf(ed25519.PrivateKey{}) {
			t.Fatalf("VaultSigner.%s holds a private key", ty.Field(i).Name)
		}
	}
	f, srv := newFakeVault(t)
	v := &VaultSigner{Addr: srv.URL, Key: "strata-bundles", Token: "signer-token"}
	if err := v.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	argsFile := filepath.Join(dir, "args")
	script := filepath.Join(dir, "fake-compile")
	_ = os.WriteFile(script, []byte(`#!/bin/sh
echo "$@" > `+argsFile+`
while [ $# -gt 0 ]; do
  case "$1" in
    --out) printf unsigned > "$2"; shift 2 ;;
    --cost-report) printf '{"total":10,"rules":[]}' > "$2"; shift 2 ;;
    *) shift ;;
  esac
done
`), 0o755)
	c := &Compiler{Binary: script, Signer: v, CostBudget: 100}
	out, err := c.Build(context.Background(), 3, []Named{{Name: "example-api", Spec: Spec{Mode: "enforce"}}})
	if err != nil {
		t.Fatal(err)
	}
	args, _ := os.ReadFile(argsFile)
	if !strings.Contains(string(args), "--unsigned") || strings.Contains(string(args), "--key") {
		t.Fatalf("args %q", args)
	}
	if string(out[:8]) != "unsigned" || !ed25519.Verify(f.priv.Public().(ed25519.PublicKey), out[:8], out[8:]) {
		t.Fatal("bundle is not the unsigned bytes and Vault's signature")
	}
	// What went to Vault: the bytes to sign and nothing of the key.
	priv := base64.StdEncoding.EncodeToString(f.priv)
	for _, b := range f.bodies {
		if strings.Contains(b, priv) || strings.Contains(b, priv[:43]) {
			t.Fatal("a request carried key material")
		}
	}
}

func TestCostBudget(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "fake-compile")
	_ = os.WriteFile(script, []byte(`#!/bin/sh
while [ $# -gt 0 ]; do
  case "$1" in
    --out) printf bundle > "$2"; shift 2 ;;
    --cost-report) printf '{"total":5000,"rules":[{"id":942100,"name":"SQL Injection Attack Detected via libinjection","cost":2081},{"id":941100,"name":"XSS Attack Detected via libinjection","cost":1751},{"id":932230,"name":"Remote Command Execution","cost":626},{"id":1,"name":"small","cost":2}]}' > "$2"; shift 2 ;;
    *) shift ;;
  esac
done
`), 0o755)
	c := &Compiler{Binary: script, KeyFile: "/keys/seed", CostBudget: 4999}
	_, err := c.Build(context.Background(), 1, []Named{{Name: "example-api", Spec: Spec{Mode: "enforce"}}})
	var ce *CostError
	if !errors.As(err, &ce) || ce.Total != 5000 || len(ce.Top) != 3 || ce.Top[0].ID != 942100 {
		t.Fatalf("err %v", err)
	}
	for _, want := range []string{"5000", "4999", "SQL Injection Attack Detected via libinjection", "XSS Attack", "932230"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%q lacks %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "small") {
		t.Error("more than three rules named")
	}
	c.CostBudget = 5000
	if out, err := c.Build(context.Background(), 1, []Named{{Name: "example-api", Spec: Spec{Mode: "enforce"}}}); err != nil || string(out) != "bundle" {
		t.Fatalf("at the budget: %q %v", out, err)
	}
}

// Key rotation: a pinned version signs even when a newer one exists.
func TestVaultSignerPinnedVersion(t *testing.T) {
	f, srv := newFakeVault(t)
	f.version = 3 // latest; the fake serves only that version
	v := &VaultSigner{Addr: srv.URL, Key: "strata-bundles", Token: "signer-token", Version: 2}
	if err := v.Init(context.Background()); err == nil || !strings.Contains(err.Error(), "no version 2") {
		t.Fatalf("missing pinned version: %v", err)
	}
	v.Version = 3
	if err := v.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Sign(context.Background(), []byte("x")); err != nil || !strings.Contains(f.bodies[len(f.bodies)-1], `"key_version":3`) {
		t.Fatalf("%v %s", err, f.bodies[len(f.bodies)-1])
	}
}
