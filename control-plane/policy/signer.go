package policy

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Signer signs bundles with a key it keeps (a KMS). The bundle is the
// unsigned bytes followed by the 64-byte Ed25519 signature over them.
type Signer interface {
	// PublicKey verifies what Sign returns.
	PublicKey(ctx context.Context) (ed25519.PublicKey, error)
	Sign(ctx context.Context, msg []byte) ([]byte, error)
}

// VaultSigner signs through Vault's transit engine with an ed25519 key
// that Vault does not let out: the control plane sends the bytes and gets
// the signature, it never holds the key.
type VaultSigner struct {
	Addr  string // e.g. https://vault.example.test:8200
	Mount string // transit mount, default "transit"
	Key   string // key name
	Token string // a token allowed to sign with Key and read it, nothing else
	HTTP  *http.Client

	version int // key version pinned by Init
	pub     ed25519.PublicKey
}

// MaxVaultMessage: Vault refuses request bodies over 32 MiB by default,
// and the message travels base64-encoded.
const MaxVaultMessage = 24 << 20

// Init reads the key: it must be ed25519, not exportable and without
// plaintext backup; its latest version is pinned (a rotation in Vault
// would make bundles the nodes refuse, so it needs a restart).
func (v *VaultSigner) Init(ctx context.Context) error {
	if v.Mount == "" {
		v.Mount = "transit"
	}
	if v.HTTP == nil {
		v.HTTP = &http.Client{Timeout: 30 * time.Second}
	}
	if v.Addr == "" || v.Key == "" || v.Token == "" {
		return errors.New("vault signer: address, key and token are required")
	}
	var resp struct {
		Data struct {
			Type                 string `json:"type"`
			Exportable           bool   `json:"exportable"`
			AllowPlaintextBackup bool   `json:"allow_plaintext_backup"`
			LatestVersion        int    `json:"latest_version"`
			Keys                 map[string]struct {
				PublicKey string `json:"public_key"`
			} `json:"keys"`
		} `json:"data"`
	}
	if err := v.call(ctx, http.MethodGet, "keys/"+url.PathEscape(v.Key), nil, &resp); err != nil {
		return err
	}
	d := resp.Data
	switch {
	case d.Type != "ed25519":
		return fmt.Errorf("vault signer: key %q is %q, want ed25519", v.Key, d.Type)
	case d.Exportable || d.AllowPlaintextBackup:
		return fmt.Errorf("vault signer: key %q can leave Vault (exportable or plaintext backup); refused", v.Key)
	}
	k, ok := d.Keys[strconv.Itoa(d.LatestVersion)]
	if !ok {
		return fmt.Errorf("vault signer: key %q has no version %d", v.Key, d.LatestVersion)
	}
	pub, err := base64.StdEncoding.DecodeString(k.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("vault signer: key %q: bad public key", v.Key)
	}
	v.version, v.pub = d.LatestVersion, pub
	return nil
}

// PublicKey of the pinned key version.
func (v *VaultSigner) PublicKey(context.Context) (ed25519.PublicKey, error) {
	if v.pub == nil {
		return nil, errors.New("vault signer: not initialized")
	}
	return v.pub, nil
}

// Sign signs msg with the pinned key version.
func (v *VaultSigner) Sign(ctx context.Context, msg []byte) ([]byte, error) {
	if v.pub == nil {
		return nil, errors.New("vault signer: not initialized")
	}
	if len(msg) > MaxVaultMessage {
		return nil, fmt.Errorf("vault signer: bundle of %d bytes is over %d", len(msg), MaxVaultMessage)
	}
	req := map[string]any{"input": base64.StdEncoding.EncodeToString(msg), "key_version": v.version}
	var resp struct {
		Data struct {
			Signature string `json:"signature"`
		} `json:"data"`
	}
	if err := v.call(ctx, http.MethodPost, "sign/"+url.PathEscape(v.Key), req, &resp); err != nil {
		return nil, err
	}
	prefix := "vault:v" + strconv.Itoa(v.version) + ":"
	if !strings.HasPrefix(resp.Data.Signature, prefix) {
		return nil, fmt.Errorf("vault signer: signature not from key version %d", v.version)
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(resp.Data.Signature, prefix))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, errors.New("vault signer: bad signature")
	}
	if !ed25519.Verify(v.pub, msg, sig) {
		return nil, errors.New("vault signer: signature does not verify with the key's public key")
	}
	return sig, nil
}

func (v *VaultSigner) call(ctx context.Context, method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	u := strings.TrimRight(v.Addr, "/") + "/v1/" + strings.Trim(v.Mount, "/") + "/" + path
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return err
	}
	req.Header.Set("X-Vault-Token", v.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := v.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("vault signer: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("vault signer: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		// Vault's errors name the path and the reason; they hold no secret.
		msg := string(data)
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return fmt.Errorf("vault signer: %s %s: %d %s", method, path, resp.StatusCode, msg)
	}
	return json.Unmarshal(data, out)
}
