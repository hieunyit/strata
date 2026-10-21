package control

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"

	fleetv1 "github.com/strata/strata/agent/gen/strata/fleet/v1"
)

// ModuleManifest is published with a module build. It describes the installed
// binary, not an authorization credential. Runtime versions must match as well.
type ModuleManifest struct {
	ModulePath    string   `json:"module_path"`
	SHA256        string   `json:"sha256"`
	ModuleVersion string   `json:"module_version"`
	ABI           uint32   `json:"abi_version"`
	Capabilities  []string `json:"capabilities"`
}

func ReadModuleManifest(file string) (*ModuleManifest, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, fmt.Errorf("module manifest: %w", err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() > 16384 {
		return nil, errors.New("module manifest: file must be regular and at most 16 KiB")
	}
	d := json.NewDecoder(io.LimitReader(f, 16385))
	d.DisallowUnknownFields()
	var m ModuleManifest
	if err := d.Decode(&m); err != nil {
		return nil, fmt.Errorf("module manifest: %w", err)
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return nil, errors.New("module manifest: trailing data")
	}
	if len(m.Capabilities) > 64 || len(m.ModuleVersion) > 64 || m.ModuleVersion == "" || m.ABI == 0 {
		return nil, errors.New("module manifest: invalid metadata")
	}
	capID := regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{0,63}$`)
	for _, c := range m.Capabilities {
		if !capID.MatchString(c) {
			return nil, errors.New("module manifest: invalid capability")
		}
	}
	binary, err := os.Open(m.ModulePath)
	if err != nil {
		return nil, fmt.Errorf("module manifest: binary: %w", err)
	}
	defer binary.Close()
	st, err = binary.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() > 64<<20 {
		return nil, errors.New("module manifest: invalid module file")
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(binary, (64<<20)+1))
	if err != nil {
		return nil, err
	}
	if n > 64<<20 || hex.EncodeToString(hash.Sum(nil)) != m.SHA256 {
		return nil, errors.New("module manifest: binary checksum mismatch")
	}
	return &m, nil
}

func (m *ModuleManifest) For(c *fleetv1.Connector) []string {
	if m == nil || c.GetAbiVersion() != m.ABI || c.GetModuleVersion() != m.ModuleVersion {
		return nil
	}
	return append([]string{}, m.Capabilities...)
}
