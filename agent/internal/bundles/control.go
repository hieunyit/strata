// Package bundles installs the bundles the control plane rolls out
// (nginx-module.md › Phân phối bundle; docs/design/control-file.md): it
// downloads with FetchBundle, resuming from the offset reached, checks
// size, SHA-256 and signature, writes the file under a new name with
// fsync and rename, and only then points the control file at it, in place.
package bundles

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Control file layout (docs/design/control-file.md).
const (
	ControlSize = 4096
	ctlLayout   = 1
	ctlGenOff   = 16
	nameMax     = 255
	// bundle fields: 24 up to the force-shadow block
	ctlBundleEnd = 322
	// force-shadow block (W07-N-01, decision Q2)
	ctlForceOff   = 324
	ctlForceNames = 336
	ctlForceEnd   = ctlForceNames + MaxForcePolicies*forceNameSize
	forceNameSize = 56
	// MaxForcePolicies the control file can name.
	MaxForcePolicies = 32
	// disabled-rules block (W12-G1-02): count u32, reserved u32, IDs
	ctlRulesOff = 2128
	ctlRulesIDs = ctlRulesOff + 8
	ctlRulesEnd = ctlRulesIDs + MaxDisabledRules*4
	// MaxDisabledRules the control file can hold.
	MaxDisabledRules = 480
)

var ctlMagic = []byte("STRCTL1\x00")

// ctlMu serializes this process's writes of control files: the bundle
// manager and the force-shadow commands write the same file, each with the
// seqlock, which allows one writer at a time.
var ctlMu sync.Mutex

// Control is what the control file names.
type Control struct {
	Generation uint64
	Version    uint64
	SHA256     [32]byte
	Name       string
	// ForceAll and ForcePolicies: the force-shadow block.
	ForceAll      bool
	ForcePolicies []string
	// DisabledRules: the disabled-rules block (emergency kill switch).
	DisabledRules []uint32
}

// ReadControl reads path; os.ErrNotExist when there is none yet.
func ReadControl(path string) (Control, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Control{}, err
	}
	if len(b) != ControlSize || string(b[:8]) != string(ctlMagic) || binary.LittleEndian.Uint32(b[8:]) != ctlLayout {
		return Control{}, fmt.Errorf("bundles: %s is not a control file", path)
	}
	c := Control{Generation: binary.LittleEndian.Uint64(b[16:]), Version: binary.LittleEndian.Uint64(b[24:])}
	copy(c.SHA256[:], b[32:64])
	n := int(binary.LittleEndian.Uint16(b[64:]))
	if n > nameMax {
		return Control{}, fmt.Errorf("bundles: %s: name of %d bytes", path, n)
	}
	c.Name = string(b[66 : 66+n])
	c.ForceAll = binary.LittleEndian.Uint32(b[ctlForceOff:])&1 != 0
	cnt := int(binary.LittleEndian.Uint32(b[ctlForceOff+4:]))
	if cnt > MaxForcePolicies {
		return Control{}, fmt.Errorf("bundles: %s: %d force-shadow policies", path, cnt)
	}
	for i := 0; i < cnt; i++ {
		f := b[ctlForceNames+i*forceNameSize : ctlForceNames+(i+1)*forceNameSize]
		end := 0
		for end < len(f) && f[end] != 0 {
			end++
		}
		c.ForcePolicies = append(c.ForcePolicies, string(f[:end]))
	}
	nr := int(binary.LittleEndian.Uint32(b[ctlRulesOff:]))
	if nr > MaxDisabledRules {
		return Control{}, fmt.Errorf("bundles: %s: %d disabled rules", path, nr)
	}
	for i := 0; i < nr; i++ {
		c.DisabledRules = append(c.DisabledRules, binary.LittleEndian.Uint32(b[ctlRulesIDs+4*i:]))
	}
	return c, nil
}

// WriteDisabledRules sets the disabled-rules block of an existing control
// file in place, with the seqlock; workers apply it at their next read
// (≤ 1 s). os.ErrNotExist when there is no control file yet.
func WriteDisabledRules(path string, ids []uint32) (uint64, error) {
	if len(ids) > MaxDisabledRules {
		return 0, fmt.Errorf("bundles: %d disabled rules, at most %d", len(ids), MaxDisabledRules)
	}
	block := make([]byte, ctlRulesEnd-ctlRulesOff)
	binary.LittleEndian.PutUint32(block, uint32(len(ids)))
	for i, id := range ids {
		binary.LittleEndian.PutUint32(block[8+4*i:], id)
	}
	ctlMu.Lock()
	defer ctlMu.Unlock()
	cur, err := ReadControl(path)
	if err != nil {
		return 0, err
	}
	return writeInPlace(path, cur.Generation, func(put func(int64, []byte) error) error {
		return put(ctlRulesOff, block)
	})
}

// ValidPolicyName: what the control file and the bundle accept as a policy
// name, [a-z0-9._-]{1,55}.
func ValidPolicyName(name string) bool {
	if name == "" || len(name) >= forceNameSize {
		return false
	}
	for _, c := range []byte(name) {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '.' && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

// WriteForceShadow sets the force-shadow block of an existing control file
// in place, with the seqlock; workers apply it at their next read (≤ 1 s)
// without reloading the bundle. os.ErrNotExist when there is no control
// file yet (no bundle installed).
func WriteForceShadow(path string, all bool, policies []string) (uint64, error) {
	if len(policies) > MaxForcePolicies {
		return 0, fmt.Errorf("bundles: %d force-shadow policies, at most %d", len(policies), MaxForcePolicies)
	}
	block := make([]byte, ctlForceEnd-ctlForceOff)
	if all {
		binary.LittleEndian.PutUint32(block, 1)
	}
	binary.LittleEndian.PutUint32(block[4:], uint32(len(policies)))
	for i, p := range policies {
		if !ValidPolicyName(p) {
			return 0, fmt.Errorf("bundles: bad policy name %q", p)
		}
		copy(block[ctlForceNames-ctlForceOff+i*forceNameSize:], p)
	}
	ctlMu.Lock()
	defer ctlMu.Unlock()
	cur, err := ReadControl(path)
	if err != nil {
		return 0, err
	}
	return writeInPlace(path, cur.Generation, func(put func(int64, []byte) error) error {
		return put(ctlForceOff, block)
	})
}

// writeInPlace runs the seqlock around fields: odd generation, fields,
// next even generation, fsync.
func writeInPlace(path string, gen uint64, fields func(put func(int64, []byte) error) error) (uint64, error) {
	if gen%2 == 1 {
		// Only this agent writes: an odd generation is a write a crash
		// interrupted. Finishing it is what this write does.
		gen++
	}
	next := gen + 2
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	put := func(off int64, b []byte) error {
		_, err := f.WriteAt(b, off)
		return err
	}
	g := make([]byte, 8)
	binary.LittleEndian.PutUint64(g, next-1) // odd: being written
	if err := put(ctlGenOff, g); err != nil {
		return 0, err
	}
	if err := fields(put); err != nil {
		return 0, err
	}
	binary.LittleEndian.PutUint64(g, next)
	if err := put(ctlGenOff, g); err != nil {
		return 0, err
	}
	return next, f.Sync()
}

func validName(name string) bool {
	if name == "" || len(name) > nameMax || name == "." || name == ".." {
		return false
	}
	for _, c := range []byte(name) {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '.' && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

// WriteControl points path at bundle name. An existing file is updated in
// place with the seqlock (odd generation, fields, next even generation):
// the NGINX workers map its inode, so it is never replaced. A missing file
// is created whole (generation 2) under a temporary name, then renamed.
func WriteControl(path string, version uint64, sha [32]byte, name string) (uint64, error) {
	if !validName(name) {
		return 0, fmt.Errorf("bundles: bad bundle file name %q", name)
	}
	body := make([]byte, ControlSize)
	copy(body, ctlMagic)
	binary.LittleEndian.PutUint32(body[8:], ctlLayout)
	binary.LittleEndian.PutUint64(body[24:], version)
	copy(body[32:64], sha[:])
	binary.LittleEndian.PutUint16(body[64:], uint16(len(name)))
	copy(body[66:], name)

	ctlMu.Lock()
	defer ctlMu.Unlock()
	cur, err := ReadControl(path)
	if errors.Is(err, os.ErrNotExist) {
		binary.LittleEndian.PutUint64(body[ctlGenOff:], 2)
		tmp := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".new")
		if err := os.WriteFile(tmp, body, 0o644); err != nil {
			return 0, err
		}
		if err := syncFile(tmp); err != nil {
			return 0, err
		}
		if err := os.Rename(tmp, path); err != nil {
			return 0, err
		}
		return 2, syncDir(filepath.Dir(path))
	}
	if err != nil {
		return 0, err
	}
	// Only the bundle fields: the force-shadow block stays as it is.
	return writeInPlace(path, cur.Generation, func(put func(int64, []byte) error) error {
		if err := put(24, body[24:ctlBundleEnd]); err != nil {
			return err
		}
		return put(0, body[:ctlGenOff])
	})
}

func syncFile(p string) error {
	f, err := os.Open(p)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func syncDir(p string) error {
	d, err := os.Open(p)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
