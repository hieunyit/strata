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
)

// Control file layout (docs/design/control-file.md).
const (
	ControlSize = 4096
	ctlLayout   = 1
	ctlGenOff   = 16
	nameMax     = 255
)

var ctlMagic = []byte("STRCTL1\x00")

// Control is what the control file names.
type Control struct {
	Generation uint64
	Version    uint64
	SHA256     [32]byte
	Name       string
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
	return c, nil
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
	if cur.Generation%2 == 1 {
		// Only this agent writes: an odd generation is a write a crash
		// interrupted. Finishing it is what this write does.
		cur.Generation++
	}
	next := cur.Generation + 2
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	put := func(off int64, b []byte) error {
		_, err := f.WriteAt(b, off)
		return err
	}
	gen := make([]byte, 8)
	binary.LittleEndian.PutUint64(gen, next-1) // odd: being written
	if err := put(ctlGenOff, gen); err != nil {
		return 0, err
	}
	if err := put(24, body[24:]); err != nil {
		return 0, err
	}
	if err := put(0, body[:ctlGenOff]); err != nil {
		return 0, err
	}
	binary.LittleEndian.PutUint64(gen, next)
	if err := put(ctlGenOff, gen); err != nil {
		return 0, err
	}
	return next, f.Sync()
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
