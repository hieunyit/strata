// Package bundlefmt reads the signed header of a Strata bundle
// (docs/design/control-file.md › Bundle v1): a 64-byte header, sections,
// and an Ed25519 signature over everything before the last 64 bytes. It
// checks the signature only; the engine checks the layout.
package bundlefmt

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	headerSize = 64
	sigSize    = ed25519.SignatureSize
	// FlagRollback allows a version lower than the one running.
	FlagRollback = 1 << 0
)

var magic = []byte("STRBNDL\x00")

// Header is the signed header.
type Header struct {
	Format    uint16
	Flags     uint16
	Policies  uint32
	Version   uint64
	CreatedMs uint64
}

// MaxKeys trusted at once: the current signing key and, while it is
// rotated, the next one (docs/design/control-file.md, "Xoay khóa ký").
const MaxKeys = 2

// ValidKeys: one Ed25519 public key, or two concatenated.
func ValidKeys(pub []byte) bool {
	return len(pub) == ed25519.PublicKeySize || len(pub) == MaxKeys*ed25519.PublicKeySize
}

// Verify checks data's signature with pub (one or two 32-byte keys: the
// bundle may be signed by either) and returns the header.
func Verify(data, pub []byte) (Header, error) {
	if !ValidKeys(pub) {
		return Header{}, fmt.Errorf("bundle: public keys of %d bytes, want %d or %d", len(pub), ed25519.PublicKeySize, MaxKeys*ed25519.PublicKeySize)
	}
	if len(data) < headerSize+sigSize {
		return Header{}, errors.New("bundle: too short")
	}
	body, sig := data[:len(data)-sigSize], data[len(data)-sigSize:]
	ok := false
	for k := 0; k+ed25519.PublicKeySize <= len(pub) && !ok; k += ed25519.PublicKeySize {
		ok = ed25519.Verify(ed25519.PublicKey(pub[k:k+ed25519.PublicKeySize]), body, sig)
	}
	if !ok {
		return Header{}, errors.New("bundle: signature does not verify")
	}
	if string(data[:8]) != string(magic) {
		return Header{}, errors.New("bundle: bad magic")
	}
	h := Header{
		Format:    binary.LittleEndian.Uint16(data[8:]),
		Flags:     binary.LittleEndian.Uint16(data[10:]),
		Policies:  binary.LittleEndian.Uint32(data[12:]),
		Version:   binary.LittleEndian.Uint64(data[16:]),
		CreatedMs: binary.LittleEndian.Uint64(data[24:]),
	}
	if h.Format != 1 {
		return Header{}, fmt.Errorf("bundle: format %d, this build reads 1", h.Format)
	}
	return h, nil
}
