package bundlefmt

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

// VerifyPolicy verifies the signature and bounded v1 policy table, then checks
// a selected name and optionally full enforce (no canary). It does not validate
// engine sections, Hyperscan compatibility or whether rules detect an attack.
func VerifyPolicy(data, pub []byte, name string, requireEnforce bool) (Header, error) {
	if !validPolicyName(name) {
		return Header{}, errors.New("bundle: policy name must be 1..55 lowercase ASCII letters, digits, dots, underscores or hyphens")
	}
	h, err := Verify(data, pub)
	if err != nil {
		return Header{}, err
	}
	const entrySize = 64
	if h.Policies > 4096 {
		return Header{}, errors.New("bundle: too many policies")
	}
	end := uint64(headerSize) + uint64(h.Policies)*entrySize
	signedLen := uint64(len(data) - sigSize)
	sectionOff := binary.LittleEndian.Uint64(data[32:40])
	sectionLen := binary.LittleEndian.Uint64(data[40:48])
	if end > signedLen || sectionOff < end || sectionOff%4096 != 0 || sectionOff > signedLen || sectionLen > signedLen-sectionOff {
		return Header{}, errors.New("bundle: invalid policy table bounds")
	}
	seen := make(map[string]bool, h.Policies)
	found := false
	for off := headerSize; uint64(off) < end; off += entrySize {
		e := data[off : off+entrySize]
		n := bytes.IndexByte(e[:56], 0)
		if n < 1 || n > 55 {
			return Header{}, errors.New("bundle: invalid policy name")
		}
		policy := string(e[:n])
		if !validPolicyName(policy) {
			return Header{}, errors.New("bundle: invalid policy name")
		}
		for _, b := range e[n:56] {
			if b != 0 {
				return Header{}, errors.New("bundle: nonzero policy name padding")
			}
		}
		if seen[policy] {
			return Header{}, errors.New("bundle: duplicate policy name")
		}
		seen[policy] = true
		canary := binary.LittleEndian.Uint16(e[59:61])
		if e[56] > 1 || canary > 9999 || (e[56] == 0 && canary != 0) {
			return Header{}, errors.New("bundle: invalid policy mode/canary")
		}
		if policy == name {
			found = true
			if requireEnforce && (e[56] != 1 || canary != 0) {
				return Header{}, fmt.Errorf("bundle: policy %q is not full enforce", name)
			}
		}
	}
	if !found {
		return Header{}, fmt.Errorf("bundle: policy %q not found", name)
	}
	return h, nil
}

func validPolicyName(name string) bool {
	if len(name) < 1 || len(name) > 55 {
		return false
	}
	for _, b := range []byte(name) {
		switch {
		case b >= 'a' && b <= 'z', b >= '0' && b <= '9', b == '.', b == '_', b == '-':
		default:
			return false
		}
	}
	return true
}
