package bundlefmt

import (
	"bytes"
	"encoding/binary"
	"errors"
	"unicode/utf8"

	"github.com/strata/strata/agent/pkg/privacy"
)

// PrivacyFilters reads P-01 names/patterns from a signed v1 bundle. Identity key
// material stays inside the authenticated bytes and is never returned or logged.
func PrivacyFilters(data, pub []byte) (map[string]*privacy.Filter, error) {
	h, err := Verify(data, pub)
	if err != nil {
		return nil, err
	}
	if _, err := Requirements(data, pub); err != nil {
		return nil, err
	}
	out := map[string]*privacy.Filter{}
	if h.Policies == 0 {
		return out, nil
	}
	n := bytes.IndexByte(data[headerSize:headerSize+56], 0)
	if n < 1 {
		return nil, errors.New("bundle: invalid privacy policy name")
	}
	if _, err := VerifyPolicy(data, pub, string(data[headerSize:headerSize+n]), false); err != nil {
		return nil, err
	}
	names := make([]string, h.Policies)
	for i := range names {
		at := headerSize + i*64
		name := data[at : at+56]
		names[i] = string(name[:bytes.IndexByte(name, 0)])
		out[names[i]] = nil
	}
	off := binary.LittleEndian.Uint64(data[32:40])
	size := binary.LittleEndian.Uint64(data[40:48])
	if size == 0 {
		return out, nil
	}
	count := uint64(binary.LittleEndian.Uint32(data[off:]))
	var section []byte
	for at := off + 8; at < off+8+count*24; at += 24 {
		if binary.LittleEndian.Uint32(data[at:]) != 9 {
			continue
		}
		if section != nil {
			return nil, errors.New("bundle: duplicate privacy section")
		}
		start, length := binary.LittleEndian.Uint64(data[at+8:]), binary.LittleEndian.Uint64(data[at+16:])
		section = data[start : start+length]
	}
	if section == nil {
		for i := range names {
			if data[headerSize+i*64+62]&4 != 0 {
				return nil, errors.New("bundle: required privacy section missing")
			}
		}
		return out, nil
	}
	if len(section) < 40 {
		return nil, errors.New("bundle: short privacy header")
	}
	ne, ns := uint64(binary.LittleEndian.Uint32(section)), uint64(binary.LittleEndian.Uint32(section[4:]))
	if ne > uint64(h.Policies) || ns > ne*80 || 40+ne*24+ns*8 > uint64(len(section)) {
		return nil, errors.New("bundle: privacy table bounds")
	}
	stringsAt := 40 + ne*24
	blob := section[stringsAt+ns*8:]
	readStrings := func(first, n uint64) ([]string, error) {
		if first > ns || n > ns-first {
			return nil, errors.New("bundle: privacy string bounds")
		}
		items := []string{}
		for i := first; i < first+n; i++ {
			at := stringsAt + i*8
			o, l := uint64(binary.LittleEndian.Uint32(section[at:])), uint64(binary.LittleEndian.Uint32(section[at+4:]))
			if o > uint64(len(blob)) || l > uint64(len(blob))-o || l > 256 || !utf8.Valid(blob[o:o+l]) {
				return nil, errors.New("bundle: privacy string invalid")
			}
			items = append(items, string(blob[o:o+l]))
		}
		return items, nil
	}
	seen := map[uint64]bool{}
	for at := uint64(40); at < 40+ne*24; at += 24 {
		pi := uint64(binary.LittleEndian.Uint32(section[at:]))
		ff, fc := uint64(binary.LittleEndian.Uint32(section[at+4:])), uint64(binary.LittleEndian.Uint32(section[at+8:]))
		pf, pc := uint64(binary.LittleEndian.Uint32(section[at+12:])), uint64(binary.LittleEndian.Uint32(section[at+16:]))
		if pi >= uint64(h.Policies) || seen[pi] || fc > 64 || pc > 16 || binary.LittleEndian.Uint32(section[at+20:]) > 1 {
			return nil, errors.New("bundle: invalid privacy entry")
		}
		seen[pi] = true
		fields, err := readStrings(ff, fc)
		if err != nil {
			return nil, err
		}
		patterns, err := readStrings(pf, pc)
		if err != nil {
			return nil, err
		}
		filter, err := privacy.New(fields, patterns)
		if err != nil {
			return nil, err
		}
		if binary.LittleEndian.Uint32(section[at+20:])&1 != 0 {
			filter, err = filter.WithIdentityKey(section[8:40])
			if err != nil {
				return nil, err
			}
		}
		out[names[pi]] = filter
	}
	for i := range names {
		if data[headerSize+i*64+62]&4 != 0 && !seen[uint64(i)] {
			return nil, errors.New("bundle: required privacy entry missing")
		}
	}
	return out, nil
}
