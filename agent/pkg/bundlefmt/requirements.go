package bundlefmt

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
)

// Requirements reads compatibility metadata only after authenticating the bundle.
// It does not change the v1 format or replace the engine's layout validation.
func Requirements(data, pub []byte) ([]string, error) {
	h, err := Verify(data, pub)
	if err != nil {
		return nil, err
	}
	end := uint64(len(data) - sigSize)
	tableEnd := uint64(headerSize) + uint64(h.Policies)*64
	if h.Policies > 4096 || tableEnd > end {
		return nil, errors.New("bundle: invalid policy table")
	}
	set := map[string]bool{}
	for off := uint64(headerSize); off < tableEnd; off += 64 {
		flags := data[off+62]
		if flags&3 == 3 {
			return nil, errors.New("bundle: invalid snippet size")
		}
		if flags&3 != 0 {
			set[fmt.Sprintf("snippet.%d", []int{128, 2048, 4096}[flags&3])] = true
		}
		if data[off+63] != 0 {
			set["max_args"] = true
		}
	}
	off := binary.LittleEndian.Uint64(data[32:40])
	size := binary.LittleEndian.Uint64(data[40:48])
	if size == 0 {
		return sortedRequirements(set), nil
	}
	if off < tableEnd || off%4096 != 0 || off > end || size > end-off || size < 8 {
		return nil, errors.New("bundle: invalid sections")
	}
	n := uint64(binary.LittleEndian.Uint32(data[off:]))
	if n > 64 || 8+n*24 > size {
		return nil, errors.New("bundle: invalid section directory")
	}
	for at := off + 8; at < off+8+n*24; at += 24 {
		kind := binary.LittleEndian.Uint32(data[at:])
		start := binary.LittleEndian.Uint64(data[at+8:])
		length := binary.LittleEndian.Uint64(data[at+16:])
		if start < off+8+n*24 || start > off+size || length > off+size-start {
			return nil, errors.New("bundle: invalid section bounds")
		}
		if kind >= 8 && length > 0 {
			set[fmt.Sprintf("section.%d", kind)] = true
		}
	}
	return sortedRequirements(set), nil
}

func sortedRequirements(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for c := range set {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}
