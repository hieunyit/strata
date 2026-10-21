package apidiscovery

import (
	"fmt"
	"sort"
)

func Propose(before []Operation, path, method string, contentTypes []string, observedMax int64) ([]Operation, error) {
	out := make([]Operation, len(before))
	copy(out, before)
	index := -1
	for i, v := range out {
		if v.Method == method && Matches(v.Path, path) {
			index = i
			break
		}
	}
	if index < 0 {
		if len(out) >= 2000 {
			return nil, fmt.Errorf("discovery: operation quota")
		}
		out = append(out, Operation{Path: path, Method: method, ContentTypes: []string{}})
		index = len(out) - 1
	}
	op := out[index]
	types := map[string]bool{}
	for _, v := range op.ContentTypes {
		types[v] = true
	}
	for _, v := range contentTypes {
		if v != "none" && v != "other" {
			types[v] = true
		}
	}
	op.ContentTypes = []string{}
	for v := range types {
		op.ContentTypes = append(op.ContentTypes, v)
	}
	sort.Strings(op.ContentTypes)
	if observedMax > op.MaxBodyBytes {
		op.MaxBodyBytes = ((observedMax + 65535) / 65536) * 65536
	}
	out[index] = op
	sortOperations(out)
	if Digest(out) == Digest(before) {
		return nil, fmt.Errorf("discovery: no proposed changes")
	}
	return out, nil
}

type Change struct {
	Path   string     `json:"path"`
	Method string     `json:"method"`
	Kind   string     `json:"kind"`
	Before *Operation `json:"before"`
	After  *Operation `json:"after"`
}

func Diff(before, after []Operation) []Change {
	out := []Change{}
	old := map[string]Operation{}
	for _, v := range before {
		old[v.Path+"/"+v.Method] = v
	}
	for _, v := range after {
		key := v.Path + "/" + v.Method
		previous, exists := old[key]
		copy := v
		if !exists {
			out = append(out, Change{Path: v.Path, Method: v.Method, Kind: "added", After: &copy})
		} else if Digest([]Operation{previous}) != Digest([]Operation{v}) {
			original := previous
			out = append(out, Change{Path: v.Path, Method: v.Method, Kind: "modified", Before: &original, After: &copy})
		}
	}
	return out
}
