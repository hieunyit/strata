// Command fakecompile stands in for strata-compile in tests/e2e, where no
// Rust toolchain is installed: it reads the policies file and writes a
// bundle with the real header layout, signed with the seed in --key. The
// lab smoke test runs the real compiler.
package main

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
)

func main() {
	var policies, key, out string
	var version uint64
	for i := 1; i+1 < len(os.Args); i += 2 {
		switch os.Args[i] {
		case "--policies":
			policies = os.Args[i+1]
		case "--key":
			key = os.Args[i+1]
		case "--out":
			out = os.Args[i+1]
		case "--version":
			version, _ = strconv.ParseUint(os.Args[i+1], 10, 64)
		}
	}
	raw, err := os.ReadFile(policies)
	if err != nil {
		fail(err)
	}
	var doc struct {
		Policies []json.RawMessage `json:"policies"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		fail(err)
	}
	seed, err := os.ReadFile(key)
	if err != nil || len(seed) != ed25519.SeedSize {
		fail(fmt.Errorf("key: %v (%d bytes)", err, len(seed)))
	}
	b := make([]byte, 4096)
	copy(b, "STRBNDL\x00")
	binary.LittleEndian.PutUint16(b[8:], 1)
	binary.LittleEndian.PutUint32(b[12:], uint32(len(doc.Policies)))
	binary.LittleEndian.PutUint64(b[16:], version)
	copy(b[64:], raw) // the policies, so different contents give different bundles
	b = append(b, ed25519.Sign(ed25519.NewKeyFromSeed(seed), b)...)
	if err := os.WriteFile(out, b, 0o644); err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "fakecompile:", err)
	os.Exit(1)
}
