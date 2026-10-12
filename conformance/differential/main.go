//go:build ignore

// Command differential runs the framing profiles over a corpus (or one raw
// request on stdin) and prints a JSON record per input, plus a summary of the
// divergent ones. Divergences are request-smuggling candidates.
//
//	go run . corpus/          # all *.http under corpus/
//	go run . < one-request.http
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	differential "github.com/strata/strata/conformance/differential"
)

func main() {
	var inputs []struct {
		name string
		raw  []byte
	}
	if len(os.Args) > 1 {
		root := os.Args[1]
		matches, _ := filepath.Glob(filepath.Join(root, "*.http"))
		for _, m := range matches {
			b, err := os.ReadFile(m)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(2)
			}
			inputs = append(inputs, struct {
				name string
				raw  []byte
			}{filepath.Base(m), b})
		}
	} else {
		b, _ := io.ReadAll(os.Stdin)
		inputs = append(inputs, struct {
			name string
			raw  []byte
		}{"stdin", b})
	}

	enc := json.NewEncoder(os.Stdout)
	divergent := 0
	for _, in := range inputs {
		r := differential.Compare(in.name, in.raw)
		if r.Divergent {
			divergent++
		}
		_ = enc.Encode(r)
	}
	fmt.Fprintf(os.Stderr, "%d inputs, %d framing divergences\n", len(inputs), divergent)
}
