// Command strata-import-crs reads OWASP CRS (W03-S-02: inventory; the IR
// import of each group follows in later tasks).
//
//	strata-import-crs inventory --crs <coreruleset dir> [--out docs/crs-inventory.csv]
//
// The CRS directory is the one fetch-crs.sh prints.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/strata/strata/tools/strata-import-crs/internal/inventory"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] != "inventory" {
		fmt.Fprintln(os.Stderr, "usage: strata-import-crs inventory --crs <dir> [--out file.csv]")
		os.Exit(2)
	}
	fs := flag.NewFlagSet("inventory", flag.ExitOnError)
	crs := fs.String("crs", "", "CRS release directory (contains rules/ and crs-setup.conf.example)")
	out := fs.String("out", "docs/crs-inventory.csv", "CSV to write")
	_ = fs.Parse(os.Args[2:])
	if *crs == "" {
		fmt.Fprintln(os.Stderr, "strata-import-crs: --crs is required (see tools/strata-import-crs/fetch-crs.sh)")
		os.Exit(2)
	}
	inv, err := inventory.Read(*crs)
	if err != nil {
		var pe *inventory.ParseError
		if errors.As(err, &pe) {
			for _, e := range pe.Errors {
				fmt.Fprintln(os.Stderr, e)
			}
		}
		fmt.Fprintln(os.Stderr, "strata-import-crs:", err)
		os.Exit(1)
	}
	f, err := os.Create(*out)
	if err != nil {
		fmt.Fprintln(os.Stderr, "strata-import-crs:", err)
		os.Exit(1)
	}
	if err := inv.WriteCSV(f); err != nil {
		f.Close()
		fmt.Fprintln(os.Stderr, "strata-import-crs:", err)
		os.Exit(1)
	}
	if err := f.Close(); err != nil {
		fmt.Fprintln(os.Stderr, "strata-import-crs:", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "strata-import-crs: CRS %s, %d files parsed (100%%), %d rules -> %s\n", inv.Version, len(inv.Files), len(inv.Rules), *out)
}
