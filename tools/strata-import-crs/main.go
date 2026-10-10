// Command strata-import-crs reads OWASP CRS (W03-S-02: inventory; the IR
// import of each group follows in later tasks).
//
//	strata-import-crs inventory --crs <coreruleset dir> [--out docs/crs-inventory.csv]
//	strata-import-crs ftw --crs <coreruleset dir> [--out corpus/crs-ftw] [--report docs/crs-ftw-unconverted.md]
//
// The CRS directory is the one fetch-crs.sh prints.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/strata/strata/tools/strata-import-crs/internal/ftw"
	"github.com/strata/strata/tools/strata-import-crs/internal/inventory"
)

func main() {
	if len(os.Args) >= 2 && os.Args[1] == "ftw" {
		ftwCmd()
		return
	}
	if len(os.Args) < 2 || os.Args[1] != "inventory" {
		fmt.Fprintln(os.Stderr, "usage: strata-import-crs inventory|ftw --crs <dir> ...")
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

// ftwCmd converts the release's go-ftw tests (W04-S-01).
func ftwCmd() {
	fs := flag.NewFlagSet("ftw", flag.ExitOnError)
	crs := fs.String("crs", "", "CRS release directory")
	out := fs.String("out", "corpus/crs-ftw", "directory for the converted tests")
	rep := fs.String("report", "docs/crs-ftw-unconverted.md", "list of the tests not converted")
	_ = fs.Parse(os.Args[2:])
	if *crs == "" {
		fmt.Fprintln(os.Stderr, "strata-import-crs: --crs is required")
		os.Exit(2)
	}
	inv, err := inventory.Read(*crs)
	if err != nil {
		fmt.Fprintln(os.Stderr, "strata-import-crs:", err)
		os.Exit(1)
	}
	res, err := ftw.Convert(filepath.Join(*crs, "tests", "regression", "tests"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "strata-import-crs:", err)
		os.Exit(1)
	}
	if err := res.Write(*out); err != nil {
		fmt.Fprintln(os.Stderr, "strata-import-crs:", err)
		os.Exit(1)
	}
	f, err := os.Create(*rep)
	if err != nil {
		fmt.Fprintln(os.Stderr, "strata-import-crs:", err)
		os.Exit(1)
	}
	res.Report(f, inv.Version)
	if err := f.Close(); err != nil {
		fmt.Fprintln(os.Stderr, "strata-import-crs:", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "strata-import-crs: %d go-ftw tests, %d converted, %d listed in %s\n",
		res.Total, res.Total-len(res.Skipped), len(res.Skipped), *rep)
}
