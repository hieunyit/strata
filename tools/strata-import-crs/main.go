// Command strata-import-crs reads OWASP CRS (W03-S-02: inventory; the IR
// import of each group follows in later tasks).
//
//	strata-import-crs inventory --crs <coreruleset dir> [--out docs/crs-inventory.csv]
//	strata-import-crs ftw --crs <coreruleset dir> [--out corpus/crs-ftw] [--report docs/crs-ftw-unconverted.md]
//	strata-import-crs import --crs <coreruleset dir> [--out rules/crs] [--report docs/crs-import-report.md] [--compile strata-compile]
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
	"github.com/strata/strata/tools/strata-import-crs/internal/importer"
	"github.com/strata/strata/tools/strata-import-crs/internal/inventory"
)

func main() {
	if len(os.Args) >= 2 && os.Args[1] == "ftw" {
		ftwCmd()
		return
	}
	if len(os.Args) >= 2 && os.Args[1] == "import" {
		importCmd()
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

// Groups imported into rules/crs: the request groups that detect attacks
// (initialization, exclusions and blocking evaluation are CRS plumbing
// that Strata's engine does itself).
var groups = []importer.Group{
	{File: "REQUEST-911-METHOD-ENFORCEMENT.conf", Out: "911-method.yaml", Ruleset: "crs-911-method", AttackType: "protocol", Layer: "protocol"},
	{File: "REQUEST-913-SCANNER-DETECTION.conf", Out: "913-scanner.yaml", Ruleset: "crs-913-scanner", AttackType: "scanner", Layer: "managed"},
	{File: "REQUEST-920-PROTOCOL-ENFORCEMENT.conf", Out: "920-protocol.yaml", Ruleset: "crs-920-protocol", AttackType: "protocol", Layer: "protocol"},
	{File: "REQUEST-921-PROTOCOL-ATTACK.conf", Out: "921-protocol-attack.yaml", Ruleset: "crs-921-protocol-attack", AttackType: "protocol", Layer: "protocol"},
	{File: "REQUEST-922-MULTIPART-ATTACK.conf", Out: "922-multipart.yaml", Ruleset: "crs-922-multipart", AttackType: "protocol", Layer: "protocol"},
	{File: "REQUEST-930-APPLICATION-ATTACK-LFI.conf", Out: "930-lfi.yaml", Ruleset: "crs-930-lfi", AttackType: "path-traversal", Layer: "managed"},
	{File: "REQUEST-931-APPLICATION-ATTACK-RFI.conf", Out: "931-rfi.yaml", Ruleset: "crs-931-rfi", AttackType: "file-inclusion", Layer: "managed"},
	{File: "REQUEST-932-APPLICATION-ATTACK-RCE.conf", Out: "932-rce.yaml", Ruleset: "crs-932-rce", AttackType: "command-injection", Layer: "managed"},
	{File: "REQUEST-933-APPLICATION-ATTACK-PHP.conf", Out: "933-php.yaml", Ruleset: "crs-933-php", AttackType: "rce", Layer: "managed"},
	{File: "REQUEST-934-APPLICATION-ATTACK-GENERIC.conf", Out: "934-generic.yaml", Ruleset: "crs-934-generic", AttackType: "rce", Layer: "managed"},
	{File: "REQUEST-941-APPLICATION-ATTACK-XSS.conf", Out: "941-xss.yaml", Ruleset: "crs-941-xss", AttackType: "xss", Layer: "managed"},
	{File: "REQUEST-942-APPLICATION-ATTACK-SQLI.conf", Out: "942-sqli.yaml", Ruleset: "crs-942-sqli", AttackType: "sql-injection", Layer: "managed"},
	{File: "REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf", Out: "943-session-fixation.yaml", Ruleset: "crs-943-session-fixation", AttackType: "other", Layer: "managed"},
	{File: "REQUEST-944-APPLICATION-ATTACK-JAVA.conf", Out: "944-java.yaml", Ruleset: "crs-944-java", AttackType: "rce", Layer: "managed"},
}

// importCmd writes rules/crs/*.yaml and the import report.
func importCmd() {
	fs := flag.NewFlagSet("import", flag.ExitOnError)
	crs := fs.String("crs", "", "CRS release directory")
	out := fs.String("out", "rules/crs", "directory for the IR files")
	rep := fs.String("report", "docs/crs-import-report.md", "import report")
	compile := fs.String("compile", "", "strata-compile, to drop the rules it refuses (recommended)")
	maxPL := fs.Int("max-pl", 2, "maximum paranoia level imported (default 2)")
	_ = fs.Parse(os.Args[2:])
	die := func(err error) {
		fmt.Fprintln(os.Stderr, "strata-import-crs:", err)
		os.Exit(1)
	}
	if *crs == "" {
		die(errors.New("--crs is required"))
	}
	inv, err := inventory.Read(*crs)
	if err != nil {
		die(err)
	}
	res, err := importer.Import(groups, importer.Options{CRSDir: *crs, Version: inv.Version, MaxPL: *maxPL, Compile: *compile})
	if err != nil {
		die(err)
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		die(err)
	}
	total, imported := 0, 0
	for _, g := range res.Groups {
		total += g.Read
		imported += len(g.Rules)
		path := filepath.Join(*out, g.Group.Out)
		if len(g.Rules) == 0 {
			_ = os.Remove(path)
			continue
		}
		doc, err := importer.Marshal(g, inv.Version)
		if err != nil {
			die(err)
		}
		if err := os.WriteFile(path, doc, 0o644); err != nil {
			die(err)
		}
	}
	f, err := os.Create(*rep)
	if err != nil {
		die(err)
	}
	res.Report(f, inv.Version)
	if err := f.Close(); err != nil {
		die(err)
	}
	fmt.Fprintf(os.Stderr, "strata-import-crs: CRS %s, %d rules read, %d imported into %s, the rest in %s\n", inv.Version, total, imported, *out, *rep)
}
