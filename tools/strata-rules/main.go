// Command strata-rules works on the rule repository.
//
//	strata-rules lint [--repo <root>] [dir]   (default dir: rules)
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/strata/strata/tools/strata-rules/internal/lint"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] != "lint" {
		fmt.Fprintln(os.Stderr, "usage: strata-rules lint [--repo <root>] [dir]")
		os.Exit(2)
	}
	fs := flag.NewFlagSet("lint", flag.ExitOnError)
	repo := fs.String("repo", ".", "repository root (where docs/spec and rules/schema are)")
	_ = fs.Parse(os.Args[2:])
	dir := filepath.Join(*repo, "rules")
	if fs.NArg() > 0 {
		dir = fs.Arg(0)
	}
	l, err := lint.New(*repo)
	if err != nil {
		fmt.Fprintln(os.Stderr, "strata-rules:", err)
		os.Exit(2)
	}
	findings, files, err := l.Lint(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "strata-rules:", err)
		os.Exit(2)
	}
	for _, f := range findings {
		fmt.Println(f)
	}
	fmt.Fprintf(os.Stderr, "strata-rules lint: %d files, %d problems\n", files, len(findings))
	if len(findings) > 0 {
		os.Exit(1)
	}
}
