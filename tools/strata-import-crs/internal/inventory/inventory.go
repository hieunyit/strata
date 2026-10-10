// Package inventory lists every rule of a CRS release (W03-S-02):
// docs/crs-inventory.csv with, per rule id, its phase, operators,
// transformations, variables and actions.
package inventory

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/strata/strata/tools/strata-import-crs/internal/seclang"
)

// Inventory is a parsed CRS release.
type Inventory struct {
	Version string
	Files   []string
	Rules   []seclang.Rule
}

// ParseError lists the syntax errors of every file that did not parse.
type ParseError struct{ Errors []string }

func (e *ParseError) Error() string {
	return fmt.Sprintf("%d syntax errors: not every file parsed", len(e.Errors))
}

var versionRe = regexp.MustCompile(`OWASP_CRS/(\d+\.\d+\.\d+)`)

// Read parses rules/*.conf and crs-setup.conf.example of a release. Any
// syntax error fails the whole read: the inventory is all or nothing.
func Read(dir string) (*Inventory, error) {
	files, err := filepath.Glob(filepath.Join(dir, "rules", "*.conf"))
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no rules/*.conf under %s", dir)
	}
	files = append(files, filepath.Join(dir, "crs-setup.conf.example"))
	sort.Strings(files)
	inv := &Inventory{}
	var syntax []string
	seen := map[int]string{}
	for _, p := range files {
		src, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		name := filepath.Base(p)
		if inv.Version == "" {
			if m := versionRe.FindSubmatch(src); m != nil {
				inv.Version = string(m[1])
			}
		}
		f, err := seclang.Parse(name, string(src))
		if err != nil {
			return nil, err
		}
		for _, e := range f.Errors {
			syntax = append(syntax, name+": "+e)
		}
		for _, r := range f.Rules {
			if r.ID == 0 {
				syntax = append(syntax, fmt.Sprintf("%s: line %d: %s without an id", name, r.Line, r.Directive))
				continue
			}
			if prev, dup := seen[r.ID]; dup {
				syntax = append(syntax, fmt.Sprintf("%s: line %d: id %d already in %s", name, r.Line, r.ID, prev))
				continue
			}
			seen[r.ID] = name
			inv.Rules = append(inv.Rules, r)
		}
		inv.Files = append(inv.Files, name)
	}
	if len(syntax) > 0 {
		return nil, &ParseError{Errors: syntax}
	}
	sort.Slice(inv.Rules, func(i, j int) bool { return inv.Rules[i].ID < inv.Rules[j].ID })
	return inv, nil
}

// Header of the CSV. Lists inside a cell are separated by " | ".
var Header = []string{
	"rule_id", "file", "line", "directive", "phase", "paranoia_level", "severity",
	"operators", "transformations", "variables", "actions", "chain_links", "msg",
}

// WriteCSV writes one row per rule, sorted by id.
func (inv *Inventory) WriteCSV(w io.Writer) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(Header); err != nil {
		return err
	}
	j := func(s []string) string { return strings.Join(s, " | ") }
	for i := range inv.Rules {
		r := &inv.Rules[i]
		pl := ""
		if n := r.ParanoiaLevel(); n > 0 {
			pl = strconv.Itoa(n)
		}
		row := []string{
			strconv.Itoa(r.ID), r.File, strconv.Itoa(r.Line), r.Directive, r.Phase, pl, r.Severity,
			j(r.Operators()), j(r.Transforms()), j(r.Variables()), j(r.Actions()),
			strconv.Itoa(len(r.Chain)), r.Msg,
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}
