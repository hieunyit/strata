// Package seclang reads ModSecurity / Coraza SecLang files into rules, with
// the SecLang grammar of the OWASP CRS project
// (github.com/coreruleset/seclang_parser, ANTLR). A chained rule is folded
// into the rule that starts the chain, as Strata's IR does (a flat AND).
package seclang

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/antlr4-go/antlr/v4"
	"github.com/coreruleset/seclang_parser/parser"
)

// Link is one SecRule of a chain (the first is the rule itself).
type Link struct {
	Line       int
	Variables  []string // e.g. ARGS, !REQUEST_COOKIES:/__utm/, &ARGS
	Operator   string   // e.g. rx, pm, detectSQLi; "rx" when the @name is omitted
	Negated    bool     // !@op
	Argument   string   // operator argument as written
	Transforms []string // t:none, t:urlDecodeUni, ... in order
	Actions    []string // action names other than t:, in order (id, phase, block, setvar...)
}

// Rule is one SecRule or SecAction with an id, its chain folded in.
type Rule struct {
	ID        int
	File      string
	Line      int
	Directive string // SecRule or SecAction
	Phase     string // as written: 1..5, request, response, logging
	Severity  string
	Msg       string
	Tags      []string
	Skip      int    // skip:N, the number of rules skipped when the rule matches
	Chain     []Link // len >= 1 for SecRule; [0] for SecAction holds its actions
}

// File is a parsed .conf file.
type File struct {
	Name       string
	Rules      []Rule
	Directives map[string]int // directive name -> count (SecRule, SecMarker, ...)
	Errors     []string       // syntax errors; empty means the whole file parsed
}

type errorCollector struct {
	*antlr.DefaultErrorListener
	errs []string
}

func (e *errorCollector) SyntaxError(_ antlr.Recognizer, sym interface{}, line, col int, msg string, _ antlr.RecognitionException) {
	e.errs = append(e.errs, fmt.Sprintf("line %d:%d: %s", line, col, msg))
}

// Parse reads one file. It returns an error only for problems that are not
// in the file's text; syntax errors are listed in File.Errors.
func Parse(name string, src string) (*File, error) {
	errs := &errorCollector{DefaultErrorListener: antlr.NewDefaultErrorListener()}
	lexer := parser.NewSecLangLexer(antlr.NewInputStream(src))
	lexer.RemoveErrorListeners()
	lexer.AddErrorListener(errs)
	p := parser.NewSecLangParser(antlr.NewCommonTokenStream(lexer, antlr.TokenDefaultChannel))
	p.RemoveErrorListeners()
	p.AddErrorListener(errs)
	tree := p.Configuration()

	f := &File{Name: name, Directives: map[string]int{}}
	var open *Rule // a rule whose last link said "chain"
	for _, st := range tree.AllStmt() {
		s, ok := st.(*parser.StmtContext)
		if !ok {
			continue
		}
		dir := directiveName(s)
		if dir == "" {
			continue // a comment block
		}
		f.Directives[dir]++
		switch {
		case s.Engine_config_rule_directive() != nil: // SecRule
			link := readLink(s.Variables(), s.Operator(), s.Actions())
			link.Line = s.Engine_config_rule_directive().GetStart().GetLine()
			chained := hasAction(link.Actions, "chain")
			if open != nil {
				open.Chain = append(open.Chain, link)
				if !chained {
					f.Rules = append(f.Rules, *open)
					open = nil
				}
				continue
			}
			r := Rule{File: name, Line: link.Line, Directive: "SecRule", Chain: []Link{link}}
			fillMeta(&r, s.Actions())
			if chained {
				open = &r
				continue
			}
			f.Rules = append(f.Rules, r)
		case dir == "SecAction":
			link := readLink(nil, nil, s.Engine_config_directive().Actions())
			link.Line = s.Engine_config_directive().GetStart().GetLine()
			r := Rule{File: name, Line: link.Line, Directive: "SecAction", Chain: []Link{link}}
			fillMeta(&r, s.Engine_config_directive().Actions())
			f.Rules = append(f.Rules, r)
		}
	}
	if open != nil {
		errs.errs = append(errs.errs, fmt.Sprintf("line %d: chain of rule %d never ends", open.Line, open.ID))
		f.Rules = append(f.Rules, *open)
	}
	f.Errors = errs.errs
	return f, nil
}

// directiveName is the directive keyword of a statement ("" for comments).
func directiveName(s *parser.StmtContext) string {
	if s.GetChildCount() == 0 {
		return ""
	}
	for _, c := range s.GetChildren() {
		pt, ok := c.(antlr.ParserRuleContext)
		if !ok {
			continue
		}
		if _, isComment := pt.(*parser.Comment_blockContext); isComment {
			continue
		}
		// The first token of the directive context is its keyword.
		if tok := pt.GetStart(); tok != nil {
			return tok.GetText()
		}
	}
	return ""
}

func readLink(vars parser.IVariablesContext, op parser.IOperatorContext, acts parser.IActionsContext) Link {
	var l Link
	if v, ok := vars.(*parser.VariablesContext); ok && v != nil {
		prefix := ""
		for _, c := range v.GetChildren() {
			switch c.(type) {
			case *parser.Var_notContext:
				prefix += "!"
			case *parser.Var_countContext:
				prefix += "&"
			case *parser.Var_stmtContext:
				l.Variables = append(l.Variables, prefix+c.(antlr.ParseTree).GetText())
				prefix = ""
			}
		}
	}
	if o, ok := op.(*parser.OperatorContext); ok && o != nil {
		l.Operator = "rx" // SecLang's default operator
		if n := o.Operator_name(); n != nil {
			l.Operator = strings.TrimPrefix(n.GetText(), "@")
		}
		l.Negated = o.Operator_not() != nil
		if v := o.Operator_value(); v != nil {
			l.Argument = v.GetText()
		}
	}
	for _, a := range actionsOf(acts) {
		if a.ACTION_TRANSFORMATION() != nil {
			l.Transforms = append(l.Transforms, a.Transformation_action_value().GetText())
			continue
		}
		l.Actions = append(l.Actions, actionName(a))
	}
	return l
}

func actionsOf(acts parser.IActionsContext) []*parser.ActionContext {
	a, ok := acts.(*parser.ActionsContext)
	if !ok || a == nil {
		return nil
	}
	var out []*parser.ActionContext
	for _, x := range a.AllAction_() {
		if ac, ok := x.(*parser.ActionContext); ok {
			out = append(out, ac)
		}
	}
	return out
}

func actionName(a *parser.ActionContext) string {
	if w := a.Action_with_params(); w != nil {
		return w.GetText()
	}
	if o := a.Action_only(); o != nil {
		return o.GetText()
	}
	return a.GetText()
}

func actionValue(a *parser.ActionContext) string {
	v := a.Action_value()
	if v == nil {
		return ""
	}
	return strings.Trim(v.GetText(), "'")
}

func hasAction(acts []string, name string) bool {
	for _, a := range acts {
		if a == name {
			return true
		}
	}
	return false
}

func fillMeta(r *Rule, acts parser.IActionsContext) {
	for _, a := range actionsOf(acts) {
		switch actionName(a) {
		case "id":
			r.ID, _ = strconv.Atoi(actionValue(a))
		case "phase":
			r.Phase = actionValue(a)
		case "severity":
			r.Severity = actionValue(a)
		case "msg":
			r.Msg = actionValue(a)
		case "tag":
			r.Tags = append(r.Tags, actionValue(a))
		case "skip":
			r.Skip, _ = strconv.Atoi(actionValue(a))
		}
	}
}

// ParanoiaLevel reads the paranoia-level/N tag, 0 when there is none.
func (r *Rule) ParanoiaLevel() int {
	for _, t := range r.Tags {
		if n, ok := strings.CutPrefix(t, "paranoia-level/"); ok {
			v, _ := strconv.Atoi(n)
			return v
		}
	}
	return 0
}

// Operators, Transforms, Variables and Actions of all links, de-duplicated
// in first-seen order.
func (r *Rule) Operators() []string {
	var out []string
	for _, l := range r.Chain {
		if l.Operator == "" {
			continue
		}
		op := "@" + l.Operator
		if l.Negated {
			op = "!" + op
		}
		out = append(out, op)
	}
	return uniq(out)
}

func (r *Rule) Transforms() []string {
	var out []string
	for _, l := range r.Chain {
		out = append(out, l.Transforms...)
	}
	return uniq(out)
}

func (r *Rule) Variables() []string {
	var out []string
	for _, l := range r.Chain {
		out = append(out, l.Variables...)
	}
	return uniq(out)
}

func (r *Rule) Actions() []string {
	var out []string
	for _, l := range r.Chain {
		out = append(out, l.Actions...)
	}
	u := uniq(out)
	sort.Strings(u)
	return u
}

func uniq(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
