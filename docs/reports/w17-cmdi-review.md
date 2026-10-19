# W17-R-01: CMDi detector, compiler/runtime

Source: `engine/src/detectors/injection/cmdi.rs` of `25e959e` (branch
`W17-cmdi-ssti-ja4`), as repaired by the unfinished `codex/w17-cmdi-component`
work tree (quadratic suffix scans and recursive substitution removed, bounded
token storage, path boundaries). Base main `09b4cba`.

## Defects found and fixed

| Defect | Reproduction on the source | Fix |
| --- | --- | --- |
| A command name glued to a path is read as "command + argument" | `net/http`, `id/5`, `ip/24`, `top/rated`, `type/json` flagged | The argument needs whitespace (or `$IFS`/`+`) after the command |
| Commands that are English words after `;` or a line break | `Thanks\nfind me…`, `Hello; more details later`, lorem ipsum `\nSed ut…`, `Done; set the meeting…` flagged | Two lists: program names (`whoami`, `wget`, `id`…) match after a separator alone; words (`find`, `more`, `set`, `head`…) need a shell argument: option `-x`, path `/x` or `\x`, URL, substitution, a number for `sleep`/`ping` |
| Redirection taken as an argument of a word | `a < b; top > bottom` flagged | `<`/`>` count only after a program name |

The 14 benign strings above were all flagged by the source (red run kept in
this PR's description); the repaired detector flags none of them.

## Wiring

`detect_cmdi` is appended as operator code **19** (codes 0–18 unchanged), no
`value`, transforms/negation through the existing evaluator path, semantic cost
10. No shipped rule uses it; test-only rule 800818 lives in
`engine/compiler/examples/cmdi-test.yaml`. A libstrata built before this change
rejects bundles that use the operator: upgrade the module first (same rule as
`detect_ssti`, `docs/design/control-file.md`).

## Tests

- `engine/src/detectors/injection/cmdi.rs`: attacks, benign, prose/paths,
  nested/escaped commands, long tokens, 64 KiB adversarial inputs under a
  time bound.
- `engine/compiler/tests/cmdi.rs`: IR → signed bundle → engine; enforce blocks,
  shadow logs, schema rejects a `value`, opcodes 0–18 stable, cost 81, negation
  on a missing target, and the repository corpus: **0 of 3,000 benign
  requests** (`corpus/benign/synthetic.jsonl`, `pilot.jsonl`) and **930 of 958**
  command-injection requests (479 payloads in a query and in a form) blocked.
  The misses are payloads with a literal backslash-n (`;id\n`), which a shell
  reads as the letter n, and one PHP call (`;system('id')`).
- `connectors/nginx/t/042-cmdi.t`: the same rule through NGINX (query, form
  body, shadow, double encoding, benign prose and paths).

Gate results are in the PR description. This is a lexical detector, not a
shell parser, and not an FP campaign on real traffic: run a rule using it in
shadow first.
