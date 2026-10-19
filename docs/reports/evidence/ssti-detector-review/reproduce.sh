#!/bin/sh
# Diagnostic comparison; run from the reviewed repo, with its dev image available.
set -eu
repo=$(git rev-parse --show-toplevel)
mkdir -p "$repo/build"
work=$(mktemp -d "$repo/build/ssti-review.XXXXXX")
trap 'rm -rf "$work"' EXIT
source_sha=25e959e1b8f2d5a0fd6858033e0ab06889171b9a
git show "$source_sha:engine/src/detectors/injection/ssti.rs" > "$work/source-ssti.rs"
printf '%s  %s\n' c614246c5e75b254cec807552ef1f8f4064db0e85c4a215826d1892b3c89b4b2 "$work/source-ssti.rs" | sha256sum -c -
cp "$repo/docs/reports/evidence/ssti-detector-review/probe.rs" "$work/probe.rs"
rel=${work#"$repo/"}
"$repo/deploy/dev/run.sh" rustc --edition=2024 -D warnings -O "$rel/probe.rs" -o "$rel/probe"
set +e
"$repo/deploy/dev/run.sh" "$rel/probe" --expect-source-fixed
status=$?
set -e
[ "$status" = 101 ] || { echo "FAIL: expected source assertion exit 101, got $status" >&2; exit 1; }
"$repo/deploy/dev/run.sh" "$rel/probe"
