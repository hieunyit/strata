#!/usr/bin/env bash
# Differential check of the Rust port against the original libinjection C
# library (v3.10.0, pinned by sha256) on its sample corpora and on any
# extra files given (e.g. a fuzz corpus). Prints the number of inputs and
# every input where the two disagree; exits 1 on any difference.
# Usage: engine/tools/libinjection/diff.sh <build-dir> [extra input files...]
set -euo pipefail
build="${1:?usage: diff.sh <build-dir> [files...]}"; shift
root="$(cd "$(dirname "$0")/../../.." && pwd)"
version=3.10.0
sha=9dd7ae68a21a3c50f705c383b1b714c77fd4093b0a561a5400f0cb0ad79b1ae7
tarball="$build/dl/libinjection-$version.tar.gz"
src="$build/libinjection-$version"

mkdir -p "$build/dl"
[ -f "$tarball" ] || curl -fsSL -o "$tarball" \
    "https://github.com/client9/libinjection/archive/refs/tags/v$version.tar.gz"
echo "$sha  $tarball" | sha256sum -c --quiet
if [ ! -d "$src" ]; then
    mkdir -p "$src"
    tar -xzf "$tarball" -C "$src" --strip-components=1
fi

cc -O1 -I"$src/src" -o "$build/libinjection-ref" "$root/engine/tools/libinjection/ref.c" \
    "$src/src/libinjection_sqli.c" "$src/src/libinjection_xss.c" "$src/src/libinjection_html5.c"
cargo build --release -q -p libstrata --example injection-cli
rust="$root/target/release/examples/injection-cli"

# every line of the sample corpora and of the extra files
corpus="$build/libinjection-corpus.txt"
cat "$src"/data/*.txt "$@" > "$corpus"
"$build/libinjection-ref" < "$corpus" > "$build/libinjection-c.out"
"$rust" < "$corpus" > "$build/libinjection-rust.out"

total=$(wc -l < "$corpus")
sqli=$(grep -vc '^- ' "$build/libinjection-c.out" || true)
xss=$(grep -c ' 1$' "$build/libinjection-c.out" || true)
echo "inputs: $total (C: $sqli SQLi, $xss XSS)"
if cmp -s "$build/libinjection-c.out" "$build/libinjection-rust.out"; then
    echo "identical results"
else
    paste -d '\t' "$build/libinjection-c.out" "$build/libinjection-rust.out" "$corpus" \
        | awk -F '\t' '$1 != $2 { n++; if (n <= 50) print "C=" $1 " RUST=" $2 " INPUT=" $3 }
                       END { print n " differences"; exit n > 0 }'
fi
