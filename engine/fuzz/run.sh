#!/usr/bin/env bash
# Builds the fuzz targets with coverage instrumentation (stable rustc:
# sancov passes + libFuzzer from libfuzzer-sys, no nightly needed) and runs
# them in parallel for the given time. Crashes land in build/fuzz/<target>/.
# Usage: engine/fuzz/run.sh <seconds> [targets...]   (in the dev image)
set -euo pipefail
secs="${1:?usage: run.sh <seconds> [targets...]}"; shift
root="$(cd "$(dirname "$0")/../.." && pwd)"
targets=("$@")
[ ${#targets[@]} -gt 0 ] || targets=(sqli xss guard_chunks response_tx bodies body_eval event_encode budget_eval)
out="$root/build/fuzz"
mkdir -p "$out"

export RUSTFLAGS="--cfg fuzzing -Cpasses=sancov-module \
 -Cllvm-args=-sanitizer-coverage-level=4 -Cllvm-args=-sanitizer-coverage-inline-8bit-counters \
 -Cllvm-args=-sanitizer-coverage-pc-table -Cllvm-args=-sanitizer-coverage-trace-compares \
 -Cdebug-assertions -Coverflow-checks"
export CARGO_TARGET_DIR="$root/target/fuzz"
# an explicit --target keeps RUSTFLAGS off build scripts (as cargo-fuzz does)
triple="$(rustc -vV | sed -n 's/^host: //p')"
cargo build --release --target "$triple" --manifest-path "$root/engine/fuzz/Cargo.toml" \
    "${targets[@]/#/--bin=}"
bin="$CARGO_TARGET_DIR/$triple/release"

for t in "${targets[@]}"; do
    mkdir -p "$out/$t/corpus" "$out/$t/artifacts"
    # seeds: libinjection's samples and test inputs for the detectors
    if [ "$t" = sqli ] || [ "$t" = xss ]; then
        for f in "$root"/engine/tests/libinjection/test-*.txt; do
            cp "$f" "$out/$t/corpus/" 2>/dev/null || true
        done
    fi
    # seeds for the body parsers: one body of each format
    if [ "$t" = bodies ] || [ "$t" = body_eval ] || [ "$t" = budget_eval ]; then
        printf '\001B--B\r\nContent-Disposition: form-data; name="f"; filename="a.php"\r\n\r\nx\r\n--B--' > "$out/$t/corpus/multipart"
        printf '\001\000{"a": [1, {"b": "x\\u0041"}], "c": null}' > "$out/$t/corpus/json"
        printf '\002\000<?xml version="1.0"?><!DOCTYPE r [<!ENTITY e "x">]><r a="&lt;b&gt;"><![CDATA[c]]>t&#65;</r>' > "$out/$t/corpus/xml"
    fi
    "$bin/$t" "$out/$t/corpus" \
        -artifact_prefix="$out/$t/artifacts/" -max_total_time="$secs" \
        -max_len=16384 -rss_limit_mb=2048 -print_final_stats=1 \
        > "$out/$t.log" 2>&1 &
done
fail=0
for job in $(jobs -p); do
    wait "$job" || fail=1
done
for t in "${targets[@]}"; do
    echo "== $t: $(grep -E '^stat::number_of_executed_units' "$out/$t.log" | awk '{print $2}') runs," \
         "$(ls "$out/$t/corpus" | wc -l) corpus files, $(ls "$out/$t/artifacts" | wc -l) crashes"
done
exit $fail
