#!/usr/bin/env bash
# Nightly jobs on the lab machine, while GitHub Actions has no minutes
# (W09-S-02 asks for a nightly run; .github/workflows/nightly.yml is the CI
# version of the same job). Runs `make mutate` on origin/main, in a worktree
# of its own (build/nightly/src), so the working tree of the repository is
# never touched. Each run keeps build/nightly/<UTC date>/: the report, the
# summary and the log; history.tsv gets one line per run (bypass rate), and
# the 14 latest runs are kept.
#
# Usage: deploy/nightly/nightly.sh            (cron: install-cron.sh)
# NIGHTLY_CPUS: the CPUs the dev container may use (default 0-5).
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
base="$root/build/nightly"
src="$base/src"
day="$(date -u +%Y-%m-%d)"
out="$base/$day"
mkdir -p "$out"
exec > >(tee "$out/nightly.log") 2>&1
echo "nightly: $(date -u +%FT%TZ) start"

git -C "$root" fetch -q origin
if [ ! -d "$src/.git" ] && [ ! -f "$src/.git" ]; then
    git -C "$root" worktree add -q --detach "$src" origin/main
else
    git -C "$src" checkout -q --detach origin/main
    git -C "$src" reset -q --hard origin/main
    git -C "$src" clean -qfd -e build/
fi
commit=$(git -C "$src" rev-parse --short HEAD)
echo "nightly: origin/main $commit"

rc=0
# made here, as this user: docker would make the mount points as root
mkdir -p "$src/build/go" "$root/build/go" "$root/build/cargo-registry"
# the module and crate caches of the main tree, so a night downloads nothing
STRATA_DEV_DOCKER_ARGS="--cpuset-cpus=${NIGHTLY_CPUS:-0-5} -v $root/build/go:/src/build/go -v $root/build/cargo-registry:/usr/local/cargo/registry" \
    "$src/deploy/dev/run.sh" make mutate </dev/null || rc=$?
cp "$src/docs/mutation-report.md" "$out/" 2>/dev/null || true
cp "$src/build/mutate/summary.json" "$out/" 2>/dev/null || true

# one line: date, commit, exit code, variants tested, bypassed, rate
line=$(python3 - "$out/summary.json" <<'PY' 2>/dev/null || echo "- - -"
import json, sys
s = json.load(open(sys.argv[1]))
t = s["total"]
v, b = t["tested"], t["bypassed"]
print(v, b, f"{100 * b / v:.1f}%" if v else "-")
PY
)
printf '%s\t%s\t%s\t%s\n' "$day" "$commit" "$rc" "$(tr ' ' '\t' <<<"$line")" >> "$base/history.tsv"
# keep the 14 latest runs
find "$base" -mindepth 1 -maxdepth 1 -type d -name '20*' | sort | head -n -14 | xargs -r rm -rf
echo "nightly: $(date -u +%FT%TZ) done, rc=$rc ($line)"
exit "$rc"
