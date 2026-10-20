#!/usr/bin/env bash
# Inside the dev image (deploy/compact/build.sh): binaries, rules, corpus
# into build/compact/dist with the runtime Dockerfile.
set -euo pipefail
version=$1 commit=$2
cd "$(dirname "$0")/../.."
out=build/compact
dist=$out/dist
# the lab build's target directory: same features, so its cache is reused
export CARGO_TARGET_DIR=$PWD/build/lab/target
rm -rf "$dist" && mkdir -p "$dist/bin" "$dist/rules"

# strata-eval: the rule pack release runs every rule's tests
cargo build --release -p strata-compiler -p strata-replay -p strata-eval
cp "$CARGO_TARGET_DIR/release/strata-compile" "$CARGO_TARGET_DIR/release/strata-replay" "$dist/bin/"

# the core rule pack as rule IR the control plane compiles into every
# bundle; the package's own bundle is signed with a throwaway key and dropped
key=$(mktemp)
trap 'rm -f "$key"' EXIT
head -c 32 /dev/urandom > "$key"
rm -rf "$out/rules-pkg"
(cd tools/strata-rules && PATH="$CARGO_TARGET_DIR/release:$PATH" go run . release --repo ../.. --pack core --version "compact-$version" \
    --key "$key" --out "../../$out/rules-pkg")
irs=("$out"/rules-pkg/*.rules.json)
[ "${#irs[@]}" = 1 ] && [ -f "${irs[0]}" ] || { echo "build: want one rule IR (*.rules.json) from the core pack" >&2; ls "$out/rules-pkg" >&2; exit 1; }
cp "${irs[0]}" "$dist/rules/core.rules.json"
cp "$out/rules-pkg/NOTICE" "$dist/rules/NOTICE" # licenses of the imported rules (CRS: Apache-2.0)

# the benign and attack corpus, replayed with every draft (W13-G2-01)
count=$("$CARGO_TARGET_DIR/release/strata-replay" gen --out "$out/corpus-count.parquet" --count 1 --corpus corpus 2>&1 |
    sed -n 's/.* from \([0-9]*\) corpus requests.*/\1/p')
"$CARGO_TARGET_DIR/release/strata-replay" gen --out "$dist/replay-corpus.parquet" --count "$count" --corpus corpus

# the control plane with the Web UI built in (CP-A08)
[ -f ui/dist/index.html ] || { echo "build: ui/dist missing" >&2; exit 1; }
find control-plane/webui/dist -mindepth 1 ! -name .gitkeep -delete
cp -R ui/dist/. control-plane/webui/dist/
(cd control-plane && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$version -X main.commit=$commit" \
    -o "../$dist/bin/strata-control-plane" ./cmd/server)
find control-plane/webui/dist -mindepth 1 ! -name .gitkeep -delete

cp deploy/lab/block.html deploy/compact/Dockerfile "$dist/"
ls -l "$dist" "$dist/bin" "$dist/rules"
