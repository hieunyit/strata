#!/usr/bin/env bash
# Builds everything the lab runs into build/lab, inside the dev image:
#   deploy/dev/run.sh deploy/lab/build.sh
# libstrata is built without test hooks, in its own target directory so
# that the test builds in target/ are left alone.
set -euo pipefail
cd "$(dirname "$0")/../.."
out=build/lab
versions=(${NGINX_VERSIONS:-1.30.5 1.31.6})
export CARGO_TARGET_DIR=$PWD/$out/target

# Two invocations, like the Makefile: built together, cargo would unify
# features and libstrata.a would pull the full (non-PIC) Hyperscan compiler
# that strata-compile needs instead of the runtime.
cargo build --release -p libstrata-ffi
cargo build --release -p mkbundle -p strata-compiler -p strata-replay
for v in "${versions[@]}"; do
    STRATA_LIB=$CARGO_TARGET_DIR/release/libstrata.a connectors/nginx/scripts/build.sh "$v" "$out"
done

dist=$out/dist
rm -rf "$dist" && mkdir -p "$dist/bin"
for v in "${versions[@]}"; do
    mkdir -p "$dist/nginx/$v"
    cp "$out/nginx-$v/objs/nginx" "$out/nginx-$v/objs/ngx_http_strata_module.so" \
        "$out/nginx-$v/conf/mime.types" "$dist/nginx/$v/"
done
cp "$CARGO_TARGET_DIR/release/mkbundle" "$CARGO_TARGET_DIR/release/strata-compile" "$CARGO_TARGET_DIR/release/strata-replay" "$dist/bin/"
# the whole benign and attack corpus once, replayed with every draft
# (W13-G2-01): gen takes the corpus in order, so count = its size
n=$("$CARGO_TARGET_DIR/release/strata-replay" gen --out "$out/corpus-count.parquet" --count 1 --corpus corpus 2>&1 |
    sed -n 's/.* from \([0-9]*\) corpus requests.*/\1/p')
"$CARGO_TARGET_DIR/release/strata-replay" gen --out "$dist/replay-corpus.parquet" --count "$n" --corpus corpus
(cd agent && CGO_ENABLED=0 go build -trimpath -o "../$dist/bin/" ./cmd/strata-agent ./cmd/strata-emit)
# the Web UI built into the control plane (CP-A08) when ui/dist was built
# (build/ui.sh npm run build); otherwise the lab's ui container serves it
if [ -f ui/dist/index.html ]; then
    find control-plane/webui/dist -mindepth 1 ! -name .gitkeep -delete
    cp -R ui/dist/. control-plane/webui/dist/
fi
(cd control-plane && CGO_ENABLED=0 go build -trimpath -o "../$dist/bin/strata-control-plane" ./cmd/server)
cp engine/compiler/examples/rules.yaml deploy/lab/policies.yaml deploy/lab/block.html deploy/lab/init.sh deploy/lab/fleet-init.sh deploy/lab/install-bundle.sh "$dist/"
cp deploy/lab/runtime.Dockerfile "$dist/Dockerfile"
ls -l "$dist" "$dist/bin"
