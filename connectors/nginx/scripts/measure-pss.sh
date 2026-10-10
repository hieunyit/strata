#!/usr/bin/env bash
# W05-R-01: memory of N NGINX workers sharing one bundle (with a large
# Hyperscan section) through the master's read-only MAP_SHARED mapping.
# Usage: measure-pss.sh <nginx-version> [workers] [rules]   (in the dev image)
set -euo pipefail
version="${1:?usage: measure-pss.sh <nginx-version> [workers] [rules]}"
workers="${2:-32}"
nrules="${3:-6000}"
root="$(cd "$(dirname "$0")/../../.." && pwd)"
bin="$root/target/release"
objs="$root/build/nginx-$version/objs"
fx="$root/connectors/nginx/t/fixtures"
work="$(mktemp -d)"
trap 'kill -QUIT "$(cat "$work"/logs/nginx.pid 2>/dev/null)" 2>/dev/null || true; sleep 1; rm -rf "$work"' EXIT
mkdir -p "$work/conf" "$work/logs" "$work/bundles"

# synthetic CRS-like rules (same shapes as the Hyperscan PoC)
perl -e '
  my @w = qw(select union insert update delete script iframe onerror onload eval exec system passwd
             shadow cmd powershell wget curl base64 document cookie window location alert prompt
             concat char sleep benchmark waitfor xp_cmdshell information_schema);
  my $s = 0x9e3779b9; sub r { $s = ($s * 1103515245 + 12345) & 0x7fffffff; $s }
  my $n = shift; my @r;
  for my $i (0 .. $n - 1) {
    my ($a, $b) = ($w[r() % @w], $w[r() % @w]);
    my @p = ("(?i)$a\\\\s+$b\\\\s*\\\\(\\\\s*$i", "(?i)<\\\\s*$a" . "[^>]{0,40}$b$i",
             "$a" . "[0-9a-f]{4,16}$b" . "_$i", "(?i)($a|$b)[=:]\\\\s*[\x27\\\"][^\x27\\\"]{1,32}$i",
             "rule-" . sprintf("%05d", $i) . "-$a", "(?s)$a.{0,64}$b.{0,8}#$i");
    push @r, sprintf(q({"id":%d,"name":"synthetic %d","layer":"managed","stage":"request_headers","score":1,"severity":"notice","match":{"all":[{"targets":[{"var":"args"},{"var":"request_headers","key":"User-Agent"}],"transforms":["url_decode_uni","lowercase"],"operator":{"type":"rx","value":"%s"}}]},"metadata":{"source":"organization","license":"Apache-2.0"}}), 800000 + $i, $i, $p[$i % 6]);
  }
  print "{\"ir_version\":1,\"ruleset\":{\"name\":\"pss\",\"version\":\"1\"},\"rules\":[" . join(",", @r) . "]}\n";
' "$nrules" > "$work/rules.json"
printf 'policies: [{ name: example-api, mode: shadow }]\n' > "$work/policies.yaml"

t0=$(date +%s.%N)
"$bin/strata-compile" --rules "$work/rules.json" --policies "$work/policies.yaml" \
    --key "$fx/test.key" --version 1 --out "$work/bundles/bundle-1.sbn"
t1=$(date +%s.%N)
"$bin/strata-compile" --policies "$work/policies.yaml" --key "$fx/test.key" --version 1 \
    --out "$work/bundles/empty-1.sbn" 2>/dev/null
echo "compile: $(awk -v a="$t0" -v b="$t1" 'BEGIN { printf "%.1f", b - a }') s, bundle $(stat -c %s "$work/bundles/bundle-1.sbn") bytes"

port=$((20000 + RANDOM % 20000))

measure() {   # $1 bundle file name
    "$bin/mkbundle" control --out "$work/control" --generation 2 --version 1 --name "$1"
    cat > "$work/conf/nginx.conf" <<CONF
load_module $objs/ngx_http_strata_module.so;
worker_processes $workers;
pid logs/nginx.pid;
error_log logs/error.log notice;
events { worker_connections 256; }
thread_pool default threads=1;
http {
    access_log off;
    strata_control_file  $work/control;
    strata_bundle_dir    $work/bundles;
    strata_bundle_pubkey $fx/bundle.pub;
    server {
        listen 127.0.0.1:$port reuseport;
        location /t { strata on; proxy_pass http://127.0.0.1:$port/backend/; }
        location /backend/ { strata off; return 200 "ok"; }
    }
}
CONF
    "$objs/nginx" -p "$work/" -c conf/nginx.conf
    sleep 2
    # enough connections that every worker scans (reuseport spreads them)
    seq 1 4000 | xargs -P 32 -I{} curl -s -o /dev/null -A "probe {}" \
        "http://127.0.0.1:$port/t?q=select+union+{}&x=%3Cscript%3E" || true
    master=$(cat "$work/logs/nginx.pid")
    pids="$master $(ps -o pid= --ppid "$master" | tr '\n' ' ')"
    local n=0 rss=0 pss=0 tpss=0 priv=0
    for p in $pids; do
        read -r r s < <(awk -v f="$1" '
            /^[0-9a-f]+-[0-9a-f]+ / { on = index($0, f) > 0; next }
            on && /^Rss:/ { r += $2 } on && /^Pss:/ { s += $2 }
            END { print r + 0, s + 0 }' "/proc/$p/smaps")
        read -r tp pd < <(awk '/^Pss:/ { p = $2 } /^Private_Dirty:/ { d = $2 } END { print p, d }' "/proc/$p/smaps_rollup")
        n=$((n + 1)); rss=$((rss + r)); pss=$((pss + s)); tpss=$((tpss + tp)); priv=$((priv + pd))
    done
    echo "$1: processes=$n bundle_rss_kb/worker=$((rss / n)) bundle_pss_kb_total=$pss total_pss_kb=$tpss private_dirty_kb/process=$((priv / n))"
    grep -c "strata: " "$work/logs/error.log" >/dev/null || true
    kill -QUIT "$master"; sleep 2
}

measure bundle-1.sbn
measure empty-1.sbn
