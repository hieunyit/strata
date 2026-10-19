#!/bin/sh
# Fresh systemd node only. Inputs, including local packages, must be trusted by
# the operator. No key download, enrollment, mode migration or unsigned fallback.
set -eu
umask 077
die() { echo "strata-standalone-install: $*" >&2; exit 1; }
pkgs="" bundle="" key="" policy="" listen="" upstream="" nginx_ver=""
while [ $# -gt 0 ]; do
    [ $# -ge 2 ] || die "every option requires a value"
    case "$1" in
        --packages) pkgs=$2 ;; --bundle) bundle=$2 ;; --pubkey) key=$2 ;;
        --policy) policy=$2 ;; --listen) listen=$2 ;; --upstream) upstream=$2 ;;
        --nginx) nginx_ver=$2 ;; *) die "unknown option $1" ;;
    esac
    shift 2
done
[ "$(id -u)" = 0 ] || die "run as root"
[ -d /run/systemd/system ] || die "systemd is required"
for input in "$pkgs" "$bundle" "$key"; do [ -e "$input" ] || die "local packages, bundle and public key are required"; done
[ -d "$pkgs" ] || die "packages must be a local directory"
[ -f "$bundle" ] || die "bundle must be a regular file"
[ -f "$key" ] || die "key must be a regular file"
pkgs=$(CDPATH="" cd -- "$pkgs" && pwd)
LC_ALL=C; export LC_ALL
case "$policy" in ''|*[!a-z0-9._-]*) die "invalid policy name" ;; esac
[ "${#policy}" -le 55 ] || die "policy name exceeds 55 bytes"
# Deliberately support a small config-safe address grammar, with no URI suffix,
# variables, IPv6, DNS resolution in listen, or NGINX directives from input.
case "$listen$upstream" in *[!a-zA-Z0-9.:-]*) die "invalid address characters" ;; esac
printf '%s\n' "$listen" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]{1,5}$' || die "listen must be IPv4:port"
printf '%s\n' "$upstream" | grep -Eq '^[a-zA-Z0-9][a-zA-Z0-9.-]*:[0-9]{1,5}$' || die "upstream must be host:port"
for address in "$listen" "$upstream"; do
    port=${address##*:}; [ "$port" -gt 0 ] || die "invalid port"
    [ "$port" -le 65535 ] || die "invalid port"
done
if [ -n "$nginx_ver" ]; then
    case "$nginx_ver" in *[!0-9.]*) die "invalid NGINX version" ;; esac
    printf '%s\n' "$nginx_ver" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || die "invalid NGINX version"
fi
# Check state before package hooks can restart an existing node.
exec 9>/run/lock/strata-standalone-install.lock
flock -n 9 || die "another standalone installation is running"
[ ! -e /var/lib/strata/identity/node-id ] || die "Fleet identity exists; explicit migration is required"
[ ! -e /var/lib/strata/bundles/control ] || die "active bundle exists; use the documented update procedure"
[ ! -e /etc/strata/bundle.pub ] || die "bundle key already configured"
if systemctl is-active -q nginx; then die "active NGINX requires manual review before installation"; fi
for unit in strata-agent.service strata-agent.socket strata-agent-standalone.service strata-agent-standalone.socket; do
    if systemctl is-active -q "$unit" || systemctl is-enabled -q "$unit" 2>/dev/null; then
        die "existing active/enabled $unit; explicit migration is required"
    fi
done
if [ -d /etc/nginx ] && grep -RIEq '^[[:space:]]*(strata[[:space:]_]|load_module.*ngx_http_strata)' /etc/nginx; then
    die "existing Strata configuration requires manual review"
fi
script_dir=$(CDPATH="" cd -- "$(dirname -- "$0")" && pwd)
[ -f "$script_dir/install.sh" ] || die "install.sh must accompany this script"
work=$(mktemp -d /var/tmp/strata-standalone.XXXXXX)
pid="" configured=false started=false complete=false
cleanup() {
    rc=$?
    trap - EXIT HUP INT TERM
    if [ -n "$pid" ]; then kill "$pid" 2>/dev/null || :; wait "$pid" 2>/dev/null || :; fi
    if [ "$complete" = false ]; then
        if [ "$started" = true ]; then
            systemctl disable --now strata-agent-standalone.service strata-agent-standalone.socket || rc=1
        fi
        if [ "$configured" = true ]; then
            cp -p "$work/nginx.original" /etc/nginx/nginx.conf
            rm -f /etc/nginx/conf.d/strata-standalone.conf
        fi
        echo "strata-standalone-install: installation incomplete; packages and diagnostic bundle state may remain" >&2
    fi
    rm -rf "$work"
    exit "$rc"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
# Snapshot inputs before verification. This bounds copies and isolates the
# preflight control, socket and engine from all live node paths.
[ "$(stat -Lc %s -- "$bundle")" -le 268435456 ] || die "bundle exceeds 256 MiB"
case "$(stat -Lc %s -- "$key")" in 32|64) ;; *) die "public key must contain 32 or 64 raw bytes" ;; esac
head -c 268435457 -- "$bundle" > "$work/source.sbn"
[ "$(stat -c %s "$work/source.sbn")" -le 268435456 ] || die "bundle exceeds 256 MiB"
head -c 65 -- "$key" > "$work/bundle.pub"
case "$(stat -c %s "$work/bundle.pub")" in 32|64) ;; *) die "public key changed while copying" ;; esac
set -- --packages "$pkgs" --packages-only
[ -z "$nginx_ver" ] || set -- "$@" --nginx "$nginx_ver"
sh "$script_dir/install.sh" "$@"
# A distribution package may start the stock welcome server. It was not active
# at entry; stop it so the final start actually checks binding the new route.
systemctl stop nginx
strata-agent verify-bundle --bundle-file="$work/source.sbn" --bundle-pubkey="$work/bundle.pub" --policy="$policy" --require-enforce
strata-agent run --standalone --bundle-file="$work/source.sbn" --bundle-pubkey="$work/bundle.pub" \
    --required-policy="$policy" --require-full-enforce --bundle-dir="$work/bundles" \
    --control-file="$work/control" --event-socket="$work/events.sock" \
    --events-jsonl="$work/events.jsonl" --metrics-file= --metrics-addr= >"$work/agent.log" 2>&1 &
pid=$!
digest=$(sha256sum "$work/source.sbn" | cut -d ' ' -f 1)
expected=".strata-$digest.sbn"
# A nonempty control page can still have an odd generation or an unpublished
# filename. Wait for this exact immutable bundle and a stable seqlock snapshot.
control_ready() {
    ctl=$1; dir=$2
    [ -f "$ctl" ] || return 1
    gen=$(od -An -tu8 -j16 -N8 "$ctl" | tr -d ' ')
    [ -n "$gen" ] || return 1
    [ "$gen" -gt 0 ] || return 1
    [ $((gen % 2)) = 0 ] || return 1
    [ "$(dd if="$ctl" bs=1 skip=66 count=76 2>/dev/null)" = "$expected" ] || return 1
    active_sum=$(sha256sum "$dir/$expected" 2>/dev/null) || return 1
    [ "${active_sum%% *}" = "$digest" ] || return 1
    [ "$gen" = "$(od -An -tu8 -j16 -N8 "$ctl" | tr -d ' ')" ]
}
i=0
while ! control_ready "$work/control" "$work/bundles"; do
    kill -0 "$pid" 2>/dev/null || { cat "$work/agent.log" >&2; die "bundle preflight failed"; }
    i=$((i+1)); [ "$i" -lt 100 ] || die "bundle preflight timed out"
    sleep .1
done
kill "$pid"; wait "$pid"; pid=
module=/usr/lib/nginx/modules/ngx_http_strata_module.so
[ -f "$module" ] || module=/usr/lib64/nginx/modules/ngx_http_strata_module.so
cat > "$work/nginx.conf" <<CONF
load_module $module;
pid $work/nginx.pid;
error_log stderr;
events {}
http {
 access_log off;
 strata_control_file $work/control;
 strata_bundle_dir $work/bundles;
 strata_bundle_pubkey $work/bundle.pub;
 server { listen $listen; strata on; strata_policy $policy; }
}
CONF
nginx -t -q -p "$work/" -c "$work/nginx.conf" || die "native module rejected bundle/config"
# Only now publish the source and create the dedicated inspected route. The
# defaults for CPU budget, fail mode and body handling remain the module defaults.
install -d -o root -g strata -m 0750 /var/lib/strata/standalone
install -o root -g strata -m 0640 "$work/source.sbn" /var/lib/strata/standalone/source.sbn
install -o root -g strata -m 0640 "$work/bundle.pub" /etc/strata/bundle.pub
cat > "$work/standalone.env" <<CONF
STRATA_BUNDLE_SOURCE=--bundle-file=/var/lib/strata/standalone/source.sbn
STRATA_EVENTS_JSONL=/var/log/strata/events.jsonl
STRATA_SYSLOG_ADDR=
STRATA_METRICS_ADDR=127.0.0.1:9469
STRATA_NODE_ID=standalone
STRATA_REQUIRED_POLICY=$policy
STRATA_REQUIRE_FULL_ENFORCE=true
CONF
install -o root -g strata -m 0640 "$work/standalone.env" /etc/strata/standalone.env
started=true
systemctl enable --now strata-agent-standalone.socket strata-agent-standalone.service
i=0
while ! control_ready /var/lib/strata/bundles/control /var/lib/strata/bundles; do
    systemctl is-active -q strata-agent-standalone.service || die "standalone service failed"
    i=$((i+1)); [ "$i" -lt 100 ] || die "live bundle publication timed out"
    sleep .1
done
cp -p /etc/nginx/nginx.conf "$work/nginx.original"
configured=true
{ printf 'load_module %s;\n' "$module"; cat "$work/nginx.original"; } > /etc/nginx/nginx.conf
cat > /etc/nginx/conf.d/strata-standalone.conf <<CONF
strata_control_file /var/lib/strata/bundles/control;
strata_bundle_dir /var/lib/strata/bundles;
strata_bundle_pubkey /etc/strata/bundle.pub;
strata_event_socket unix:/run/strata/events.sock;
strata_metrics_file /run/strata/metrics;
strata_node_id standalone;
server {
 listen $listen;
 server_name api.example.test;
 location / {
  strata on;
  strata_policy $policy;
  proxy_pass http://$upstream;
 }
}
CONF
chmod 0644 /etc/nginx/conf.d/strata-standalone.conf
nginx -T -q > "$work/expanded.conf" || die "live NGINX configuration failed"
grep -Fq "# configuration file /etc/nginx/conf.d/strata-standalone.conf:" "$work/expanded.conf" || die "nginx.conf does not include the managed route"
systemctl enable nginx
systemctl start nginx
complete=true
echo "strata-standalone-install: ready on $listen, policy $policy; verify benign and attack traffic on this route"
