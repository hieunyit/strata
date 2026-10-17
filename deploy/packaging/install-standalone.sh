#!/bin/sh
# Strata Standalone Installer (RV-G1-01): One command deployment for edge gateways
# and small clusters with zero external dependencies (no control plane, no ClickHouse, no Postgres).
#
# Usage:
#   sh install-standalone.sh --packages <dir|URL> [--nginx <version>]
#                           [--bundle <file|URL>] [--bundle-pubkey <file>]
#                           [--events-jsonl <file>] [--syslog <addr>]
#                           [--metrics-addr <addr>]
#
set -eu

die() { echo "strata-install-standalone: $*" >&2; exit 1; }
say() { echo "strata-install-standalone: $*"; }

pkgs="" nginx_ver="" bundle="" bundle_pubkey=""
events_jsonl="/var/log/strata/events.jsonl"
syslog_addr=""
metrics_addr="127.0.0.1:9469"

while [ $# -gt 0 ]; do
    case "$1" in
        --packages) pkgs=${2:?}; shift 2 ;;
        --nginx) nginx_ver=${2:?}; shift 2 ;;
        --bundle) bundle=${2:?}; shift 2 ;;
        --bundle-pubkey) bundle_pubkey=${2:?}; shift 2 ;;
        --events-jsonl) events_jsonl=${2:?}; shift 2 ;;
        --syslog) syslog_addr=${2:?}; shift 2 ;;
        --metrics-addr) metrics_addr=${2:?}; shift 2 ;;
        *) die "unknown argument $1" ;;
    esac
done

[ -n "$pkgs" ] || die "usage: install-standalone.sh --packages <dir|URL> [--bundle <file|URL>] [--events-jsonl <file>]"
[ "$(id -u)" = 0 ] || die "run as root"
case "$nginx_ver" in ''|[0-9]*.[0-9]*.[0-9]*) ;; *) die "bad NGINX version $nginx_ver" ;; esac

. /etc/os-release
case "$ID ${ID_LIKE:-}" in
    *debian*|*ubuntu*) fam=deb ;;
    *rhel*|*fedora*|*centos*|*rocky*|*almalinux*) fam=rpm ;;
    *) die "unsupported system $ID" ;;
esac

# --- packages download / verification ---------------------------------------
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
case "$pkgs" in
    http://*|https://*)
        command -v curl >/dev/null || die "curl is needed to download $pkgs"
        curl -fsSL "${pkgs%/}/SHA256SUMS" -o "$work/SHA256SUMS" || die "no SHA256SUMS at $pkgs"
        fetch() {
            curl -fsSL "${pkgs%/}/$1" -o "$work/$1" || die "download $1"
            (cd "$work" && grep " \./$1\$" SHA256SUMS | sha256sum -c --quiet -) || die "$1: checksum mismatch"
        }
        list() { sed -n 's|.* \./||p' "$work/SHA256SUMS"; }
        dir=$work ;;
    *)
        [ -d "$pkgs" ] || die "no directory $pkgs"
        fetch() { :; }
        list() { ls "$pkgs"; }
        dir=$(cd "$pkgs" && pwd) ;;
esac

if [ $fam = deb ]; then
    agent_pkg=$(list | grep '^strata-agent_.*_amd64\.deb$' | sort -V | tail -1)
    modules=$(list | sed -n 's/^nginx-module-strata_\([0-9.]*\)+.*_amd64\.deb$/\1/p' | sort -uV)
else
    agent_pkg=$(list | grep '^strata-agent-.*\.x86_64\.rpm$' | sort -V | tail -1)
    modules=$(list | sed -n 's/^nginx-module-strata-\([0-9.]*\)+.*\.x86_64\.rpm$/\1/p' | sort -uV)
fi
[ -n "$agent_pkg" ] || die "no strata-agent $fam package in $pkgs"
[ -n "$modules" ] || die "no nginx-module-strata $fam package in $pkgs"

# --- NGINX install / check --------------------------------------------------
installed=""
if command -v nginx >/dev/null; then
    installed=$(nginx -v 2>&1 | sed -n 's|.*nginx/\([0-9.]*\).*|\1|p')
fi
if [ -n "$installed" ]; then
    [ -z "$nginx_ver" ] || [ "$nginx_ver" = "$installed" ] \
        || die "NGINX $installed is installed, not $nginx_ver: upgrade NGINX first"
    nginx_ver=$installed
fi
[ -n "$nginx_ver" ] || nginx_ver=$(echo "$modules" | tail -1)
echo "$modules" | grep -qx "$nginx_ver" \
    || die "no Strata module built for NGINX $nginx_ver (built for: $(echo $modules))"

if [ -z "$installed" ]; then
    minor=$(echo "$nginx_ver" | cut -d. -f2)
    branch=""; [ $((minor % 2)) = 1 ] && branch=mainline/
    say "installing NGINX $nginx_ver from nginx.org"
    if [ $fam = deb ]; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y -qq curl gnupg ca-certificates >/dev/null
        curl -fsSL https://nginx.org/keys/nginx_signing.key | gpg --dearmor > /usr/share/keyrings/nginx-archive-keyring.gpg
        echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] http://nginx.org/packages/${branch}$ID $VERSION_CODENAME nginx" \
            > /etc/apt/sources.list.d/nginx.list
        apt-get update -qq
        full=$(apt-cache madison nginx | awk -v v="$nginx_ver" '$3 ~ "^"v"-" { print $3; exit }')
        [ -n "$full" ] || die "nginx.org has no NGINX $nginx_ver for $ID $VERSION_CODENAME"
        apt-get install -y -qq "nginx=$full" >/dev/null
    else
        cat > /etc/yum.repos.d/nginx.repo <<EOF
[nginx]
name=nginx.org
baseurl=http://nginx.org/packages/${branch}rhel/\$releasever/\$basearch/
gpgcheck=1
enabled=1
gpgkey=https://nginx.org/keys/nginx_signing.key
module_hotfixes=true
EOF
        dnf install -y -q "nginx-$nginx_ver" >/dev/null || die "nginx.org has no NGINX $nginx_ver for $ID $VERSION_ID"
    fi
fi

# --- Strata packages install ------------------------------------------------
if [ $fam = deb ]; then
    module_pkg=$(list | grep "^nginx-module-strata_${nginx_ver}+.*_amd64\.deb\$" | sort -V | tail -1)
else
    module_pkg=$(list | grep "^nginx-module-strata-${nginx_ver}+.*\.x86_64\.rpm\$" | sort -V | tail -1)
fi
fetch "$agent_pkg"
fetch "$module_pkg"
say "installing $agent_pkg and $module_pkg"
if [ $fam = deb ]; then
    apt-get install -y -qq "$dir/$agent_pkg" "$dir/$module_pkg" >/dev/null
else
    dnf install -y -q "$dir/$agent_pkg" "$dir/$module_pkg" >/dev/null
fi

conf=/etc/nginx/nginx.conf
if ! grep -q '^[[:space:]]*load_module[[:space:]].*ngx_http_strata_module\.so' "$conf"; then
    { echo "load_module modules/ngx_http_strata_module.so;"; cat "$conf"; } > "$conf.strata" && mv "$conf.strata" "$conf"
    say "load_module added to $conf"
fi

# --- Configure standalone directories and permissions ------------------------
install -d -o strata -g strata -m 0755 /var/lib/strata/bundles
install -d -o strata -g strata -m 0755 /var/log/strata
install -d -o strata -g strata -m 0755 /etc/strata

# Handle bundle
args="--bundle-dir=/var/lib/strata/bundles"
if [ -n "$bundle" ]; then
    case "$bundle" in
        http://*|https://*)
            say "downloading bundle from $bundle"
            curl -fsSL "$bundle" -o /var/lib/strata/bundles/bundle.sbn
            chown strata:strata /var/lib/strata/bundles/bundle.sbn
            chmod 0644 /var/lib/strata/bundles/bundle.sbn
            args="$args --bundle-file=/var/lib/strata/bundles/bundle.sbn"
            ;;
        *)
            [ -f "$bundle" ] || die "bundle file not found: $bundle"
            install -o strata -g strata -m 0644 "$bundle" /var/lib/strata/bundles/bundle.sbn
            args="$args --bundle-file=/var/lib/strata/bundles/bundle.sbn"
            ;;
    esac
fi

if [ -n "$bundle_pubkey" ]; then
    [ -f "$bundle_pubkey" ] || die "bundle pubkey not found: $bundle_pubkey"
    install -o strata -g strata -m 0644 "$bundle_pubkey" /etc/strata/bundle.pub
    args="$args --bundle-pubkey=/etc/strata/bundle.pub"
fi

if [ -n "$events_jsonl" ]; then
    touch "$events_jsonl"
    chown strata:strata "$events_jsonl"
    chmod 0640 "$events_jsonl"
    args="$args --events-jsonl=$events_jsonl"
fi

if [ -n "$syslog_addr" ]; then
    args="$args --syslog-addr=$syslog_addr"
fi

# Write /etc/strata/standalone.env
cat > /etc/strata/standalone.env <<EOF
STRATA_METRICS_ADDR=${metrics_addr}
STRATA_STANDALONE_ARGS="${args}"
EOF
chown root:strata /etc/strata/standalone.env
chmod 0640 /etc/strata/standalone.env

# Configure /etc/nginx/conf.d/strata.conf
cat > /etc/nginx/conf.d/strata.conf <<EOF
strata_control_file  /var/lib/strata/bundles/control;
strata_bundle_dir    /var/lib/strata/bundles;
strata_node_id       standalone;
strata_event_socket  unix:/run/strata/events.sock;
strata_metrics_file  /run/strata/metrics;
EOF
if [ -n "$bundle_pubkey" ]; then
    echo "strata_bundle_pubkey /etc/strata/bundle.pub;" >> /etc/nginx/conf.d/strata.conf
fi

say "standalone configuration written to /etc/strata/standalone.env and /etc/nginx/conf.d/strata.conf"

nginx -t -q || die "nginx -t failed"

if [ -d /run/systemd/system ]; then
    # Disable fleet agent service if present, enable standalone agent service
    systemctl disable -q strata-agent 2>/dev/null || true
    systemctl stop -q strata-agent 2>/dev/null || true
    systemctl enable -q --now strata-agent.socket strata-agent-standalone
    systemctl restart strata-agent-standalone
    systemctl enable -q nginx
    if systemctl is-active -q nginx; then systemctl reload nginx; else systemctl start nginx; fi
    say "strata-agent-standalone and NGINX started via systemd"
else
    say "no systemd: run 'strata-agent run --standalone $args' and start NGINX"
fi

say "done: Strata Standalone Lite ready (NGINX $nginx_ver, metrics at $metrics_addr, events at $events_jsonl)"
