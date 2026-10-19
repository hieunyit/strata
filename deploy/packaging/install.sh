#!/bin/sh
# Strata node installer (W10-N-01): one command on a clean Ubuntu, Debian or
# RHEL-family machine.
#
#   sh install.sh --packages <dir|URL> [--nginx <version>]
#                 [--packages-only]
#                 [--server <host:port> --token-file <file> --ca <file> [--server-name <name>]]
#
# 1. NGINX: the one installed, or, if none, <version> from nginx.org (the
#    newest version the packages have a module for when not given).
# 2. strata-agent and the nginx-module-strata package built for exactly that
#    NGINX version; none built for it is an error (nothing is installed).
# 3. load_module at the top of nginx.conf; net.unix.max_dgram_qlen (package).
# 4. With --server: enrolls the node (the token is used once), writes
#    /etc/nginx/conf.d/strata.conf, starts the agent and (re)loads NGINX.
# Inspection stays off until a server or location says `strata on;` and
# `strata_policy <name>;`
# (docs/runbook/install.md). From a URL, every file is checked against
# SHA256SUMS. Run it again to upgrade: it is idempotent.
set -eu

die() { echo "strata-install: $*" >&2; exit 1; }
say() { echo "strata-install: $*"; }

pkgs="" nginx_ver="" server="" server_name="" token_file="" ca="" packages_only=false
while [ $# -gt 0 ]; do
    case "$1" in
        --packages) pkgs=${2:?}; shift 2 ;;
        --packages-only) packages_only=true; shift ;;
        --nginx) nginx_ver=${2:?}; shift 2 ;;
        --server) server=${2:?}; shift 2 ;;
        --server-name) server_name=${2:?}; shift 2 ;;
        --token-file) token_file=${2:?}; shift 2 ;;
        --ca) ca=${2:?}; shift 2 ;;
        *) die "unknown argument $1" ;;
    esac
done
[ -n "$pkgs" ] || die "usage: install.sh --packages <dir|URL> [--nginx <version>] [--server <host:port> --token-file <file> --ca <file>]"
[ "$(id -u)" = 0 ] || die "run as root"
if [ "$packages_only" = true ]; then
    [ -z "$server$server_name$token_file$ca" ] || die "--packages-only cannot enroll a node"
fi
if [ -n "$server" ]; then
    [ -r "${token_file:-/nonexistent}" ] || die "--server needs --token-file <readable file>"
    [ -r "${ca:-/nonexistent}" ] || die "--server needs --ca <readable file>"
fi
case "$nginx_ver" in ''|[0-9]*.[0-9]*.[0-9]*) ;; *) die "bad NGINX version $nginx_ver" ;; esac

. /etc/os-release
case "$ID ${ID_LIKE:-}" in
    *debian*|*ubuntu*) fam=deb ;;
    *rhel*|*fedora*|*centos*|*rocky*|*almalinux*) fam=rpm ;;
    *) die "unsupported system $ID" ;;
esac

# --- the packages --------------------------------------------------------
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
case "$pkgs" in
    http://*|https://*)
        command -v curl >/dev/null || die "curl is needed to download $pkgs"
        curl -fsSL "${pkgs%/}/SHA256SUMS" -o "$work/SHA256SUMS" || die "no SHA256SUMS at $pkgs"
        fetch() { # file: download and check it
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

# --- NGINX -----------------------------------------------------------------
installed=""
if command -v nginx >/dev/null; then
    installed=$(nginx -v 2>&1 | sed -n 's|.*nginx/\([0-9.]*\).*|\1|p')
fi
if [ -n "$installed" ]; then
    [ -z "$nginx_ver" ] || [ "$nginx_ver" = "$installed" ] \
        || die "NGINX $installed is installed, not $nginx_ver: upgrade NGINX first (and only to a version listed below)"
    nginx_ver=$installed
fi
[ -n "$nginx_ver" ] || nginx_ver=$(echo "$modules" | tail -1)
echo "$modules" | grep -qx "$nginx_ver" \
    || die "no Strata module built for NGINX $nginx_ver (built for: $(echo $modules)); keep NGINX on one of those"

if [ -z "$installed" ]; then
    # nginx.org: odd minor = mainline
    minor=$(echo "$nginx_ver" | cut -d. -f2)
    branch=""; [ $((minor % 2)) = 1 ] && branch=mainline/
    say "installing NGINX $nginx_ver from nginx.org"
    if [ $fam = deb ]; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y -qq curl ca-certificates >/dev/null
        curl --proto '=https' --proto-redir '=https' -fsSL https://nginx.org/keys/nginx_signing.key -o "$work/nginx-signing.asc"
        # APT >= 1.4 accepts armored .asc keys directly. Avoid installing the
        # full GnuPG suite solely to convert this public key. _apt needs 0644.
        install -m 0644 "$work/nginx-signing.asc" /usr/share/keyrings/nginx-archive-keyring.asc
        echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.asc] https://nginx.org/packages/${branch}$ID $VERSION_CODENAME nginx" \
            > /etc/apt/sources.list.d/nginx.list
        chmod 0644 /etc/apt/sources.list.d/nginx.list
        # OS indexes were just refreshed. Add only NGINX indexes and keep those
        # OS indexes for dependency resolution in the following installations.
        apt-get update -qq -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/nginx.list \
            -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0
        full=$(apt-cache madison nginx | awk -v v="$nginx_ver" '$3 ~ "^"v"-" { print $3; exit }')
        [ -n "$full" ] || die "nginx.org has no NGINX $nginx_ver for $ID $VERSION_CODENAME"
        apt-get install -y -qq "nginx=$full" >/dev/null
    else
        cat > /etc/yum.repos.d/nginx.repo <<EOF
[nginx]
name=nginx.org
baseurl=https://nginx.org/packages/${branch}rhel/\$releasever/\$basearch/
gpgcheck=1
enabled=1
gpgkey=https://nginx.org/keys/nginx_signing.key
module_hotfixes=true
EOF
        dnf install -y -q "nginx-$nginx_ver" >/dev/null || die "nginx.org has no NGINX $nginx_ver for $ID $VERSION_ID"
    fi
fi

# --- Strata packages --------------------------------------------------------
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

if [ "$packages_only" = true ]; then
    say "packages installed; NGINX configuration and Strata activation left to caller"
    exit 0
fi

conf=/etc/nginx/nginx.conf
if ! grep -q '^[[:space:]]*load_module[[:space:]].*ngx_http_strata_module\.so' "$conf"; then
    { echo "load_module modules/ngx_http_strata_module.so;"; cat "$conf"; } > "$conf.strata" && mv "$conf.strata" "$conf"
    say "load_module added to $conf"
fi

# --- enrollment ---------------------------------------------------------------
if [ -n "$server" ]; then
    install -o root -g strata -m 0640 "$ca" /etc/strata/ca.pem
    sed -i -e "s|^STRATA_SERVER=.*|STRATA_SERVER=$server|" \
        -e "s|^STRATA_SERVER_NAME=.*|STRATA_SERVER_NAME=$server_name|" /etc/strata/agent.env
    if [ ! -s /var/lib/strata/identity/node-id ]; then
        tok=/var/lib/strata/enroll.token
        install -o strata -g strata -m 0600 "$token_file" "$tok"
        if ! runuser -u strata -- /usr/bin/strata-agent enroll --server="$server" ${server_name:+--server-name="$server_name"} \
            --tls-ca=/etc/strata/ca.pem --token-file="$tok" --identity-dir=/var/lib/strata/identity; then
            rm -f "$tok"
            die "enrollment refused (token used, expired, or wrong CA)"
        fi
        rm -f "$tok"
    fi
    node=$(cat /var/lib/strata/identity/node-id)
    # NGINX reads the bundle key at start; the agent's identity stays private
    install -o strata -g strata -m 0644 /var/lib/strata/identity/bundle.pub /var/lib/strata/bundles/bundle.pub
    sed "s|@NODE_ID@|$node|" /usr/share/nginx-module-strata/strata.conf.example > /etc/nginx/conf.d/strata.conf
    say "node $node enrolled with $server"
fi

nginx -t -q || die "nginx -t failed: see above"
if [ -d /run/systemd/system ]; then
    if [ -n "$server" ]; then
        systemctl enable -q --now strata-agent.socket strata-agent
        systemctl restart strata-agent
    fi
    systemctl enable -q nginx
    if systemctl is-active -q nginx; then systemctl reload nginx; else systemctl start nginx; fi
else
    say "no systemd: start strata-agent and NGINX yourself"
fi
say "done: NGINX $nginx_ver, $(basename "$module_pkg"), $(basename "$agent_pkg")"
[ -n "$server" ] || say "not enrolled yet: run again with --server, --token-file and --ca"
