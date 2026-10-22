#!/bin/sh
# nginx-module-strata post-install: NGINX workers join the strata group when
# the agent is installed first; nginx.conf is left to install.sh or the
# operator (docs/runbook/install.md).
set -e
if getent group strata >/dev/null && getent passwd nginx >/dev/null; then usermod -a -G strata nginx; fi
# audit 22/10/2026: NGINX trusted a bundle key the agent user could rewrite.
# A configuration written by an older install.sh moves to a root-owned copy.
conf=/etc/nginx/conf.d/strata.conf
old=/var/lib/strata/bundles/bundle.pub
if [ -f "$conf" ] && grep -q "^strata_bundle_pubkey $old;\$" "$conf" && [ -s "$old" ] && [ ! -e /etc/strata/bundle.pub ]; then
    install -d -o root -g root -m 0755 /etc/strata
    install -o root -g root -m 0644 "$old" /etc/strata/bundle.pub
    sed -i "s|^strata_bundle_pubkey $old;\$|strata_bundle_pubkey /etc/strata/bundle.pub;|" "$conf"
    echo "strata: bundle key moved to /etc/strata/bundle.pub (root-owned); reload NGINX"
fi
cat <<'MSG'
----------------------------------------------------------------------
The Strata module is in /usr/lib/nginx/modules/ngx_http_strata_module.so.
Load it at the top of /etc/nginx/nginx.conf:
    load_module modules/ngx_http_strata_module.so;
Settings: /usr/share/nginx-module-strata/strata.conf.example
----------------------------------------------------------------------
MSG
exit 0
