#!/bin/sh
# nginx-module-strata post-install: NGINX workers join the strata group when
# the agent is installed first; nginx.conf is left to install.sh or the
# operator (docs/runbook/install.md).
set -e
if getent group strata >/dev/null && getent passwd nginx >/dev/null; then usermod -a -G strata nginx; fi
cat <<'MSG'
----------------------------------------------------------------------
The Strata module is in /usr/lib/nginx/modules/ngx_http_strata_module.so.
Load it at the top of /etc/nginx/nginx.conf:
    load_module modules/ngx_http_strata_module.so;
Settings: /usr/share/nginx-module-strata/strata.conf.example
----------------------------------------------------------------------
MSG
exit 0
