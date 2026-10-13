#!/bin/sh
# strata-agent pre-remove: stop the service (data in /var/lib/strata stays).
set -e
if [ -d /run/systemd/system ]; then systemctl disable --now strata-agent.service >/dev/null 2>&1 || true; fi
exit 0
