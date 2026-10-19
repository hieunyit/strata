#!/bin/sh
# RPM posttrans: after old preun, restart the selected standalone/Fleet mode.
# Fresh installs have neither an enabled standalone service nor a Fleet identity.
set -e
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload
    /usr/libexec/strata/agent-restart
fi
exit 0
