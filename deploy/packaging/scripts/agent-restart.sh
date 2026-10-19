#!/bin/sh
# Called only by package upgrade/post-transaction hooks under systemd.
set -eu
if systemctl is-active -q strata-agent-standalone.service ||
   systemctl is-active -q strata-agent-standalone.socket ||
   systemctl is-enabled -q strata-agent-standalone.service; then
    systemctl enable -q strata-agent-standalone.socket strata-agent-standalone.service
    systemctl start strata-agent-standalone.socket
    systemctl restart strata-agent-standalone.service
elif [ -s /var/lib/strata/identity/node-id ]; then
    systemctl enable -q strata-agent.socket strata-agent.service
    if ! systemctl is-active -q strata-agent.socket; then
        systemctl stop strata-agent.service
        systemctl start strata-agent.socket
    fi
    systemctl restart strata-agent.service
fi
