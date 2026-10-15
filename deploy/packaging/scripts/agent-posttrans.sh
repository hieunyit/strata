#!/bin/sh
# strata-agent %posttrans (rpm only, W13-G1-01): after the whole
# transaction, an enrolled node runs the new agent with its socket from
# systemd. On upgrade the old package's %preun runs after the new %post
# (and, before W13-G1-01, stopped and disabled the agent): this runs last.
# A fresh install is not enrolled yet: install.sh starts the agent.
set -e
if [ -d /run/systemd/system ] && [ -s /var/lib/strata/identity/node-id ]; then
    systemctl daemon-reload || true
    systemctl enable -q strata-agent.socket strata-agent.service || true
    if ! systemctl is-active -q strata-agent.socket; then
        systemctl stop strata-agent.service || true
        systemctl start strata-agent.socket || true
    fi
    systemctl restart strata-agent.service || true
fi
exit 0
