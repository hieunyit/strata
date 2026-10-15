#!/bin/sh
# strata-agent pre-remove: on removal, stop and disable the agent and its
# socket (data in /var/lib/strata stays). On upgrade (deb: "upgrade",
# rpm: 1), nothing: the agent keeps running until postinst restarts it
# (W13-G1-01; before, an upgrade stopped and disabled it for good).
set -e
case "$1" in
    remove | purge | 0)
        if [ -d /run/systemd/system ]; then
            systemctl disable --now strata-agent.service strata-agent.socket >/dev/null 2>&1 || true
        fi
        ;;
esac
exit 0
