#!/bin/sh
# strata-agent post-install (deb and rpm): user, directories, sysctl.
set -e
if ! getent group strata >/dev/null; then groupadd --system strata; fi
if ! getent passwd strata >/dev/null; then
    useradd --system --gid strata --home-dir /var/lib/strata --no-create-home \
        --shell /usr/sbin/nologin strata
fi
# NGINX workers send events to the agent's socket (mode 0660, group strata)
if getent passwd nginx >/dev/null; then usermod -a -G strata nginx; fi
install -d -o strata -g strata -m 0750 /var/lib/strata /var/lib/strata/identity /var/lib/strata/spool
install -d -o strata -g strata -m 0755 /var/lib/strata/bundles
chown root:strata /etc/strata/agent.env
if command -v systemd-tmpfiles >/dev/null; then systemd-tmpfiles --create /usr/lib/tmpfiles.d/strata.conf || true; fi
install -d -o strata -g strata -m 0750 /run/strata
# the sysctl applies now; in a container without the right to set it, the
# agent warns at start (StrataDgramQueueTooShort)
sysctl -q -p /usr/lib/sysctl.d/90-strata.conf 2>/dev/null || \
    echo "strata-agent: could not set net.unix.max_dgram_qlen now; it applies at the next boot" >&2
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
    # deb upgrade (configure, with the old version in $2) of an enrolled
    # node: the new agent replaces the old one (W13-G1-01). rpm does it in
    # %posttrans (agent-posttrans.sh): its %post runs before the old
    # package's %preun, which, before W13-G1-01, stopped the agent.
    if [ "$1" = configure ] && [ -n "${2:-}" ] && [ -s /var/lib/strata/identity/node-id ]; then
        # the socket stays with systemd, so events queue during the restart;
        # the first upgrade from a package without the socket unit moves the
        # socket to systemd once (a second's gap)
        systemctl enable -q strata-agent.socket strata-agent.service || true
        if ! systemctl is-active -q strata-agent.socket; then
            systemctl stop strata-agent.service || true
            systemctl start strata-agent.socket || true
        fi
        systemctl restart strata-agent.service || true
    fi
fi
exit 0
