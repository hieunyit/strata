# Fresh systemd container for package tests; this is not VM acceptance.
# No Strata or NGINX is present in the fixture.
ARG BASE=ubuntu:24.04
FROM ${BASE}
RUN set -e; if command -v apt-get >/dev/null; then \
        apt-get update -qq; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq systemd systemd-sysv curl ca-certificates procps python3 >/dev/null; \
        rm -rf /var/lib/apt/lists/*; \
    else \
        dnf install -y -q systemd procps-ng; dnf clean all; \
    fi; \
    systemctl mask systemd-logind.service getty.target console-getty.service 2>/dev/null || true
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
