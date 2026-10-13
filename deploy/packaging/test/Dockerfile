# A "clean VM" for the install test (W10-N-01): the distribution's base
# image with systemd as init and nothing else of Strata or NGINX.
ARG BASE=ubuntu:24.04
FROM ${BASE}
RUN if command -v apt-get >/dev/null; then \
        apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq systemd systemd-sysv curl ca-certificates procps >/dev/null \
        && rm -rf /var/lib/apt/lists/*; \
    else \
        dnf install -y -q systemd procps-ng && dnf clean all; \
    fi \
    && systemctl mask systemd-logind.service getty.target console-getty.service 2>/dev/null || true
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
