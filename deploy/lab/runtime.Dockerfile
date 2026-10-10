# Hyperscan is linked statically into the module and the tools.
# Runtime image of the lab: both NGINX builds with ngx_http_strata_module,
# strata-agent, the control plane and the bundle tools. Built from
# build/lab/dist (deploy/lab/build.sh), never from the repo directly.
FROM ubuntu:noble-20260917
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl openssl libstdc++6 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 1001 strata && useradd -u 1001 -g strata -M -d /nonexistent -s /usr/sbin/nologin strata \
    && mkdir -p /run/strata /var/lib/strata/spool /var/lib/strata/identity /var/lib/strata/bundles \
    && chown strata:strata /run/strata /var/lib/strata/spool /var/lib/strata/identity && chmod 0700 /var/lib/strata/identity
COPY nginx /opt/nginx
COPY bin/ /usr/local/bin/
COPY rules.yaml policies.yaml block.html init.sh fleet-init.sh install-bundle.sh /opt/strata/
USER strata
