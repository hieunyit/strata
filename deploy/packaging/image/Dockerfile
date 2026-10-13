# Strata node image (W10-N-01): the official NGINX image (nginx.org
# packages, Debian) with the nginx-module-strata and strata-agent packages
# of build/packages. Built by deploy/packaging/build-image.sh, whose context
# holds only the packages and the entrypoint.
# Run it with --sysctl net.unix.max_dgram_qlen=8192 and a volume on
# /var/lib/strata (identity, bundles, spool); see docs/runbook/install.md.
ARG NGINX_VERSION=1.30.5
FROM nginx:${NGINX_VERSION}
ARG NGINX_VERSION
# the packages are bind-mounted: no layer keeps them
RUN --mount=type=bind,source=packages,target=/tmp/pkgs \
    apt-get update -qq \
    && apt-get install -y -qq --no-install-recommends \
        /tmp/pkgs/strata-agent_*_amd64.deb "/tmp/pkgs/nginx-module-strata_${NGINX_VERSION}+"*_amd64.deb >/dev/null \
    && rm -rf /var/lib/apt/lists/* \
    && sed -i '1i load_module modules/ngx_http_strata_module.so;' /etc/nginx/nginx.conf \
    && nginx -t -q
COPY entrypoint.sh /usr/local/bin/strata-entrypoint
ENTRYPOINT ["strata-entrypoint"]
CMD ["nginx", "-g", "daemon off;"]
