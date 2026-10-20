# Compact control plane (CP-A09): the control plane with the Web UI built
# in, the bundle compiler, the replay tool, the core rule pack and the replay
# corpus; pg_dump/pg_restore 17 for strata-control-plane backup/restore.
# Built from build/compact/dist (deploy/compact/build.sh), never from the
# repository directly.
FROM ubuntu:noble-20260917
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl gnupg \
    && install -d /usr/share/postgresql-common/pgdg \
    && curl -fsSL -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc https://www.postgresql.org/media/keys/ACCC4CF8.asc \
    && echo "deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] https://apt.postgresql.org/pub/repos/apt noble-pgdg main" \
        > /etc/apt/sources.list.d/pgdg.list \
    && apt-get update && apt-get install -y --no-install-recommends postgresql-client-17 libstdc++6 \
    && apt-get purge -y gnupg && apt-get autoremove -y && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 1001 strata && useradd -u 1001 -g strata -M -d /nonexistent -s /usr/sbin/nologin strata \
    && install -d -o strata -g strata -m 0700 /var/lib/strata /var/backups/strata
COPY bin/ /usr/local/bin/
COPY rules/ /opt/strata/rules/
COPY block.html replay-corpus.parquet /opt/strata/
USER strata
WORKDIR /var/lib/strata
EXPOSE 8080 8443
HEALTHCHECK --interval=10s --timeout=3s --retries=30 CMD curl -fsS http://127.0.0.1:8080/healthz || exit 1
ENTRYPOINT ["strata-control-plane"]
