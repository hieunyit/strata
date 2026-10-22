#!/bin/bash
# Strata node image: enrolls once (STRATA_SERVER, STRATA_ENROLL_TOKEN or
# STRATA_ENROLL_TOKEN_FILE, STRATA_CA_FILE, STRATA_SERVER_NAME), then runs
# strata-agent and NGINX side by side. When either exits the other is
# stopped and the container exits with its status, for the orchestrator to
# restart it (a supervisor that hides a dead agent would hide lost events).
set -euo pipefail
ident=/var/lib/strata/identity
install -d -o strata -g strata -m 0750 /var/lib/strata "$ident" /var/lib/strata/spool /run/strata
install -d -o strata -g strata -m 0755 /var/lib/strata/bundles
server=${STRATA_SERVER:?STRATA_SERVER (control plane host:port) is required}
if [ ! -s "$ident/node-id" ]; then
    tok=/var/lib/strata/enroll.token
    if [ -n "${STRATA_ENROLL_TOKEN_FILE:-}" ]; then install -o strata -m 0600 "$STRATA_ENROLL_TOKEN_FILE" "$tok"
    else (umask 077; printf '%s' "${STRATA_ENROLL_TOKEN:?not enrolled: STRATA_ENROLL_TOKEN or STRATA_ENROLL_TOKEN_FILE}" > "$tok"); chown strata "$tok"; fi
    install -o root -g strata -m 0640 "${STRATA_CA_FILE:?STRATA_CA_FILE is required to enroll}" /var/lib/strata/ca.pem
    setpriv --reuid=strata --regid=strata --init-groups strata-agent enroll --server="$server" \
        ${STRATA_SERVER_NAME:+--server-name="$STRATA_SERVER_NAME"} --tls-ca=/var/lib/strata/ca.pem \
        --token-file="$tok" --identity-dir="$ident" || { rm -f "$tok"; exit 1; }
    rm -f "$tok"
fi
# root owns NGINX's copy of the bundle key, taken once at enrollment: the
# agent user must not choose the key the root master trusts (audit 22/10/2026)
if [ ! -s /etc/strata/bundle.pub ]; then
    install -d -o root -g root -m 0755 /etc/strata
    install -o root -g root -m 0644 "$ident/bundle.pub" /etc/strata/bundle.pub
fi
sed "s|@NODE_ID@|$(cat "$ident/node-id")|" /usr/share/nginx-module-strata/strata.conf.example > /etc/nginx/conf.d/strata.conf

setpriv --reuid=strata --regid=strata --init-groups strata-agent run \
    --server="$server" ${STRATA_SERVER_NAME:+--server-name="$STRATA_SERVER_NAME"} \
    --identity-dir="$ident" --spool-dir=/var/lib/strata/spool \
    --bundle-dir=/var/lib/strata/bundles --control-file=/var/lib/strata/bundles/control \
    --event-socket=unix:/run/strata/events.sock --metrics-file=/run/strata/metrics \
    --metrics-addr="${STRATA_METRICS_ADDR:-0.0.0.0:9469}" &
agent=$!
/docker-entrypoint.sh "$@" &
proxy=$!
trap 'kill -TERM $agent $proxy 2>/dev/null' TERM INT
set +e
wait -n $agent $proxy
status=$?
kill -TERM $agent $proxy 2>/dev/null
wait
exit $status
