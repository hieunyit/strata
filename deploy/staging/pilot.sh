#!/usr/bin/env bash
# W10-G1-01: the two pilot routes of an environment (staging or prod-sim),
# simulated until the PO names the real ones (docs/plan/w10-plan.md §5):
#
#   pilot-verify  POST /v1/verify on api.example.test, JSON
#   pilot-upload  POST /v1/upload on api.example.test, multipart
#
# Each route is its own node: the node image (deploy/packaging/image) built
# from the deployed tag's sources, enrolled with the environment's control
# plane in group "pilot", in front of a simulated backend (a second server
# of the same NGINX). Inspection is off until W10-G2-01 deploys the pilot
# policies and runs pilot.sh --inspect.
#
# Usage: deploy/staging/pilot.sh [--env staging|prod-sim] [--inspect|--no-inspect] up|status|down|policies
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
env=staging inspect=""
while [ $# -gt 0 ]; do
    case "$1" in
        --env) env=${2:?}; shift 2 ;;
        --inspect) inspect=1; shift ;;
        --no-inspect) inspect=0; shift ;;
        *) break ;;
    esac
done
cmd=${1:-status}
case "$env" in
    staging) d=2 project=strata-staging state="$here/.state" ;;
    prod-sim) d=3 project=strata-prodsim state="$here/.state-prod-sim" ;;
    *) echo "pilot: --env staging|prod-sim" >&2; exit 2 ;;
esac
die() { echo "pilot[$env]: $*" >&2; exit 1; }
say() { echo "pilot[$env]: $*"; }
routes=(pilot-verify pilot-upload)
port() { case "$1" in pilot-verify) echo "${d}8480" ;; pilot-upload) echo "${d}8481" ;; esac; }
cp="http://127.0.0.1:${d}8090"
[ -s "$state/deployed" ] || die "nothing deployed (deploy/staging/deploy.sh --env $env <tag>)"
# --inspect / --no-inspect are remembered: a plain "up" after a deploy keeps
# what the pilot routes had (it used to turn inspection off silently)
mkdir -p "$state/pilot"
case "$inspect" in
    1) touch "$state/pilot/inspect" ;;
    0) rm -f "$state/pilot/inspect" ;;
    *) inspect=0; [ -e "$state/pilot/inspect" ] && inspect=1 ;;
esac
tag=$(sed -n 's/^tag=//p' "$state/deployed")
src="$root/build/$env/$tag"
# shellcheck disable=SC1091
. "$state/env"
new_token() {
    curl -fsS "http://127.0.0.1:${d}8180/realms/strata/protocol/openid-connect/token" \
        -d grant_type=password -d client_id=strata-lab-cli -d "client_secret=$LAB_CLI_SECRET" \
        -d username=lab-admin --data-urlencode "password=$LAB_ADMIN_PASSWORD" |
        sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p'
}
api() { curl -fsS -H "Authorization: Bearer $(new_token)" -H 'Content-Type: application/json' "$@"; }
# four eyes (W13-G2-02): lab-admin drafts and submits, lab-approver approves
# approvals wait for the version's replay (PO 16/10: nothing is approved
# without a DONE replay); the replay of a draft takes seconds to minutes
replay_done() { # policy version
    local st start=$SECONDS
    until st=$(api "$cp/v1/policies/$1/versions/$2/replay" | sed -n 's/.*"state":"\([A-Z]*\)".*/\1/p' | head -1) && [ "$st" = DONE ]; do
        [ "$st" = FAILED ] && return 1
        [ $((SECONDS - start)) -lt 900 ] || return 1
        sleep 2
    done
}
approve_new() { # policy: version 1, just created
    api -X POST "$cp/v1/policies/$1:submit" -d '{}' >/dev/null || die "submit $1"
    replay_done "$1" 1 || die "the replay of $1 version 1 did not finish"
    curl -fsS -o /dev/null -X POST -H 'Content-Type: application/json' -H "Authorization: Bearer $(curl -fsS \
        "http://127.0.0.1:${d}8180/realms/strata/protocol/openid-connect/token" \
        -d grant_type=password -d client_id=strata-lab-cli -d "client_secret=$LAB_CLI_SECRET" \
        -d username=lab-approver --data-urlencode "password=$LAB_APPROVER_PASSWORD" |
        sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')" \
        "$cp/v1/policies/$1:approve" -d '{"version":1,"comment":"pilot route, shadow"}' || die "approve $1"
}

status() {
    api "$cp/v1/nodes" | python3 -c '
import json, sys
for n in json.load(sys.stdin)["nodes"]:
    if n.get("group_id") == "pilot" and not n.get("revoked"):
        print("  %-14s %s online=%s bundle=%s proxy=%s" % (n["hostname"], n["id"], n.get("online", False), n.get("bundle_version", "-"), n.get("proxy_version", "-")))'
}

conf() { # route, path: the NGINX server of the node and its simulated backend
    local on="# inspection off until W10-G2-01 (pilot.sh --inspect)"
    # The full signature package costs about 1-3 ms per small request on
    # the shared staging CPUs, around the 2 ms default budget: most
    # requests went fail-open, uninspected (#27, #28). Shadow does not block,
    # so the pilot locations get a larger budget; the latency it adds is
    # what the access log's t= measures.
    [ "$inspect" = 1 ] && on="strata on;
        strata_policy $1;
        strata_cpu_budget ${PILOT_CPU_BUDGET:-20ms};"
    cat <<EOF
log_format strata_pilot '\$remote_addr "\$request" \$status blk=\$strata_block_id act=\$strata_action '
                        'score=\$strata_score rules=\$strata_rules policy=\$strata_policy t=\$strata_time_us '
                        'len=\$request_length';
server {
    listen 80;
    access_log /var/log/nginx/access.log strata_pilot;
    server_name api.example.test;
    client_max_body_size 8m;
    location = $2 {
        $on
        proxy_pass http://127.0.0.1:8081;
    }
    location = /healthz { return 204; }
    location / { return 404; }
}
# simulated backend of $1
server {
    listen 127.0.0.1:8081;
    default_type application/json;
    location / { return 200 '{"route":"$1","status":"ok"}'; }
}
EOF
}

deploy_wait() { # policy: deploys (a bundle of every policy), waits for the rollout
    local out ro st start=$SECONDS
    out=$(api -X POST "$cp/v1/policies/$1:deploy" -d '{}') || die "deploy $1"
    ro=$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("rollout_id", ""))' <<< "$out")
    [ -n "$ro" ] || die "deploy $1: $out"
    # the rollout's own state, not one of its nodes'
    until st=$(api "$cp/v1/rollouts/$ro" | python3 -c 'import json,sys; print(json.load(sys.stdin)["rollout"]["state"])') \
        && [ "$st" = DONE ]; do
        case "$st" in FAILED|ABORTED) die "rollout $ro: $st" ;; esac
        [ $((SECONDS - start)) -lt 300 ] || die "rollout $ro not done in 300 s ($st)"
        sleep 2
    done
    say "$1 deployed, rollout $ro done in $((SECONDS - start)) s"
}

case "$cmd" in
policies)
    # W10-G2-01: one shadow policy per pilot route (fail mode stays the
    # module's default, open; oversize bodies pass)
    for r in "${routes[@]}"; do
        c=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "Authorization: Bearer $(new_token)" -H 'Content-Type: application/json' \
            "$cp/v1/policies" -d "{\"id\":\"$r\",\"name\":\"$r\",\"spec\":{\"mode\":\"MODE_SHADOW\",\"oversize\":\"OVERSIZE_PASS\"}}")
        case "$c" in
            200) approve_new "$r"; say "policy $r created in shadow, approved" ;;
            409) mode=$(api "$cp/v1/policies/$r" | python3 -c 'import json,sys; print(json.load(sys.stdin)["policy"]["spec"]["mode"])')
                 [ "$mode" = MODE_SHADOW ] || die "policy $r exists in $mode, not MODE_SHADOW" ;;
            *) die "create policy $r: HTTP $c" ;;
        esac
    done
    deploy_wait pilot-verify ;;
status)
    say "tag $tag"; status ;;
down)
    for r in "${routes[@]}"; do docker rm -f "$project-$r" >/dev/null 2>&1 || true; done
    say "pilot nodes stopped (volumes and enrollment kept)" ;;
up)
    # 1. the node image from the tag's own sources (package of W10-N-01)
    [ -d "$src" ] || die "no sources of $tag in $src (deploy it first)"
    ver=$(sed -e 's/^v//' -e 's/-/~/' -e 's/-/./g' <<< "$tag")
    tagver=${ver//\~/-}
    image="strata-nginx:1.30.5-$tagver"
    if ! docker image inspect "$image" >/dev/null 2>&1; then
        say "building $image from $src"
        (cd "$src" && STRATA_VERSION="$ver" deploy/packaging/build.sh 1.30.5 >/dev/null && deploy/packaging/build-image.sh 1.30.5)
    fi
    # 2. group and one node per route
    code=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "Authorization: Bearer $(new_token)" -H 'Content-Type: application/json' \
        "$cp/v1/groups" -d '{"id":"pilot","name":"Pilot routes (simulated)"}')
    case "$code" in 200|409) ;; *) die "group pilot: HTTP $code" ;; esac
    work="$state/pilot"
    mkdir -p "$work"
    docker compose -p "$project" cp control-plane:/state/pki/ca.pem "$work/ca.pem" >/dev/null 2>&1 \
        || docker cp "$project-control-plane-1:/state/pki/ca.pem" "$work/ca.pem"
    chmod 0644 "$work/ca.pem"
    for r in "${routes[@]}"; do
        path=/v1/${r#pilot-}
        conf "$r" "$path" > "$work/$r.conf"
        # worker_processes from the container's CPUs, not the host's (the
        # official image's autotune): 16 cold workers on 2 CPUs made most
        # requests run over the CPU budget
        envs=(-e NGINX_ENTRYPOINT_WORKER_PROCESSES_AUTOTUNE=1 -e "STRATA_SERVER=control-plane:8443" -e STRATA_SERVER_NAME=cp.example.test -e STRATA_CA_FILE=/pilot/ca.pem)
        if ! docker run --rm --entrypoint test -v "${project}_pilot-$r:/v" "$image" -s /v/identity/node-id 2>/dev/null; then
            api -X POST "$cp/v1/groups/pilot/enrollmentTokens" -d '{}' | sed -n 's/.*"token":"\([^"]*\)".*/\1/p' > "$work/$r.token"
            [ -s "$work/$r.token" ] || die "no enrollment token for $r"
            chmod 0644 "$work/$r.token"
            envs+=(-e "STRATA_ENROLL_TOKEN_FILE=/pilot/$r.token")
        fi
        docker rm -f "$project-$r" >/dev/null 2>&1 || true
        docker run -d --name "$project-$r" --hostname "$r" --restart unless-stopped \
            --network "${project}_default" --network-alias "$r" --cpuset-cpus="${STAGING_CPUS:-14-15}" \
            --sysctl net.unix.max_dgram_qlen=8192 -p "127.0.0.1:$(port "$r"):80" \
            -v "${project}_pilot-$r:/var/lib/strata" -v "$work:/pilot:ro" \
            -v "$work/$r.conf:/etc/nginx/conf.d/default.conf:ro" \
            --label "strata.pilot=$r" --label "org.opencontainers.image.version=$tag" \
            "${envs[@]}" "$image" >/dev/null
    done
    # 3. both online, then their agents in VictoriaMetrics
    start=$SECONDS
    until [ "$(status | grep -c 'online=True')" = 2 ]; do
        [ $((SECONDS - start)) -lt 120 ] || { status; die "pilot nodes not online in 120 s"; }
        sleep 2
    done
    # the tokens are used once enrolled (not before: the entrypoint reads them)
    rm -f "$work"/*.token
    scrape="$src/deploy/lab/vm/scrape.yml"
    if ! grep -q 'job_name: strata-agent-pilot' "$scrape"; then
        cat >> "$scrape" <<'EOF'
  - job_name: strata-agent-pilot
    scrape_interval: 15s
    static_configs:
      - targets: ["pilot-verify:9469", "pilot-upload:9469"]
EOF
        docker kill -s HUP "$project-victoriametrics-1" >/dev/null
    fi
    for r in "${routes[@]}"; do
        # a node just started may still reset connections while its NGINX
        # loads the bundle; curl then exits non-zero, which set -e turned
        # into a silent exit of the whole script (deploy.sh, 14/10)
        start=$SECONDS
        until c=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Host: api.example.test' -H 'Content-Type: application/json' \
            -d '{"id":"example"}' "http://127.0.0.1:$(port "$r")/v1/${r#pilot-}") && [ "$c" = 200 ]; do
            [ $((SECONDS - start)) -lt 30 ] || die "$r does not answer 200 in 30 s (${c:-no answer})"
            sleep 1
        done
    done
    say "pilot nodes up on :${d}8480 (verify) and :${d}8481 (upload), inspection $([ "$inspect" = 1 ] && echo on || echo off)"
    status ;;
*) die "usage: pilot.sh [--env staging|prod-sim] [--inspect|--no-inspect] up|status|down|policies" ;;
esac
