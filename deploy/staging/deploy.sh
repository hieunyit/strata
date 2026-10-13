#!/usr/bin/env bash
# W09-Q-02: deploys a tagged release to staging, on this machine (Docker +
# Compose), next to the lab. Only a tag can be deployed:
#   - it must look like v<major>.<minor>.<patch>[-<pre>];
#   - it must exist on origin and point there to the same commit as here;
#   - the sources are taken from the tag itself (git archive), never from
#     the working tree, and everything is built from them.
# Staging is the lab stack (deploy/lab of that tag) under the project
# strata-staging: host ports 1xxxx become 2xxxx (UI 28088, NGINX 28080 and
# 28081, control plane 28090, Keycloak 28180, Grafana 23000...), images
# are tagged with the release, passwords and data stay in
# deploy/staging/.state and the strata-staging volumes across deploys.
#
# Usage: deploy/staging/deploy.sh <tag>          deploy (build, up, smoke)
#        deploy/staging/deploy.sh --check <tag>  only the checks on the tag
#        deploy/staging/deploy.sh --status       what is deployed
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
state="$here/.state"
remote="${STAGING_REMOTE:-origin}"

die() { echo "staging: $*" >&2; exit 1; }

if [ "${1:-}" = "--status" ]; then
    cat "$state/deployed" 2>/dev/null || echo "staging: nothing deployed"
    exit 0
fi
check_only=0
if [ "${1:-}" = "--check" ]; then check_only=1; shift; fi
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
echo "staging: $tag = $local_commit (on $remote)"
[ "$check_only" = 1 ] && exit 0

# 2. the sources of the tag, and the build from them
src="$root/build/staging/$tag"
rm -rf "$src" && mkdir -p "$src"
git -C "$root" archive "$tag" | tar -x -C "$src"
(cd "$src" && deploy/dev/run.sh deploy/lab/build.sh)

# 3. the lab stack of the tag, as staging
lab="$src/deploy/lab"
for f in compose.yaml smoke.sh keycloak/strata-realm.json; do
    sed -i -E \
        -e 's/(127\.0\.0\.1|localhost):1([0-9]{4})\b/\1:2\2/g' \
        -e 's/^name: strata-lab$/name: strata-staging/' \
        -e "s/strata-lab-runtime:dev/strata-staging-runtime:$tag/g" \
        -e "s/strata-lab-ui:dev/strata-staging-ui:$tag/g" \
        "$lab/$f"
done
grep -q '^name: strata-staging$' "$lab/compose.yaml" || die "compose.yaml of $tag has no project name to rewrite"
mkdir -p "$state"
rm -rf "$lab/.state" && ln -s "$state" "$lab/.state"
"$lab/init-env.sh" # once: staging passwords, kept across deploys
compose=(docker compose -f "$lab/compose.yaml" --env-file "$state/env")
"${compose[@]}" build
"${compose[@]}" up -d --wait --wait-timeout 900

# 4. what is deployed, then the lab smoke test against it
printf 'tag=%s\ncommit=%s\ndeployed_at=%s\n' "$tag" "$local_commit" "$(date -u +%FT%TZ)" > "$state/deployed"
"$lab/smoke.sh"
echo "staging: $tag deployed"
