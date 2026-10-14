#!/usr/bin/env bash
# W09-Q-02: only release tags on origin can be deployed to staging. Checks
# the refusals of deploy.sh (--check: no build, nothing started):
#   a branch name, a commit hash, a tag that is not a release tag, a release
#   tag that exists only here, a tag that does not exist; and, with
#   STAGING_TEST_TAG=<a pushed release tag>, that such a tag is accepted.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
deploy="$here/deploy.sh"
fail=0
refuse() { # description, args...
    local what=$1; shift
    if out=$("$deploy" --check "$@" 2>&1); then
        echo "FAIL $what: accepted ($out)"; fail=1
    else
        echo "ok   $what refused: ${out#staging: }"
    fi
}
refuse "a branch" main
refuse "a commit" "$(git -C "$root" rev-parse HEAD)"
refuse "a tag that is not a release tag" not-a-release
refuse "a release tag that does not exist" v0.0.0-missing
local_tag="v0.0.0-stagingtest.$$"
git -C "$root" tag "$local_tag" HEAD
refuse "a release tag only here (not pushed)" "$local_tag"
git -C "$root" tag -d "$local_tag" >/dev/null
if [ -n "${STAGING_TEST_TAG:-}" ]; then
    if out=$("$deploy" --check "$STAGING_TEST_TAG" 2>&1); then
        echo "ok   $STAGING_TEST_TAG accepted: ${out#staging: }"
    else
        echo "FAIL $STAGING_TEST_TAG refused: $out"; fail=1
    fi
fi
# $d is the port prefix of the environment (2xxxx, 3xxxx), set once by the
# --env case; reusing it (a loop over --signatures did) breaks the port
# rewrite after the build
n=$(grep -cE '(^|[ ;(])d=|for d in' "$deploy")
if [ "$n" = 2 ]; then
    echo "ok   \$d only set by --env"
else
    echo "FAIL \$d set $n times in deploy.sh (want 2: staging, prod-sim)"; fail=1
fi
exit $fail
