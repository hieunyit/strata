#!/bin/sh
# Failed APT/DNF installs must not produce successful fixture images.
set -eu
root=$(CDPATH='' cd -- "$(dirname -- "$0")/../../.." && pwd)
mkdir -p "$root/build"
work=$(mktemp -d "$root/build/pkg-image-failure.XXXXXX")
name=strata-pkgtest-install-failure-$$
cleanup() {
    rm -rf "$work"
    for family in apt-get dnf; do
        docker image rm "$name-$family" "$name-$family-base" >/dev/null 2>&1 || :
    done
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
cat > "$work/fail" <<'SCRIPT'
#!/bin/sh
exit 42
SCRIPT
chmod 0755 "$work/fail"
for family in apt-get dnf; do
    if [ "$family" = apt-get ]; then
        dest=/usr/local/bin/apt-get
        path_line=''
    else
        dest=/lab-bin/dnf
        path_line='ENV PATH=/lab-bin'
    fi
    cat > "$work/Dockerfile" <<DOCKER
FROM debian:12
COPY fail $dest
$path_line
DOCKER
    docker build -q -t "$name-$family-base" "$work" >/dev/null
    set +e
    docker run --rm "$name-$family-base" "$family" update
    probe_status=$?
    set -e
    [ "$probe_status" = 42 ] || { echo "invalid $family failure fixture" >&2; exit 1; }
    if docker build --build-arg "BASE=$name-$family-base" -t "$name-$family" "$root/deploy/packaging/test" > "$work/build.log" 2>&1; then
        echo "FAIL: package image build swallowed $family exit 42" >&2
        exit 1
    fi
    grep -Eq '(exit|non-zero) code: *42' "$work/build.log" || { cat "$work/build.log"; exit 1; }
    echo "PASS: $family exit 42 propagates; no successful package-test image"
done
