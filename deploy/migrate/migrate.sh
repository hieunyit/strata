#!/usr/bin/env bash
# Moves the lab and staging (Docker Compose projects strata-lab and
# strata-staging) to another machine: export here, copy the directory,
# import there. Copying the repository is not enough: the data lives in
# Docker volumes, the passwords in .state, staging runs from its own build
# tree, and the release key of the signature package is outside the repo.
#
# Exported, per project:
#   - every volume of the project, with its labels, owners and modes kept,
#     except run-* and shm-* (sockets, tmpfs) and, unless --with-events,
#     clickhouse, victoriametrics and spool-* (events and metrics: they
#     start empty on the new machine);
#   - its .state (passwords; for staging, what is deployed);
#   - staging only: the tree it runs from (build/staging/<tag>, without its
#     build/ outputs), because it is not the tag as is (ports rewritten,
#     signature package, Vault limits fixed by hand on v0.9.0-rc.1);
#   - the images built here (strata-*), with --all-images every image of
#     the project (the new machine then needs no registry).
# And once: ~/.strata/keys (release key of the signature package).
#
# Each project is stopped while its volumes are read (a database copied
# while it runs may not open), then started again if it was running.
#
# Usage: deploy/migrate/migrate.sh export [--with-events] [--all-images] [--no-restart] <dir>
#        deploy/migrate/migrate.sh import [--no-up] [--up-all] <dir>
# import refuses to overwrite a volume, a .state, a tree or a key that is
# already there; it brings up the projects that were running at export
# (all with --up-all), then runs their smoke test.
#
# MIGRATE_PROJECTS ("name|compose file|state dir|tree dir" separated by
# spaces, tree dir empty when the project runs from the repository) and
# MIGRATE_KEYS_DIR replace the defaults (tests: test-migrate.sh).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
keys_dir="${MIGRATE_KEYS_DIR:-$HOME/.strata/keys}"
tar_image="${MIGRATE_TAR_IMAGE:-alpine:3.20}"

die() { echo "migrate: $*" >&2; exit 1; }
say() { echo "migrate: $*"; }

default_projects() {
    echo "strata-lab|$root/deploy/lab/compose.yaml|$root/deploy/lab/.state|"
    local tag
    tag=$(sed -n 's/^tag=//p' "$root/deploy/staging/.state/deployed" 2>/dev/null | head -1)
    [ -n "$tag" ] && echo "strata-staging|$root/build/staging/$tag/deploy/lab/compose.yaml|$root/deploy/staging/.state|$root/build/staging/$tag"
    return 0
}
projects() {
    if [ -n "${MIGRATE_PROJECTS:-}" ]; then tr ' ' '\n' <<<"$MIGRATE_PROJECTS"; else default_projects; fi
}

# volume name without the project prefix -> kept or not
keep_volume() { # short-name with-events
    case "$1" in
        run-*|shm-*) return 1 ;;
        clickhouse|victoriametrics|spool-*) [ "$2" = 1 ] ;;
        *) return 0 ;;
    esac
}

tar_volume_out() { # volume out-dir
    docker run --rm -v "$1:/v:ro" -v "$2:/out" "$tar_image" tar -C /v -cpzf "/out/$1.tgz" .
}
tar_volume_in() { # volume archive-dir
    docker run --rm -v "$1:/v" -v "$2:/in:ro" "$tar_image" tar -C /v -xpzf "/in/$1.tgz"
}

cmd_export() {
    local with_events=0 all_images=0 restart=1
    while [ $# -gt 1 ]; do
        case "$1" in
            --with-events) with_events=1 ;;
            --all-images) all_images=1 ;;
            --no-restart) restart=0 ;;
            *) die "unknown option $1" ;;
        esac
        shift
    done
    local out="${1:-}"
    [ -n "$out" ] || die "usage: migrate.sh export [--with-events] [--all-images] [--no-restart] <dir>"
    [ ! -e "$out" ] || [ -z "$(ls -A "$out")" ] || die "$out is not empty"
    mkdir -p "$out"/{volumes,states,trees}
    out="$(cd "$out" && pwd)"
    docker image inspect "$tar_image" >/dev/null 2>&1 || docker pull -q "$tar_image" >/dev/null
    local images=("$tar_image") manifest="$out/manifest"
    {
        echo "format=1"
        echo "created_at=$(date -u +%FT%TZ)"
        echo "repo_commit=$(git -C "$root" rev-parse HEAD 2>/dev/null || echo none)"
        echo "with_events=$with_events"
    } > "$manifest"

    local spec name compose state tree vols v short running exported
    while IFS= read -r spec; do
        [ -n "$spec" ] || continue
        IFS='|' read -r name compose state tree <<<"$spec"
        vols=$(docker volume ls -q --filter "label=com.docker.compose.project=$name")
        if [ -z "$vols" ]; then say "$name: no volumes here, skipped"; continue; fi
        [ -f "$compose" ] || die "$name: no compose file $compose"
        [ -f "$state/env" ] || die "$name: no $state/env (its passwords)"

        running=$(docker ps -q --filter "label=com.docker.compose.project=$name" | wc -l)
        mapfile -t found < <(docker ps -a --filter "label=com.docker.compose.project=$name" --format '{{.Image}}' | sort -u)
        for i in "${found[@]}"; do
            # ours are named strata-*; the others come from a registry
            if [ "$all_images" = 1 ] || [[ "$i" == strata-* ]]; then
                images+=("$i")
            fi
        done
        if [ "$running" -gt 0 ]; then
            say "$name: stopping ($running containers running)"
            docker compose -p "$name" -f "$compose" --env-file "$state/env" stop >/dev/null
        fi

        exported=()
        for v in $vols; do
            short="${v#"${name}"_}"
            if ! keep_volume "$short" "$with_events"; then say "$name: $short not exported"; continue; fi
            tar_volume_out "$v" "$out/volumes"
            docker volume inspect -f '{{range $k, $l := .Labels}}{{$k}}={{$l}}{{"\n"}}{{end}}' "$v" > "$out/volumes/$v.labels"
            exported+=("$v")
        done
        tar -C "$state" -cpzf "$out/states/$name.tgz" .
        if [ -n "$tree" ]; then
            tar -C "$tree" --exclude=./build --exclude=./deploy/lab/.state -cpzf "$out/trees/$name.tgz" .
        fi
        {
            echo "project=$name"
            echo "  compose=${compose#"${tree:-$root}"/}"
            echo "  state=${state#"$root"/}"
            echo "  tree=${tree#"$root"/}"
            echo "  running=$running"
            echo "  volumes=${exported[*]}"
        } >> "$manifest"
        say "$name: ${#exported[@]} volumes, .state${tree:+, tree}"

        if [ "$running" -gt 0 ] && [ "$restart" = 1 ]; then
            say "$name: starting again"
            docker compose -p "$name" -f "$compose" --env-file "$state/env" start >/dev/null
        fi
    done < <(projects)

    mapfile -t images < <(printf '%s\n' "${images[@]}" | sort -u)
    say "saving images: ${images[*]}"
    docker save "${images[@]}" | gzip > "$out/images.tar.gz"
    if [ -d "$keys_dir" ]; then
        tar -C "$keys_dir" -cpzf "$out/keys.tgz" .
        echo "keys=yes" >> "$manifest"
    else
        say "no $keys_dir: release key not exported"
    fi
    (cd "$out" && find . -type f ! -name SHA256SUMS -printf '%P\n' | sort | xargs sha256sum > SHA256SUMS)
    say "done: $out ($(du -sh "$out" | cut -f1)); copy it whole (rsync -a), then: deploy/migrate/migrate.sh import <dir>"
    say "it holds passwords, the CA keys and the Vault unseal key: copy it over an encrypted channel, delete it after"
}

# manifest value of a project: field project key
pfield() { awk -v p="$2" -v k="$3" '$0 == "project=" p { on = 1; next } /^project=/ { on = 0 } on && $1 ~ "^" k "=" { sub(/^ *[^=]*=/, ""); print; exit }' "$1"; }

cmd_import() {
    local up=1 up_all=0
    while [ $# -gt 1 ]; do
        case "$1" in
            --no-up) up=0 ;;
            --up-all) up_all=1 ;;
            *) die "unknown option $1" ;;
        esac
        shift
    done
    local in="${1:-}"
    [ -n "$in" ] && [ -f "$in/manifest" ] || die "usage: migrate.sh import [--no-up] [--up-all] <dir exported by migrate.sh export>"
    in="$(cd "$in" && pwd)"
    local manifest="$in/manifest"
    grep -qx 'format=1' "$manifest" || die "$manifest: unknown format"
    (cd "$in" && sha256sum --quiet -c SHA256SUMS) || die "$in: checksums do not match (copy incomplete or altered)"

    # what this machine would lose: checked for every project first
    local name spec compose state tree v vols
    local -A target_compose target_state target_tree
    while IFS= read -r spec; do
        [ -n "$spec" ] || continue
        IFS='|' read -r name compose state tree <<<"$spec"
        target_compose[$name]="$compose" target_state[$name]="$state" target_tree[$name]="$tree"
    done < <(projects_for_import "$manifest")
    for name in $(sed -n 's/^project=//p' "$manifest"); do
        [ -n "${target_state[$name]:-}" ] || die "nowhere to put $name (MIGRATE_PROJECTS?)"
        for v in $(pfield "$manifest" "$name" volumes); do
            ! docker volume inspect "$v" >/dev/null 2>&1 || die "volume $v already exists here: remove it (docker compose -p $name down -v) or use another machine"
        done
        state="${target_state[$name]}"
        [ ! -e "$state" ] || [ -z "$(ls -A "$state")" ] || die "$state already exists"
        tree="${target_tree[$name]}"
        [ -z "$tree" ] || [ ! -e "$tree" ] || die "$tree already exists"
    done
    if [ -f "$in/keys.tgz" ]; then
        local k
        for k in $(tar -tzf "$in/keys.tgz" | grep -v '/$'); do
            [ ! -e "$keys_dir/${k#./}" ] || die "$keys_dir/${k#./} already exists"
        done
    fi
    local commit
    commit=$(sed -n 's/^repo_commit=//p' "$manifest")
    if [ "$(git -C "$root" rev-parse HEAD 2>/dev/null)" != "$commit" ]; then
        say "warning: this repository is not at $commit (the commit exported); the lab runs from the repository"
    fi

    say "loading images"
    gunzip -c "$in/images.tar.gz" | docker load -q

    local labels args l
    for name in $(sed -n 's/^project=//p' "$manifest"); do
        for v in $(pfield "$manifest" "$name" volumes); do
            labels="$in/volumes/$v.labels"
            args=()
            while IFS= read -r l; do [ -n "$l" ] && args+=(--label "$l"); done < "$labels"
            docker volume create "${args[@]}" "$v" >/dev/null
            tar_volume_in "$v" "$in/volumes"
        done
        state="${target_state[$name]}"
        mkdir -p "$state"
        tar -C "$state" -xpzf "$in/states/$name.tgz"
        tree="${target_tree[$name]}"
        if [ -n "$tree" ]; then
            mkdir -p "$tree"
            tar -C "$tree" -xpzf "$in/trees/$name.tgz"
            ln -s "$state" "$(dirname "${target_compose[$name]}")/.state"
        fi
        say "$name: volumes, .state${tree:+, tree} in place"
    done
    if [ -f "$in/keys.tgz" ]; then
        mkdir -p "$keys_dir" && chmod 0700 "$keys_dir"
        tar -C "$keys_dir" -xpzf "$in/keys.tgz"
        say "keys in $keys_dir"
    fi

    [ "$up" = 1 ] || { say "done (not started: --no-up)"; return 0; }
    local smoke
    for name in $(sed -n 's/^project=//p' "$manifest"); do
        if [ "$up_all" = 0 ] && [ "$(pfield "$manifest" "$name" running)" = 0 ]; then
            say "$name: was stopped at export, not started (--up-all to start it)"
            continue
        fi
        compose="${target_compose[$name]}" state="${target_state[$name]}"
        say "$name: starting"
        docker compose -p "$name" -f "$compose" --env-file "$state/env" up -d --no-build --wait --wait-timeout 900
        smoke="$(dirname "$compose")/smoke.sh"
        if [ -x "$smoke" ]; then "$smoke"; fi
    done
    say "done"
}

# where each exported project goes on this machine: as on the old one,
# under this repository
projects_for_import() { # manifest
    local name tree
    for name in $(sed -n 's/^project=//p' "$1"); do
        if [ -n "${MIGRATE_PROJECTS:-}" ]; then
            tr ' ' '\n' <<<"$MIGRATE_PROJECTS" | grep "^$name|" || die "MIGRATE_PROJECTS has no $name"
            continue
        fi
        tree=$(pfield "$1" "$name" tree)
        if [ -n "$tree" ]; then tree="$root/$tree"; fi
        echo "$name|${tree:-$root}/$(pfield "$1" "$name" compose)|$root/$(pfield "$1" "$name" state)|$tree"
    done
}

case "${1:-}" in
    export) shift; cmd_export "$@" ;;
    import) shift; cmd_import "$@" ;;
    *) die "usage: migrate.sh export|import [options] <dir>" ;;
esac
