#!/usr/bin/env bash
# W07-G1-01 on a running lab (make lab-up): ForceShadow from the admin API;
# time until every NGINX worker of node-1 lets through a request it would
# block (Event ID, action log), and until it blocks again at expiry.
set -euo pipefail
. deploy/lab/.state/env
tok() { curl -fsS http://127.0.0.1:18180/realms/strata/protocol/openid-connect/token -d grant_type=password -d client_id=strata-lab-cli -d "client_secret=$LAB_CLI_SECRET" -d "username=$1" --data-urlencode "password=$2" | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p'; }
OP=$(tok lab-operator "$LAB_OPERATOR_PASSWORD")
host=$(docker inspect strata-lab-agent-1-1 --format '{{.Config.Hostname}}')
node=$(curl -fsS -H "Authorization: Bearer $OP" http://127.0.0.1:18090/v1/nodes | python3 -c "import json,sys; print([n['id'] for n in json.load(sys.stdin)['nodes'] if n['hostname']=='$host'][0])")
attack() { curl -s -o /dev/null -w '%{http_code}' -H 'Host: api.example.test' 'http://127.0.0.1:18080/files/%2e%2e/etc/passwd'; }
echo "node-1 = $node; before: $(attack)"
dur=15
t0=$(date +%s.%N)
resp=$(curl -fsS -X POST -H "Authorization: Bearer $OP" -H 'Content-Type: application/json' \
  -d "{\"node_id\":\"$node\",\"policy_id\":\"example-api\",\"duration_seconds\":$dur}" http://127.0.0.1:18090/v1/nodes:forceShadow)
echo "API: $resp"
# every worker: 20 requests in a row
streak() { local want=$1 n=0; while [ $n -lt 20 ]; do c=$(attack); if [ "$want" = pass ] && [ "$c" != 403 ]; then n=$((n+1)); elif [ "$want" = block ] && [ "$c" = 403 ]; then n=$((n+1)); else return 1; fi; done; }
until streak pass; do
  [ "$(echo "$(date +%s.%N) - $t0 > 10" | bc)" = 1 ] && { echo "FAIL: still blocked after 10 s"; exit 1; }
  sleep 0.05
done
t1=$(date +%s.%N)
printf 'shadow on every worker after %.2f s (status %s)\n' "$(echo "$t1 - $t0" | bc)" "$(attack)"
docker logs --tail 5 strata-lab-nginx-stable-1 2>&1 | grep -o 'blk=[^ ]* act=[^ ]*' | tail -1
until streak block; do
  [ "$(echo "$(date +%s.%N) - $t0 > $dur + 10" | bc)" = 1 ] && { echo "FAIL: not blocked again"; exit 1; }
  sleep 0.1
done
printf 'blocked again %.2f s after the call (duration %d s)\n' "$(echo "$(date +%s.%N) - $t0" | bc)" $dur
id=$(echo "$resp" | sed -n 's/.*"id":"\(cmd-[a-z2-7]*\)".*/\1/p')
curl -fsS -H "Authorization: Bearer $OP" "http://127.0.0.1:18090/v1/commands/$id" | python3 -c 'import json,sys; c=json.load(sys.stdin)["command"]; print("command", c["id"], c["state"], c["created_by"])'
