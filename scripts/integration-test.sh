#!/usr/bin/env bash
# Fully automated integration tests using Podman.
#
#  1. Starts a throwaway PostgreSQL 16 container.
#  2. Runs the Go integration suite (backend/integration) against it, with a mock ip-api server.
#  3. Builds the application container image (frontend + backend) and runs it against the same
#     database loaded with fixture data, then exercises the HTTP API and the served SPA.
#
# Usage: scripts/integration-test.sh [--no-e2e] [--keep]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_ID="$$-$RANDOM"
NET="pmacct-it-$RUN_ID"
PG="pmacct-it-pg-$RUN_ID"
APP="pmacct-it-app-$RUN_ID"
IMAGE="localhost/pmacct-analyzer:it-$RUN_ID"
PG_IMAGE="${PG_IMAGE:-docker.io/library/postgres:16-alpine}"
E2E=1
KEEP=0
for a in "$@"; do
  case "$a" in
    --no-e2e) E2E=0 ;;
    --keep) KEEP=1 ;;
    *) echo "unknown arg: $a" >&2; exit 2 ;;
  esac
done

log() { printf '\033[1;34m[it]\033[0m %s\n' "$*"; }
cleanup() {
  if [ "$KEEP" = 1 ]; then log "keeping containers ($PG, $APP)"; return; fi
  podman rm -f "$APP" >/dev/null 2>&1 || true
  podman rm -f "$PG" >/dev/null 2>&1 || true
  podman network rm "$NET" >/dev/null 2>&1 || true
  podman rmi "$IMAGE" >/dev/null 2>&1 || true
}
trap cleanup EXIT

log "creating network $NET"
podman network create "$NET" >/dev/null

log "starting postgres ($PG_IMAGE)"
podman run -d --name "$PG" --network "$NET" -p 127.0.0.1::5432 \
  -e POSTGRES_USER=pmacct -e POSTGRES_PASSWORD=pmacctpass -e POSTGRES_DB=pmacct \
  "$PG_IMAGE" >/dev/null
PG_PORT="$(podman port "$PG" 5432/tcp | head -n1 | sed 's/.*://')"
for i in $(seq 1 60); do
  if podman exec "$PG" pg_isready -U pmacct -d pmacct >/dev/null 2>&1; then break; fi
  sleep 1
  [ "$i" = 60 ] && { echo "postgres did not become ready" >&2; podman logs "$PG"; exit 1; }
done
# pg_isready can pass before the init script restarts the server; verify a real query.
for i in $(seq 1 30); do
  if podman exec "$PG" psql -U pmacct -d pmacct -Atc 'select 1' >/dev/null 2>&1; then break; fi
  sleep 1
done
export TEST_DATABASE_URL="postgres://pmacct:pmacctpass@127.0.0.1:${PG_PORT}/pmacct?sslmode=disable"
log "postgres ready on 127.0.0.1:$PG_PORT"

log "running Go unit tests"
(cd "$ROOT/backend" && go test ./...)

log "running Go integration tests"
(cd "$ROOT/backend" && go test -count=1 ${VERBOSE:+-v} ./integration/...)

if [ "$E2E" = 0 ]; then log "skipping container e2e"; exit 0; fi

log "loading fixture data for container e2e"
podman exec "$PG" psql -U pmacct -d pmacct -q -c 'DROP TABLE IF EXISTS acct, proto, ip_info, ip_nicknames, alerts, settings, host_hourly, host_peer_daily, threat_lists, ids_events, ip_names, ip_reputation, schema_migrations CASCADE' >/dev/null
podman exec -i "$PG" psql -U pmacct -d pmacct -q < "$ROOT/backend/integration/fixtures/schema.sql" >/dev/null
podman exec -i "$PG" psql -U pmacct -d pmacct -q < "$ROOT/backend/integration/fixtures/data.sql" >/dev/null

log "building application image $IMAGE"
# WITH_AGENT=0: the Rust cross-build takes minutes; the e2e uses the locally built agent instead.
podman build -q --format docker --build-arg WITH_AGENT=0 -t "$IMAGE" -f "$ROOT/Containerfile" "$ROOT" >/dev/null

log "starting application container"
podman run -d --name "$APP" --network "$NET" -p 127.0.0.1::8080 -p 127.0.0.1::8091 \
  -e DATABASE_URL="postgres://pmacct:pmacctpass@${PG}:5432/pmacct?sslmode=disable" \
  -e LOCAL_NETWORKS="192.168.1.0/24" \
  -e ENRICH_ENABLED=false \
  -e AUTH_ENABLED=false \
  -e TLS_LISTEN_ADDR=":8091" \
  -e TLS_HOSTS="127.0.0.1,localhost" \
  "$IMAGE" >/dev/null
APP_PORT="$(podman port "$APP" 8080/tcp | head -n1 | sed 's/.*://')"
TLS_PORT="$(podman port "$APP" 8091/tcp | head -n1 | sed 's/.*://')"
BASE="http://127.0.0.1:${APP_PORT}"
TLS_BASE="https://127.0.0.1:${TLS_PORT}"
for i in $(seq 1 60); do
  if curl -sf "$BASE/healthz" >/dev/null 2>&1; then break; fi
  sleep 1
  [ "$i" = 60 ] && { echo "app did not become healthy" >&2; podman logs "$APP"; exit 1; }
done
log "app healthy on $BASE"

fail=0
check() { # check <description> <command...>
  local desc="$1"; shift
  if "$@"; then log "PASS  $desc"; else log "FAIL  $desc"; fail=1; fi
}
json() { curl -sf "$BASE$1"; }
export -f json
export BASE PG APP

check "SPA index served at /"                bash -c "json / | grep -q '<div id=\"app\"'"
check "SPA fallback for deep route"          bash -c "json /hosts/1.2.3.4 | grep -q '<div id=\"app\"'"
check "static asset served"                  bash -c "asset=\$(json / | grep -o '/assets/[^\"]*\.js' | head -n1); [ -n \"\$asset\" ] && curl -sf -o /dev/null \"$BASE\$asset\""
check "overview totals match fixture"        bash -c "json '/api/v1/overview?since=24h' | grep -q '\"bytes\":18464'"
check "overview counts 2 local hosts"        bash -c "json '/api/v1/overview?since=24h' | grep -q '\"local_hosts\":2'"
check "hosts external listing"               bash -c "json '/api/v1/hosts?since=24h&scope=external' | grep -q '\"total\":3'"
check "host detail"                          bash -c "json '/api/v1/hosts/192.168.1.10?since=24h' | grep -q '\"bytes_out\":1644'"
check "flows filter"                         bash -c "json '/api/v1/flows?since=24h&port=53' | grep -o '\"port_dst\"' | wc -l | grep -qx 3"
check "migrations created ip_info"           bash -c "podman exec $PG psql -U pmacct -d pmacct -Atc \"select count(*) from information_schema.tables where table_name='ip_info'\" | grep -qx 1"
check "enrichment reports disabled"          bash -c "json /api/v1/enrichment/status | grep -q '\"enabled\":false'"
check "unknown api route is 404 json"        bash -c "curl -s -o /dev/null -w '%{http_code}' $BASE/api/v1/nope | grep -qx 404"
check "alerts summary endpoint"              bash -c "json /api/v1/alerts/summary | grep -q '\"open\"'"
check "rules engine lists rules"             bash -c "json /api/v1/rules | grep -q '\"threat_feed\"'"
check "ids summary reports disabled"         bash -c "json /api/v1/ids/summary | grep -q '\"enabled\":false'"
check "system status endpoint"               bash -c "json /api/v1/system/status | grep -q '\"rules_enabled\"'"
check "migrations created alerts table"      bash -c "podman exec $PG psql -U pmacct -d pmacct -Atc \"select count(*) from information_schema.tables where table_name='alerts'\" | grep -qx 1"
check "auth/me reports disabled"             bash -c "json /api/v1/auth/me | grep -q '\"auth\":false'"
check "migrations created users table"       bash -c "podman exec $PG psql -U pmacct -d pmacct -Atc \"select count(*) from information_schema.tables where table_name='users'\" | grep -qx 1"
check "healthz reachable inside container"   bash -c "podman exec $APP curl -sf http://127.0.0.1:8080/healthz | grep -q '\"status\":\"ok\"'"
check "image HEALTHCHECK passes"             podman healthcheck run "$APP"
# Built-in HTTPS: the CA downloaded over plain HTTP verifies the TLS listener; without it, TLS fails.
CA_FILE="$(mktemp)"; trap 'rm -f "$CA_FILE"' EXIT
check "tls/info reports internal CA"         bash -c "json /api/v1/tls/info | grep -q '\"internal_ca\":true'"
check "CA certificate downloadable"           bash -c "curl -sf '$BASE/api/v1/tls/ca' -o '$CA_FILE' && grep -q 'BEGIN CERTIFICATE' '$CA_FILE'"
check "https verifies with the CA"            bash -c "curl -sf --cacert '$CA_FILE' '$TLS_BASE/healthz' | grep -q '\"status\":\"ok\"'"
check "https rejected without the CA"         bash -c "! curl -sf '$TLS_BASE/healthz' >/dev/null 2>&1"
check "https serves the API"                  bash -c "curl -sf --cacert '$CA_FILE' '$TLS_BASE/api/v1/tls/info' | grep -q '\"enabled\":true'"
check "agent installer script served"        bash -c "json /api/v1/agent/install.sh | grep -q 'pmacct-agent installer'"
check "agent builds endpoint answers"         bash -c "json /api/v1/agent/builds | grep -q '\"items\"'"
check "missing agent build is a clean 404"    bash -c "curl -s -o /dev/null -w '%{http_code}' '$BASE/api/v1/agent/download/linux-amd64' | grep -q 404"
# Endpoint agent: the real Rust binary enrolls over pinned TLS and heartbeats (skipped when not built).
AGENT_BIN="$ROOT/agent/target/release/pmacct-agent"
if [ -x "$AGENT_BIN" ]; then
  AGENT_DIR="$(mktemp -d)"; export PMACCT_AGENT_DIR="$AGENT_DIR"
  ENROLL_JSON="$(curl -sf -X POST -H 'Content-Type: application/json' -d '{"name":"it-agent"}' "$BASE/api/v1/agents/enroll-tokens")"
  ENROLL_TOKEN="$(printf '%s' "$ENROLL_JSON" | sed -n 's/.*"enroll_token":"\([^"]*\)".*/\1/p')"
  CA_PIN="$(printf '%s' "$ENROLL_JSON" | sed -n 's/.*"ca_spki_sha256":"\([^"]*\)".*/\1/p')"
  check "agent rejects a wrong CA pin"          bash -c "! '$AGENT_BIN' enroll --server '$TLS_BASE' --token '$ENROLL_TOKEN' --ca-pin AAAA >/dev/null 2>&1"
  check "agent enrolls over pinned TLS"         bash -c "'$AGENT_BIN' enroll --server '$TLS_BASE' --token '$ENROLL_TOKEN' --ca-pin '$CA_PIN' 2>&1 | grep -q 'enrolled as \"it-agent\"'"
  check "agent refuses plain http"              bash -c "! curl -sf -X POST -H 'Authorization: Bearer x' '$BASE/api/v1/agent/events' -d '{}' >/dev/null 2>&1"
  check "agent heartbeat accepted"              bash -c "'$AGENT_BIN' status 2>&1 | grep -q 'heartbeat   ok'"
  check "agent listed as online"                bash -c "json /api/v1/agents | grep -q '\"name\":\"it-agent\"'"
  check "agent snapshot runs"                   bash -c "'$AGENT_BIN' snapshot | head -1 | grep -q 'capture=poll'"
  rm -rf "$AGENT_DIR"
else
  log "SKIP  endpoint agent checks (build with: cd agent && cargo build --release)"
fi

if [ "$fail" != 0 ]; then
  echo "--- app logs ---" >&2; podman logs "$APP" >&2
  exit 1
fi
log "all integration and e2e checks passed"
