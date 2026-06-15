#!/usr/bin/env bash
# E2E test: closed-loop firewall overlay (FLOKBN-045)
# Brings up the fast test base plus the firewall/monitoring overlay and verifies:
#   1. flokbn publishes bans and the banpoller renders them as nginx deny rules
#   2. banned clients start failing (403) while the negative control stays OK
#   3. flokbn /metrics serves Prometheus text format with active bans
#   4. Prometheus scrapes flokbn and sees the denied 403s via the log exporter
#   5. Grafana is healthy and the provisioned flokbn dashboard exists
#
# Prerequisites: docker and docker compose must be available.
# This test takes ~60-90 seconds to run.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

PASS=0
FAIL=0
COMPOSE_PROJECT="flokbn-e2e-firewall-$$"
COMPOSE=(docker compose -p "$COMPOSE_PROJECT" -f "$REPO_ROOT/docker-compose.test.yml" -f "$REPO_ROOT/docker-compose-firewall-with-monitoring.demo.yml")

log() { printf "[e2e-firewall] %s\n" "$*"; }
pass() { PASS=$((PASS + 1)); log "PASS: $1"; }
fail() { FAIL=$((FAIL + 1)); log "FAIL: $1"; }

cleanup() {
    log "Tearing down Docker Compose..."
    "${COMPOSE[@]}" down -v --remove-orphans 2>/dev/null || true
}
trap cleanup EXIT

# --- Check prerequisites ---
if ! command -v docker &>/dev/null; then
    log "SKIP: docker not found"
    exit 0
fi
if ! docker info &>/dev/null 2>&1; then
    log "SKIP: docker daemon not running"
    exit 0
fi

# --- Build and start ---
log "Building and starting firewall overlay stack..."
cd "$REPO_ROOT"
"${COMPOSE[@]}" build --quiet 2>/dev/null
"${COMPOSE[@]}" up -d 2>/dev/null

# --- Wait for flokbn and Filebeat ---
log "Waiting for flokbn container to start..."
MAX_WAIT=30
for i in $(seq 1 $MAX_WAIT); do
    STATUS=$("${COMPOSE[@]}" ps flokbn --format '{{.State}}' 2>/dev/null || echo "")
    if [ "$STATUS" = "running" ]; then
        break
    fi
    if [ "$i" -eq "$MAX_WAIT" ]; then
        fail "flokbn container did not start within ${MAX_WAIT}s"
        exit 1
    fi
    sleep 1
done
pass "flokbn container started"

log "Waiting for Filebeat to connect..."
MAX_WAIT=60
for i in $(seq 1 $MAX_WAIT); do
    LOGS=$("${COMPOSE[@]}" logs flokbn 2>/dev/null || echo "")
    if echo "$LOGS" | grep -q "Filebeat connected"; then
        pass "Filebeat connected"
        break
    fi
    if [ "$i" -eq "$MAX_WAIT" ]; then
        fail "Filebeat did not connect within ${MAX_WAIT}s"
    fi
    sleep 1
done

# --- Test 1: bans appear and the banpoller applies deny rules ---
log "Test 1: banpoller applies deny rules..."
DENY_RULES=""
for i in $(seq 1 30); do
    DENY_RULES=$("${COMPOSE[@]}" exec -T proxy cat /etc/nginx/banned/deny.conf 2>/dev/null || echo "")
    if echo "$DENY_RULES" | grep -q "^deny"; then
        break
    fi
    sleep 1
done
if echo "$DENY_RULES" | grep -q "^deny"; then
    DENY_COUNT=$(echo "$DENY_RULES" | grep -c "^deny")
    pass "deny.conf has $DENY_COUNT deny rules"
    echo "$DENY_RULES" | while read -r line; do log "  $line"; done
else
    fail "deny.conf has no deny rules after 30s"
fi

if echo "$DENY_RULES" | grep -q "deny 172.16.16"; then
    pass "net4 attack cluster (172.16.16.x) is denied"
else
    fail "net4 attack cluster missing from deny rules"
fi
if echo "$DENY_RULES" | grep -q "172.30.99"; then
    fail "negative control subnet 172.30.99.x must never be denied"
else
    pass "negative control subnet not in deny rules"
fi

# Give the reloaded nginx a few seconds to produce 403s and the 2s-interval
# Prometheus scrapes to pick them up.
sleep 6

# --- Test 2: banned clients fail, negative control stays OK ---
log "Test 2: client outcomes after enforcement..."
NET4_TAIL=$("${COMPOSE[@]}" logs --tail 20 clients_net4 2>/dev/null || echo "")
if echo "$NET4_TAIL" | grep -q "FAIL"; then
    pass "banned net4 clients log FAIL"
else
    fail "banned net4 clients still succeed (no FAIL in recent log)"
fi
NET5_LOGS=$("${COMPOSE[@]}" logs clients_net5 2>/dev/null || echo "")
if echo "$NET5_LOGS" | grep -q "FAIL"; then
    fail "negative control client logged FAIL"
else
    pass "negative control client never failed"
fi

# --- Test 3: flokbn /metrics endpoint ---
log "Test 3: flokbn /metrics..."
METRICS=$("${COMPOSE[@]}" exec -T flokbn wget -q -O - http://127.0.0.1:8666/metrics 2>/dev/null || echo "")
if echo "$METRICS" | grep -q "^# TYPE flokbn_jail_active gauge"; then
    pass "/metrics serves Prometheus text format"
else
    fail "/metrics missing TYPE header for flokbn_jail_active"
fi
JAIL_ACTIVE=$(echo "$METRICS" | grep "^flokbn_jail_active " | awk '{print $2}' || echo "0")
if [ -n "$JAIL_ACTIVE" ] && [ "${JAIL_ACTIVE%%.*}" -gt 0 ] 2>/dev/null; then
    pass "flokbn_jail_active = $JAIL_ACTIVE"
else
    fail "flokbn_jail_active not > 0 (got '$JAIL_ACTIVE')"
fi
if echo "$METRICS" | grep -q '^flokbn_ban_active{cidr="'; then
    pass "per-CIDR ban series present (flokbn_ban_active)"
else
    fail "flokbn_ban_active has no per-CIDR series"
fi

# --- Test 4: Prometheus sees flokbn and the denied 403s ---
log "Test 4: Prometheus queries..."
PROM_JAIL=$("${COMPOSE[@]}" exec -T prometheus wget -q -O - \
    'http://localhost:9090/api/v1/query?query=flokbn_jail_active' 2>/dev/null || echo "")
if echo "$PROM_JAIL" | grep -q '"status":"success"' && echo "$PROM_JAIL" | grep -q '"flokbn_jail_active"'; then
    pass "Prometheus scrapes flokbn_jail_active"
else
    fail "Prometheus query for flokbn_jail_active returned no sample"
fi
PROM_403=""
for i in $(seq 1 15); do
    PROM_403=$("${COMPOSE[@]}" exec -T prometheus wget -q -O - \
        'http://localhost:9090/api/v1/query?query=nginx_http_response_count_total%7Bstatus%3D%22403%22%7D' 2>/dev/null || echo "")
    if echo "$PROM_403" | grep -q '"status":"403"'; then
        break
    fi
    sleep 2
done
if echo "$PROM_403" | grep -q '"status":"403"'; then
    pass "Prometheus sees denied 403s via nginx log exporter"
else
    fail "no nginx 403 samples in Prometheus"
fi
if echo "$PROM_403" | grep -q '"subnet":"172.16.16.0/24"'; then
    pass "nginx metrics carry the client subnet label"
else
    fail "subnet label missing on nginx metrics (relabel config)"
fi

# --- Test 5: Grafana health + provisioned dashboard ---
log "Test 5: Grafana..."
GRAFANA_HEALTH=""
for i in $(seq 1 30); do
    GRAFANA_HEALTH=$("${COMPOSE[@]}" exec -T grafana wget -q -O - \
        http://localhost:3000/api/health 2>/dev/null || echo "")
    if echo "$GRAFANA_HEALTH" | grep -q '"database": *"ok"'; then
        break
    fi
    sleep 1
done
if echo "$GRAFANA_HEALTH" | grep -q '"database": *"ok"'; then
    pass "Grafana healthy"
else
    fail "Grafana /api/health not ok: $GRAFANA_HEALTH"
fi
DASHBOARD=$("${COMPOSE[@]}" exec -T grafana wget -q -O - \
    http://localhost:3000/api/dashboards/uid/flokbn 2>/dev/null || echo "")
if echo "$DASHBOARD" | grep -q '"uid": *"flokbn"'; then
    pass "provisioned flokbn dashboard exists"
else
    fail "flokbn dashboard not provisioned"
fi

# --- Summary ---
log "============================="
log "Results: $PASS passed, $FAIL failed"
log "============================="

[ "$FAIL" -eq 0 ]
