#!/usr/bin/env bash
# E2E test: live mode multi-trie detection verification
# Verifies that the Docker Compose setup with 5 client networks (4 attack,
# 1 negative control) produces expected clustering detections across
# multiple detection tries.
#
# Docker network layout (from docker-compose.yml). One traffic-gen container
# per subnet simulates all client IPs via secondary addresses:
#   net1: 172.16.1.32-35  (clients_net1: 4 IPs,  0.1s interval)  -> curl UA, GET /
#   net2: 172.16.2.32-33  (clients_net2: 2 IPs,  0.1s interval)  -> curl UA, GET /
#   net3: 172.16.3.32-36  (clients_net3: 5 IPs,  0.1s interval)  -> curl UA, GET /
#   net4: 172.16.16.32-64 (clients_net4: 33 IPs, 0.07s interval) -> curl UA, GET /
#   net5: 172.30.99.32    (clients_net5: 1 IP,   3s interval)    -> negative
#         control; must never be clustered or banned
#
# Detection config (from docker-test-config.toml):
#   general_detection:    min_size=50, depth 24-32, threshold 0.2
#   aggressive_detection: min_size=10, depth 20-28, threshold 0.15
#                         min_size=20, depth 16-24, threshold 0.2
#   iteration sleep: 1s for both detection tries
#
# Prerequisites: docker and docker compose must be available.
# This test takes ~40-60 seconds to run.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

PASS=0
FAIL=0
COMPOSE_PROJECT="cidrx-e2e-detect-$$"

log() { printf "[e2e-detect] %s\n" "$*"; }
pass() { PASS=$((PASS + 1)); log "PASS: $1"; }
fail() { FAIL=$((FAIL + 1)); log "FAIL: $1"; }

cleanup() {
    log "Tearing down Docker Compose..."
    docker compose -p "$COMPOSE_PROJECT" -f "$REPO_ROOT/docker-compose.yml" down -v --remove-orphans 2>/dev/null || true
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
log "Building and starting Docker Compose stack..."
cd "$REPO_ROOT"
docker compose -p "$COMPOSE_PROJECT" -f docker-compose.yml build --quiet 2>/dev/null
docker compose -p "$COMPOSE_PROJECT" -f docker-compose.yml up -d 2>/dev/null

# --- Wait for cidrx to start and accept connections ---
log "Waiting for cidrx container to start..."
MAX_WAIT=30
for i in $(seq 1 $MAX_WAIT); do
    STATUS=$(docker compose -p "$COMPOSE_PROJECT" -f docker-compose.yml ps cidrx --format '{{.State}}' 2>/dev/null || echo "")
    if [ "$STATUS" = "running" ]; then
        break
    fi
    if [ "$i" -eq "$MAX_WAIT" ]; then
        fail "cidrx container did not start within ${MAX_WAIT}s"
        exit 1
    fi
    sleep 1
done
pass "cidrx container started"

# --- Wait for Filebeat connection ---
log "Waiting for Filebeat to connect..."
MAX_WAIT=60
for i in $(seq 1 $MAX_WAIT); do
    LOGS=$(docker compose -p "$COMPOSE_PROJECT" -f docker-compose.yml logs cidrx 2>/dev/null || echo "")
    if echo "$LOGS" | grep -q "Filebeat connected"; then
        pass "Filebeat connected"
        break
    fi
    if [ "$i" -eq "$MAX_WAIT" ]; then
        fail "Filebeat did not connect within ${MAX_WAIT}s"
    fi
    sleep 1
done

# --- Wait for detections to accumulate ---
# 10s max is enough: filebeat harvests within ~1s (scan_frequency 1s),
# iterations run every 1s, bans activate on the first detection, and even
# the smallest cluster (net2: 2 IPs at 0.1s interval = ~20 req/s) is far
# above min_size 50 from the first batch. Poll so fast machines exit early.
log "Waiting up to 10s for detections to accumulate..."
for i in $(seq 1 10); do
    BAN_PROBE=$(docker compose -p "$COMPOSE_PROJECT" -f docker-compose.yml exec -T cidrx cat /data/blocklist.txt 2>/dev/null || echo "")
    if [ -n "$BAN_PROBE" ]; then
        break
    fi
    sleep 1
done

# --- Test 1: Ban file exists and has entries ---
log "Test 1: Ban file analysis..."
BAN_CONTENT=$(docker compose -p "$COMPOSE_PROJECT" -f docker-compose.yml exec -T cidrx cat /data/blocklist.txt 2>/dev/null || echo "")
if [ -n "$BAN_CONTENT" ]; then
    BAN_COUNT=$(echo "$BAN_CONTENT" | wc -l)
    pass "Ban file has $BAN_COUNT entries"
    log "Ban file contents:"
    echo "$BAN_CONTENT" | while read -r line; do log "  $line"; done
else
    fail "Ban file empty after 10s"
fi

# --- Test 2: Net4 detection (33 clients, most aggressive) ---
log "Test 2: Net4 (172.16.16.0/24) detection..."
if [ -n "$BAN_CONTENT" ]; then
    if echo "$BAN_CONTENT" | grep -q "172.16.16"; then
        pass "Net4 cluster (172.16.16.x) detected"
    else
        fail "Net4 cluster (172.16.16.x) not detected - expected with 33 clients"
    fi
else
    fail "Cannot check net4 - ban file empty"
fi

# --- Test 3: Jail file structure ---
log "Test 3: Jail file validation..."
JAIL_CONTENT=$(docker compose -p "$COMPOSE_PROJECT" -f docker-compose.yml exec -T cidrx cat /data/jail.json 2>/dev/null || echo "")
if [ -n "$JAIL_CONTENT" ]; then
    JAIL_VALID=$(echo "$JAIL_CONTENT" | python3 -c "
import json, sys
try:
    j = json.load(sys.stdin)
    if isinstance(j, dict):
        print('valid')
    else:
        print('invalid_type')
except:
    print('invalid_json')
" 2>/dev/null || echo "error")

    if [ "$JAIL_VALID" = "valid" ]; then
        pass "Jail file is valid JSON dict"
    else
        fail "Jail file validation failed: $JAIL_VALID"
    fi

    # Count jail entries and verify structure
    JAIL_ANALYSIS=$(echo "$JAIL_CONTENT" | python3 -c "
import json, sys
j = json.load(sys.stdin)
total = len(j)
# Check if any entries are for net4
net4_entries = [k for k in j.keys() if '172.16.16' in k]
print(f'{total}:{len(net4_entries)}')
" 2>/dev/null || echo "0:0")

    JAIL_TOTAL="${JAIL_ANALYSIS%%:*}"
    JAIL_NET4="${JAIL_ANALYSIS##*:}"

    if [ "$JAIL_TOTAL" -gt 0 ]; then
        pass "Jail has $JAIL_TOTAL entries ($JAIL_NET4 from net4)"
    else
        log "NOTE: Jail has 0 entries (CIDRs may have progressed directly to ban)"
    fi
else
    fail "Jail file empty or not readable"
fi

# --- Test 4: live stats verification via /stats ---
log "Test 4: live stats via /stats endpoint..."
CIDRX_LOGS=$(docker compose -p "$COMPOSE_PROJECT" -f docker-compose.yml logs cidrx 2>/dev/null || echo "")

LOOP_STATS=$(curl -fsS http://localhost:8666/stats 2>/dev/null || echo "")
if [ -n "$LOOP_STATS" ]; then
    OUTPUT_ANALYSIS=$(echo "$LOOP_STATS" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    windows = d.get('windows') or []
    window_size = sum(w.get('requests', 0) for w in windows)
    requests_total = d.get('ingest', {}).get('requests_total', 0)
    detected = sum(
        len(cs.get('detected_now') or [])
        for w in windows
        for cs in (w.get('cluster_sets') or [])
    )
    active_bans = d.get('jail', {}).get('total_active', 0)
    ban_entries = d.get('lists', {}).get('ban_file', {}).get('entries', 0)
    print(f'{window_size}:{requests_total}:{detected}:{active_bans}:{ban_entries}')
except Exception as e:
    print(f'error:{e}')
" 2>/dev/null || echo "error:parse")

    if [[ "$OUTPUT_ANALYSIS" != error:* ]]; then
        IFS=':' read -r WINDOW_SIZE REQUESTS_TOTAL DETECTED ACTIVE_BANS BAN_ENTRIES <<< "$OUTPUT_ANALYSIS"

        if [ "$WINDOW_SIZE" -gt 0 ]; then
            pass "Sliding windows hold $WINDOW_SIZE requests"
        else
            fail "Sliding windows are empty"
        fi

        if [ "$REQUESTS_TOTAL" -gt 0 ]; then
            pass "Ingestor processed $REQUESTS_TOTAL requests in total"
        else
            fail "Ingestor processed 0 requests"
        fi

        if [ "$DETECTED" -gt 0 ]; then
            pass "Detected $DETECTED CIDRs in last cycle"
        else
            log "NOTE: 0 detected CIDRs in last cycle (may need more accumulation)"
        fi

        if [ "$ACTIVE_BANS" -gt 0 ]; then
            pass "Active bans: $ACTIVE_BANS (ban file entries: $BAN_ENTRIES)"
        else
            log "NOTE: 0 active bans in last cycle"
        fi
    else
        fail "Could not parse /stats JSON: $OUTPUT_ANALYSIS"
    fi
else
    fail "/stats not reachable for live stats verification"
fi

# --- Test 5: No panics or fatal errors ---
log "Test 5: Error checking..."
if echo "$CIDRX_LOGS" | grep -qi "panic"; then
    fail "cidrx logs contain panics"
    echo "$CIDRX_LOGS" | grep -i "panic" | head -5
else
    pass "No panics in cidrx logs"
fi

if echo "$CIDRX_LOGS" | grep -qi "fatal"; then
    fail "cidrx logs contain fatal errors"
else
    pass "No fatal errors in cidrx logs"
fi

# --- Test 6: All infrastructure containers running ---
log "Test 6: Infrastructure health..."
for SVC in proxy filebeat cidrx; do
    SVC_STATUS=$(docker compose -p "$COMPOSE_PROJECT" -f docker-compose.yml ps "$SVC" --format '{{.State}}' 2>/dev/null || echo "unknown")
    if [ "$SVC_STATUS" = "running" ]; then
        pass "$SVC container is running"
    else
        fail "$SVC container not running (state: $SVC_STATUS)"
    fi
done

# --- Test 7: Verify traffic-gen containers are producing traffic ---
log "Test 7: Client traffic verification..."
# Check the traffic generator of each network
SAMPLE_CLIENTS=("clients_net1" "clients_net2" "clients_net3" "clients_net4" "clients_net5")
for CLIENT in "${SAMPLE_CLIENTS[@]}"; do
    CLIENT_LOGS=$(docker compose -p "$COMPOSE_PROJECT" -f docker-compose.yml logs "$CLIENT" --tail=5 2>/dev/null || echo "")
    if echo "$CLIENT_LOGS" | grep -q "OK"; then
        pass "$CLIENT is producing traffic"
    else
        fail "$CLIENT is not producing traffic"
    fi
done

# --- Test 8: Stats endpoints reachable from the host ---
log "Test 8: Stats endpoints..."
STATS_JSON=$(curl -fsS http://localhost:8666/stats 2>/dev/null || echo "")
if [ -n "$STATS_JSON" ]; then
    STATS_VALID=$(echo "$STATS_JSON" | python3 -c "
import json, sys
try:
    j = json.load(sys.stdin)
    if isinstance(j, dict):
        print('valid')
    else:
        print('invalid_type')
except:
    print('invalid_json')
" 2>/dev/null || echo "error")
    if [ "$STATS_VALID" = "valid" ]; then
        pass "/stats returns valid JSON dict"
    else
        fail "/stats validation failed: $STATS_VALID"
    fi
else
    fail "/stats not reachable on http://localhost:8666/stats"
fi

# /bans may contain only header comments early on; HTTP success is enough.
if curl -fsS -o /dev/null http://localhost:8666/bans 2>/dev/null; then
    pass "/bans returns HTTP success"
else
    fail "/bans not reachable on http://localhost:8666/bans"
fi

# --- Test 9: Negative client never clustered ---
# clients_net5 (172.30.99.32) sends 1 request every 3s - far below min_size 50.
# Test 7 already proved clients_net5 IS producing traffic, so its absence from
# the ban and jail files is meaningful: cidrx does not ban benign low-rate IPs.
log "Test 9: Negative client (172.30.99.x) exclusion..."
BAN_CONTENT=$(docker compose -p "$COMPOSE_PROJECT" -f docker-compose.yml exec -T cidrx cat /data/blocklist.txt 2>/dev/null || echo "")
if echo "$BAN_CONTENT" | grep -q "172.30.99"; then
    fail "Negative client (172.30.99.x) found in ban file"
else
    pass "Negative client (172.30.99.x) not in ban file"
fi

JAIL_CONTENT=$(docker compose -p "$COMPOSE_PROJECT" -f docker-compose.yml exec -T cidrx cat /data/jail.json 2>/dev/null || echo "")
if echo "$JAIL_CONTENT" | grep -q "172.30.99"; then
    fail "Negative client (172.30.99.x) found in jail file"
else
    pass "Negative client (172.30.99.x) not in jail file"
fi

# --- Summary ---
log "============================="
log "Results: $PASS passed, $FAIL failed"
log "============================="

[ "$FAIL" -eq 0 ]
