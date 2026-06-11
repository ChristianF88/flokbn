#!/usr/bin/env bash
# E2E test: live mode multi-trie detection verification
# Verifies that the Docker Compose setup with 4 client networks produces
# expected clustering detections across multiple detection tries.
#
# Docker network layout (from docker-compose.yml). One traffic-gen container
# per subnet simulates all client IPs via secondary addresses:
#   net1: 172.16.1.32-35  (clients_net1: 4 IPs,  0.1s interval)  -> curl UA, GET /
#   net2: 172.16.2.32-33  (clients_net2: 2 IPs,  0.1s interval)  -> curl UA, GET /
#   net3: 172.16.3.32-36  (clients_net3: 5 IPs,  0.1s interval)  -> curl UA, GET /
#   net4: 172.16.16.32-64 (clients_net4: 33 IPs, 0.07s interval) -> curl UA, GET /
#
# Detection config (from docker-test-config.toml):
#   general_detection:    min_size=2,  depth 24-32, threshold 0.2
#   aggressive_detection: min_size=10, depth 20-28, threshold 0.15
#                         min_size=20, depth 16-24, threshold 0.2
#
# Prerequisites: docker and docker compose must be available.
# This test takes ~120-150 seconds to run.
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
# With 44 clients total, net4 at 0.07s interval = ~14 req/s/client = ~462 req/s
# 5-minute sliding window should accumulate enough data within 60-90 seconds
log "Waiting 90s for detections to accumulate..."
sleep 90

# --- Test 1: Ban file exists and has entries ---
log "Test 1: Ban file analysis..."
BAN_CONTENT=$(docker compose -p "$COMPOSE_PROJECT" -f docker-compose.yml exec -T cidrx cat /data/blocklist.txt 2>/dev/null || echo "")
if [ -n "$BAN_CONTENT" ]; then
    BAN_COUNT=$(echo "$BAN_CONTENT" | wc -l)
    pass "Ban file has $BAN_COUNT entries"
    log "Ban file contents:"
    echo "$BAN_CONTENT" | while read -r line; do log "  $line"; done
else
    fail "Ban file empty after 90s"
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

# --- Test 4: cidrx JSON output analysis ---
log "Test 4: cidrx output analysis..."
CIDRX_LOGS=$(docker compose -p "$COMPOSE_PROJECT" -f docker-compose.yml logs cidrx 2>/dev/null || echo "")

# Extract the last JSON output line (most recent detection cycle)
# Docker compose logs prefix with "cidrx  | ", strip that first
LAST_JSON=$(echo "$CIDRX_LOGS" | sed 's/^cidrx[[:space:]]*|[[:space:]]*//' | grep -o '{.*}' | tail -1 || echo "")
if [ -n "$LAST_JSON" ]; then
    OUTPUT_ANALYSIS=$(echo "$LAST_JSON" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    ls = d.get('live_stats', {})
    window_size = ls.get('window_size', 0)
    batch_size = ls.get('processed_batch', 0)
    detected = len(ls.get('detected_cidrs', []))
    merged = len(ls.get('merged_cidrs', []))
    active_bans = len(ls.get('active_bans', []))
    print(f'{window_size}:{batch_size}:{detected}:{merged}:{active_bans}')
except Exception as e:
    print(f'error:{e}')
" 2>/dev/null || echo "error:parse")

    if [[ "$OUTPUT_ANALYSIS" != error:* ]]; then
        IFS=':' read -r WINDOW_SIZE BATCH_SIZE DETECTED MERGED ACTIVE_BANS <<< "$OUTPUT_ANALYSIS"

        if [ "$WINDOW_SIZE" -gt 0 ]; then
            pass "Sliding window has $WINDOW_SIZE entries"
        else
            fail "Sliding window is empty"
        fi

        if [ "$BATCH_SIZE" -gt 0 ]; then
            pass "Last batch processed $BATCH_SIZE events"
        else
            log "NOTE: Last batch had 0 events (may be between batches)"
        fi

        if [ "$DETECTED" -gt 0 ]; then
            pass "Detected $DETECTED CIDRs in last cycle"
        else
            log "NOTE: 0 detected CIDRs in last cycle (may need more accumulation)"
        fi

        if [ "$ACTIVE_BANS" -gt 0 ]; then
            pass "Active bans: $ACTIVE_BANS"
        else
            log "NOTE: 0 active bans in last cycle"
        fi
    else
        log "NOTE: Could not parse cidrx JSON output"
    fi
else
    log "NOTE: No JSON output found in cidrx logs"
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
SAMPLE_CLIENTS=("clients_net1" "clients_net2" "clients_net3" "clients_net4")
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

# --- Summary ---
log "============================="
log "Results: $PASS passed, $FAIL failed"
log "============================="

[ "$FAIL" -eq 0 ]
