#!/usr/bin/env bash
# E2E test: live analysis mode (Docker Compose)
# Starts the full stack (proxy, cidrx, filebeat, clients),
# waits for data to accumulate, then checks cidrx's output for detections.
#
# cidrx uses TCP Lumberjack v2 protocol on port 9000 (not HTTP).
# Health checking is done via container logs and ban/jail file inspection.
#
# Expected Docker network layout:
#   net1: 172.16.1.32-35  (4 clients,  0.1s interval)
#   net2: 172.16.2.32-33  (2 clients,  0.1s interval)
#   net3: 172.16.3.32-36  (5 clients,  0.1s interval)
#   net4: 172.16.16.32-64 (33 clients, 0.07s interval)
#
# Prerequisites: docker and docker compose must be available.
# This test takes ~90-120 seconds to run.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

PASS=0
FAIL=0
COMPOSE_PROJECT="cidrx-e2e-$$"

log() { printf "[e2e-live] %s\n" "$*"; }
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

# --- Wait for cidrx container to be running ---
log "Waiting for cidrx container to start..."
MAX_WAIT=30
for i in $(seq 1 $MAX_WAIT); do
    STATUS=$(docker compose -p "$COMPOSE_PROJECT" -f docker-compose.yml ps cidrx --format '{{.State}}' 2>/dev/null || echo "")
    if [ "$STATUS" = "running" ]; then
        break
    fi
    if [ "$i" -eq "$MAX_WAIT" ]; then
        fail "cidrx container did not start within ${MAX_WAIT}s (state: $STATUS)"
        exit 1
    fi
    sleep 1
done
pass "cidrx container is running"

# --- Wait for cidrx to output "Filebeat connected" ---
log "Waiting for Filebeat to connect to cidrx..."
MAX_WAIT=60
CONNECTED=false
for i in $(seq 1 $MAX_WAIT); do
    LOGS=$(docker compose -p "$COMPOSE_PROJECT" -f docker-compose.yml logs cidrx 2>/dev/null || echo "")
    if echo "$LOGS" | grep -q "Filebeat connected"; then
        CONNECTED=true
        break
    fi
    if [ "$i" -eq "$MAX_WAIT" ]; then
        log "WARNING: Filebeat connection not confirmed in logs within ${MAX_WAIT}s"
        log "Last cidrx logs:"
        echo "$LOGS" | tail -5
    fi
    sleep 1
done
if [ "$CONNECTED" = "true" ]; then
    pass "Filebeat connected to cidrx"
else
    fail "Filebeat connection not confirmed"
fi

# --- Let traffic accumulate ---
log "Waiting 60s for traffic to accumulate and clusters to form..."
sleep 60

# --- Check ban file for detections ---
log "Checking ban file..."
BAN_CONTENT=$(docker compose -p "$COMPOSE_PROJECT" -f docker-compose.yml exec -T cidrx cat /data/blocklist.txt 2>/dev/null || echo "")
if [ -n "$BAN_CONTENT" ]; then
    BAN_COUNT=$(echo "$BAN_CONTENT" | wc -l)
    pass "Ban file has $BAN_COUNT entries"

    # net4 (172.16.16.0/24) is the largest cluster (33 clients at 0.07s)
    # It should be detected by aggressive_detection
    if echo "$BAN_CONTENT" | grep -q "172.16.16"; then
        pass "Ban file contains net4 (172.16.16.x) detections"
    else
        log "NOTE: net4 (172.16.16.x) not yet in ban file - may need more time"
    fi
else
    log "NOTE: Ban file empty (may need more time for cluster detection)"
fi

# --- Check jail file ---
log "Checking jail file..."
JAIL_CONTENT=$(docker compose -p "$COMPOSE_PROJECT" -f docker-compose.yml exec -T cidrx cat /data/jail.json 2>/dev/null || echo "")
if [ -n "$JAIL_CONTENT" ]; then
    VALID_JSON=$(echo "$JAIL_CONTENT" | python3 -c "import json, sys; json.load(sys.stdin); print('yes')" 2>/dev/null || echo "no")
    if [ "$VALID_JSON" = "yes" ]; then
        pass "Jail file is valid JSON"

        # Check jail has entries
        JAIL_ENTRIES=$(echo "$JAIL_CONTENT" | python3 -c "
import json, sys
j = json.load(sys.stdin)
print(len(j))
" 2>/dev/null || echo "0")
        if [ "$JAIL_ENTRIES" -gt 0 ]; then
            pass "Jail file has $JAIL_ENTRIES entries"
        else
            log "NOTE: Jail file has 0 entries - may need more time"
        fi
    else
        fail "Jail file is not valid JSON"
    fi
else
    fail "Jail file empty or not readable"
fi

# --- Wait longer if needed for more detections ---
log "Waiting additional 30s for more detections..."
sleep 30

# --- Re-check ban and jail files after additional wait ---
BAN_CONTENT2=$(docker compose -p "$COMPOSE_PROJECT" -f docker-compose.yml exec -T cidrx cat /data/blocklist.txt 2>/dev/null || echo "")
JAIL_CONTENT2=$(docker compose -p "$COMPOSE_PROJECT" -f docker-compose.yml exec -T cidrx cat /data/jail.json 2>/dev/null || echo "")

# Diagnostic: show what was actually detected
if [ -n "$BAN_CONTENT2" ]; then
    BAN_COUNT2=$(echo "$BAN_CONTENT2" | wc -l)
    log "Ban file ($BAN_COUNT2 entries):"
    echo "$BAN_CONTENT2" | while read -r line; do log "  ban: $line"; done
fi
if [ -n "$JAIL_CONTENT2" ]; then
    python3 -c "
import json, sys
j = json.load(sys.stdin)
for cell in j.get('Cells', []):
    for p in cell.get('Prisoners', []):
        print(f\"  jail cell {cell['Id']}: {p['Cidr']} active={p['BanActive']}\")
" <<< "$JAIL_CONTENT2" 2>/dev/null | while read -r line; do log "$line"; done
fi

# Verify detections are happening (ban file has entries OR jail has prisoners)
BAN_ENTRIES=0
JAIL_PRISONERS=0
if [ -n "$BAN_CONTENT2" ]; then
    BAN_ENTRIES=$(echo "$BAN_CONTENT2" | wc -l)
fi
if [ -n "$JAIL_CONTENT2" ]; then
    JAIL_PRISONERS=$(echo "$JAIL_CONTENT2" | python3 -c "
import json, sys
j = json.load(sys.stdin)
total = sum(len(c.get('Prisoners',[])) for c in j.get('Cells',[]))
print(total)
" 2>/dev/null || echo "0")
fi

if [ "$BAN_ENTRIES" -gt 0 ] || [ "$JAIL_PRISONERS" -gt 0 ]; then
    pass "Detections found: $BAN_ENTRIES ban entries, $JAIL_PRISONERS jail prisoners"
else
    fail "No detections in ban or jail files after 90s"
fi

# Check for 172.16.x detections (any of the client networks)
FOUND_172_16=false
if [ -n "$BAN_CONTENT2" ] && echo "$BAN_CONTENT2" | grep -q "172.16"; then
    FOUND_172_16=true
fi
if [ -n "$JAIL_CONTENT2" ] && echo "$JAIL_CONTENT2" | grep -q "172.16"; then
    FOUND_172_16=true
fi
if [ "$FOUND_172_16" = "true" ]; then
    pass "Client network (172.16.x) detected in ban or jail"
else
    # Check cidrx output logs as fallback
    DETECT_LOGS=$(docker compose -p "$COMPOSE_PROJECT" -f docker-compose.yml logs cidrx 2>/dev/null || echo "")
    if echo "$DETECT_LOGS" | grep -q "172.16"; then
        pass "Client network (172.16.x) detected in cidrx output"
    else
        fail "Client network (172.16.x) NOT detected anywhere after 90s"
    fi
fi

# --- Check cidrx iteration log lines for detection data ---
log "Checking cidrx logs for iteration summaries..."
CIDRX_LOGS=$(docker compose -p "$COMPOSE_PROJECT" -f docker-compose.yml logs cidrx 2>/dev/null || echo "")

# cidrx logs one leveled summary line per loop iteration to stderr
if echo "$CIDRX_LOGS" | grep 'msg=iteration' | grep -qE 'detected=[1-9]'; then
    pass "cidrx logged iterations with detections"
elif echo "$CIDRX_LOGS" | grep -q 'msg=iteration'; then
    pass "cidrx logged iteration summaries"
else
    fail "No iteration log lines found in cidrx logs"
fi

# --- Check for panics or fatal errors ---
if echo "$CIDRX_LOGS" | grep -qi "panic"; then
    fail "cidrx logs contain panics"
else
    pass "No panics in cidrx logs"
fi

if echo "$CIDRX_LOGS" | grep -qi "fatal"; then
    fail "cidrx logs contain fatal errors"
else
    pass "No fatal errors in cidrx logs"
fi

# --- Verify proxy is serving traffic ---
log "Checking proxy health..."
PROXY_STATUS=$(docker compose -p "$COMPOSE_PROJECT" -f docker-compose.yml ps proxy --format '{{.State}}' 2>/dev/null || echo "")
if [ "$PROXY_STATUS" = "running" ]; then
    pass "Proxy container is running"
else
    fail "Proxy container not running (state: $PROXY_STATUS)"
fi

# --- Verify filebeat is running ---
FILEBEAT_STATUS=$(docker compose -p "$COMPOSE_PROJECT" -f docker-compose.yml ps filebeat --format '{{.State}}' 2>/dev/null || echo "")
if [ "$FILEBEAT_STATUS" = "running" ]; then
    pass "Filebeat container is running"
else
    fail "Filebeat container not running (state: $FILEBEAT_STATUS)"
fi

# --- Summary ---
log "============================="
log "Results: $PASS passed, $FAIL failed"
log "============================="

[ "$FAIL" -eq 0 ]
