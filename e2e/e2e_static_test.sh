#!/usr/bin/env bash
# E2E test: static analysis mode
# Builds the Go binary, generates a test log, runs static analysis,
# and verifies the JSON output contains expected clusters.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SRC_DIR="$REPO_ROOT/flokbn/src"

PASS=0
FAIL=0
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

log() { printf "[e2e-static] %s\n" "$*"; }
pass() { PASS=$((PASS + 1)); log "PASS: $1"; }
fail() { FAIL=$((FAIL + 1)); log "FAIL: $1"; }

LOG_FORMAT='%h %^ %^ [%t] "%r" %s %b "%^" "%u"'

# --- Build ---
log "Building flokbn binary..."
(cd "$SRC_DIR" && go build -o "$TMPDIR/flokbn" .)

# --- Generate test log ---
log "Generating test log file..."
LOG_FILE="$TMPDIR/test.log"
{
    # 5000 IPs in 10.20.0.0/16 (should form a cluster)
    for i in $(seq 1 5000); do
        o3=$(( i / 256 ))
        o4=$(( i % 256 ))
        printf '10.20.%d.%d - - [01/Feb/2025:00:00:00 +0000] "GET / HTTP/1.1" 200 100 "-" "test"\n' "$o3" "$o4"
    done
    # 2000 IPs in 192.168.0.0/18 (should form a cluster)
    for i in $(seq 1 2000); do
        o3=$(( i / 256 ))
        o4=$(( i % 256 ))
        printf '192.168.%d.%d - - [01/Feb/2025:00:00:00 +0000] "GET / HTTP/1.1" 200 100 "-" "test"\n' "$o3" "$o4"
    done
    # 3000 noise IPs spread across many /8s
    for i in $(seq 1 3000); do
        o1=$(( 40 + i / 1000 ))
        o2=$(( (i % 1000) / 4 ))
        o3=$(( i % 4 ))
        o4=$(( (i * 7 % 254) + 1 ))
        printf '%d.%d.%d.%d - - [01/Feb/2025:00:00:00 +0000] "GET / HTTP/1.1" 200 100 "-" "test"\n' "$o1" "$o2" "$o3" "$o4"
    done
} > "$LOG_FILE"

TOTAL_LINES=$(wc -l < "$LOG_FILE")
log "Generated $TOTAL_LINES log lines"

# --- Run static analysis (JSON output is the default) ---
log "Running static analysis (JSON)..."
JSON_FILE="$TMPDIR/result.json"
"$TMPDIR/flokbn" static \
    --logfile "$LOG_FILE" \
    --logFormat "$LOG_FORMAT" \
    --clusterArgSets 1000,16,24,0.2 \
    --clusterArgSets 500,24,32,0.1 \
    --rangesCidr 10.20.0.0/16 \
    --rangesCidr 192.168.0.0/16 \
    > "$JSON_FILE" 2>/dev/null

# --- Verify JSON output ---
if [ ! -s "$JSON_FILE" ]; then
    fail "JSON output is empty"
else
    pass "JSON output is non-empty"
fi

# Check that totalRequests is reasonable (snake_case JSON keys)
TOTAL_REQ=$(python3 -c "import json; d=json.load(open('$JSON_FILE')); print(d['general']['total_requests'])" 2>/dev/null || echo "0")
if [ "$TOTAL_REQ" -gt 9000 ]; then
    pass "Total requests ($TOTAL_REQ) >= 9000"
else
    fail "Total requests ($TOTAL_REQ) < 9000"
fi

# Check CIDR range analysis for 10.20.0.0/16
RANGE_10_COUNT=$(python3 -c "
import json
d = json.load(open('$JSON_FILE'))
for t in d.get('tries', []):
    for ca in t.get('stats', {}).get('cidr_analysis', []):
        if ca['cidr'] == '10.20.0.0/16':
            print(ca['requests'])
            break
" 2>/dev/null || echo "0")
if [ "${RANGE_10_COUNT:-0}" -gt 4000 ] 2>/dev/null; then
    pass "10.20.0.0/16 range has $RANGE_10_COUNT requests"
else
    fail "10.20.0.0/16 range has ${RANGE_10_COUNT:-0} requests (expected > 4000)"
fi

# Check that clusters were detected
CLUSTER_COUNT=$(python3 -c "
import json
d = json.load(open('$JSON_FILE'))
total = 0
for t in d.get('tries', []):
    for cl in t.get('data', []):
        total += len(cl.get('detected_ranges', []))
print(total)
" 2>/dev/null || echo "0")
if [ "$CLUSTER_COUNT" -gt 0 ]; then
    pass "Detected $CLUSTER_COUNT cluster ranges"
else
    fail "No cluster ranges detected"
fi

# Check that a 10.20.x.x cluster was found
FOUND_10_20=$(python3 -c "
import json
d = json.load(open('$JSON_FILE'))
for t in d.get('tries', []):
    for cl in t.get('data', []):
        for r in cl.get('detected_ranges', []):
            if r['cidr'].startswith('10.20.'):
                print('yes')
                exit()
print('no')
" 2>/dev/null || echo "no")
if [ "$FOUND_10_20" = "yes" ]; then
    pass "Found cluster in 10.20.x.x range"
else
    fail "No cluster found in 10.20.x.x range"
fi

# --- Plain text output test ---
log "Running plain text output..."
PLAIN_FILE="$TMPDIR/result.txt"
"$TMPDIR/flokbn" static \
    --logfile "$LOG_FILE" \
    --logFormat "$LOG_FORMAT" \
    --clusterArgSets 1000,16,24,0.2 \
    --plain > "$PLAIN_FILE" 2>/dev/null

if [ -s "$PLAIN_FILE" ]; then
    pass "Plain text output is non-empty"
else
    fail "Plain text output is empty"
fi

if grep -q "flokbn Analysis Results" "$PLAIN_FILE"; then
    pass "Plain text output contains expected header"
else
    fail "Plain text output missing expected header"
fi

# --- Summary ---
log "============================="
log "Results: $PASS passed, $FAIL failed"
log "============================="

# Clean up binary
rm -f "$TMPDIR/flokbn"

[ "$FAIL" -eq 0 ]
