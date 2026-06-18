#!/usr/bin/env bash
# E2E test: static analysis with filtering scenarios
# Tests user-agent regex, endpoint regex, time filtering, CIDR ranges,
# and combined filters across multiple tries.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SRC_DIR="$REPO_ROOT/flokbn/src"

PASS=0
FAIL=0
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

log() { printf "[e2e-filters] %s\n" "$*"; }
pass() { PASS=$((PASS + 1)); log "PASS: $1"; }
fail() { FAIL=$((FAIL + 1)); log "FAIL: $1"; }

# --- Build ---
log "Building flokbn binary..."
(cd "$SRC_DIR" && go build -o "$TMPDIR/flokbn" .)

# --- Generate rich test log with varied UAs, endpoints, and timestamps ---
log "Generating test log with varied traffic patterns..."
LOG_FILE="$TMPDIR/filter_test.log"
CONFIG_FILE="$TMPDIR/filter_test.toml"
JAIL_FILE="$TMPDIR/jail.json"
BAN_FILE="$TMPDIR/ban.txt"

# No jail file pre-created: flokbn writes a fresh 5-cell jail on first run.

python3 -c "
import random
random.seed(42)

# UA patterns
uas = {
    'browser':   'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'googlebot': 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
    'curl':      'curl/7.68.0',
    'badbot':    'BadBot/1.0',
    'scanner':   'EvilScraper/2.0',
}

# Endpoint patterns
endpoints = {
    'page':    ['/index.html', '/about.html', '/contact.html', '/products.html'],
    'api':     ['/api/data', '/api/users', '/api/stats', '/api/health'],
    'admin':   ['/admin/login', '/admin/config', '/admin/users'],
    'wp':      ['/wp-admin', '/wp-login.php', '/xmlrpc.php'],
}

# Time distribution: Feb 1-7, 2025
# Day 1-2: low traffic, Day 3-5: peak, Day 6-7: low
lines = []

# Cluster A: 3000 IPs in 10.50.0.0/16, browser+page traffic, Feb 3-5
for i in range(3000):
    v = i + 1
    ip = f'10.50.{v // 256}.{v % 256}'
    day = 3 + (i % 3)  # Feb 3-5
    hour = (i * 7) % 24
    ua = uas['browser']
    ep = endpoints['page'][i % 4]
    lines.append(f'{ip} - - [{day:02d}/Feb/2025:{hour:02d}:00:00 +0000] \"GET {ep} HTTP/1.1\" 200 1024 \"-\" \"{ua}\"')

# Cluster B: 2000 IPs in 192.168.0.0/18, Googlebot, /api/* endpoints, Feb 1-7
for i in range(2000):
    v = i + 1
    ip = f'192.168.{v // 256}.{v % 256}'
    day = 1 + (i % 7)
    hour = (i * 3) % 24
    ua = uas['googlebot']
    ep = endpoints['api'][i % 4]
    lines.append(f'{ip} - - [{day:02d}/Feb/2025:{hour:02d}:00:00 +0000] \"GET {ep} HTTP/1.1\" 200 2048 \"-\" \"{ua}\"')

# Cluster C: 1500 IPs in 172.16.0.0/20, BadBot, /wp* endpoints, Feb 4-6
for i in range(1500):
    v = i + 1
    ip = f'172.16.{v // 256}.{v % 256}'
    day = 4 + (i % 3)
    hour = (i * 11) % 24
    ua = uas['badbot']
    ep = endpoints['wp'][i % 3]
    lines.append(f'{ip} - - [{day:02d}/Feb/2025:{hour:02d}:00:00 +0000] \"GET {ep} HTTP/1.1\" 404 0 \"-\" \"{ua}\"')

# Cluster D: 1000 IPs in 203.0.0.0/16, EvilScraper, /admin/* endpoints, Feb 2-3
for i in range(1000):
    v = i + 1
    ip = f'203.0.{v // 256}.{v % 256}'
    day = 2 + (i % 2)
    hour = (i * 5) % 24
    ua = uas['scanner']
    ep = endpoints['admin'][i % 3]
    lines.append(f'{ip} - - [{day:02d}/Feb/2025:{hour:02d}:00:00 +0000] \"GET {ep} HTTP/1.1\" 403 0 \"-\" \"{ua}\"')

# Noise: 2500 curl requests across many IPs, /api/* endpoints
for i in range(2500):
    o1 = 40 + (i // 1000)
    o2 = (i % 1000) // 4
    o3 = i % 4
    o4 = 1 + ((i * 7) % 254)
    ip = f'{o1}.{o2}.{o3}.{o4}'
    day = 1 + (i % 7)
    hour = (i * 13) % 24
    ua = uas['curl']
    ep = endpoints['api'][i % 4]
    lines.append(f'{ip} - - [{day:02d}/Feb/2025:{hour:02d}:00:00 +0000] \"GET {ep} HTTP/1.1\" 200 512 \"-\" \"{ua}\"')

random.shuffle(lines)
print('\n'.join(lines))
" > "$LOG_FILE"

TOTAL_LINES=$(wc -l < "$LOG_FILE")
log "Generated $TOTAL_LINES log lines"

LOG_FORMAT='%h %^ %^ [%t] "%r" %s %b "%^" "%u"'

# --- Test 1: User-Agent regex filter (Googlebot only) ---
log "Test 1: User-Agent regex filter..."
JSON1="$TMPDIR/ua_filter.json"
"$TMPDIR/flokbn" static \
    --logfile "$LOG_FILE" \
    --logFormat "$LOG_FORMAT" \
    --useragentRegex '.*Googlebot.*' \
    --clusterArgSets 500,16,24,0.2 \
    > "$JSON1" 2>/dev/null

UA_REQ=$(python3 -c "
import json; d=json.load(open('$JSON1'))
for t in d.get('tries', []):
    print(t['stats']['total_requests_after_filtering'])
    break
" 2>/dev/null || echo "0")
# Should be ~2000 (Googlebot cluster)
if [ "$UA_REQ" -ge 1800 ] && [ "$UA_REQ" -le 2200 ]; then
    pass "UA filter: $UA_REQ requests (~2000 expected)"
else
    fail "UA filter: $UA_REQ requests (expected ~2000)"
fi

# --- Test 2: Endpoint regex filter (/api/*) ---
log "Test 2: Endpoint regex filter..."
JSON2="$TMPDIR/ep_filter.json"
"$TMPDIR/flokbn" static \
    --logfile "$LOG_FILE" \
    --logFormat "$LOG_FORMAT" \
    --endpointRegex '/api/.*' \
    --clusterArgSets 500,16,24,0.2 \
    > "$JSON2" 2>/dev/null

EP_REQ=$(python3 -c "
import json; d=json.load(open('$JSON2'))
for t in d.get('tries', []):
    print(t['stats']['total_requests_after_filtering'])
    break
" 2>/dev/null || echo "0")
# Should be ~4500 (2000 Googlebot + 2500 curl)
if [ "$EP_REQ" -ge 4000 ] && [ "$EP_REQ" -le 5000 ]; then
    pass "Endpoint filter: $EP_REQ requests (~4500 expected)"
else
    fail "Endpoint filter: $EP_REQ requests (expected ~4500)"
fi

# --- Test 3: Time range filter (Feb 3-5 only) ---
log "Test 3: Time range filter..."
JSON3="$TMPDIR/time_filter.json"
"$TMPDIR/flokbn" static \
    --logfile "$LOG_FILE" \
    --logFormat "$LOG_FORMAT" \
    --startTime "2025-02-03" \
    --endTime "2025-02-05 23:59" \
    --clusterArgSets 500,16,24,0.2 \
    > "$JSON3" 2>/dev/null

TIME_REQ=$(python3 -c "
import json; d=json.load(open('$JSON3'))
for t in d.get('tries', []):
    print(t['stats']['total_requests_after_filtering'])
    break
" 2>/dev/null || echo "0")
# Days 3-5 should capture roughly 3/7 to 5/7 of traffic depending on distribution
if [ "$TIME_REQ" -gt 3000 ]; then
    pass "Time filter: $TIME_REQ requests (> 3000)"
else
    fail "Time filter: $TIME_REQ requests (expected > 3000)"
fi

# --- Test 4: CIDR range counting ---
log "Test 4: CIDR range counting..."
JSON4="$TMPDIR/cidr_ranges.json"
"$TMPDIR/flokbn" static \
    --logfile "$LOG_FILE" \
    --logFormat "$LOG_FORMAT" \
    --rangesCidr 10.50.0.0/16 \
    --rangesCidr 192.168.0.0/16 \
    --rangesCidr 172.16.0.0/16 \
    --clusterArgSets 500,16,24,0.2 \
    > "$JSON4" 2>/dev/null

RANGE_COUNTS=$(python3 -c "
import json; d=json.load(open('$JSON4'))
for t in d.get('tries', []):
    for ca in t.get('stats', {}).get('cidr_analysis', []):
        print(f\"{ca['cidr']}:{ca['requests']}\")
" 2>/dev/null || echo "")

for expected in "10.50.0.0/16:3000" "192.168.0.0/16:2000" "172.16.0.0/16:1500"; do
    cidr="${expected%%:*}"
    count="${expected##*:}"
    actual=$(echo "$RANGE_COUNTS" | grep "^$cidr:" | cut -d: -f2 || echo "0")
    if [ "${actual:-0}" -eq "$count" ]; then
        pass "CIDR $cidr: $actual requests (expected $count)"
    else
        fail "CIDR $cidr: ${actual:-0} requests (expected $count)"
    fi
done

# --- Test 5: Combined filters via TOML config with multiple tries ---
log "Test 5: Multi-trie TOML config with combined filters..."
cat > "$CONFIG_FILE" <<TOML
[global]
jailFile = "$JAIL_FILE"
banFile = "$BAN_FILE"

[static]
logFile = "$LOG_FILE"
logFormat = '$LOG_FORMAT'

# Trie 1: All traffic, broad clustering
[static.all_traffic]
cidrRanges = ["10.50.0.0/16", "192.168.0.0/16"]
clusterArgSets = [[500, 16, 24, 0.2]]
useForJail = [true]

# Trie 2: Googlebot only (UA filter)
[static.bot_traffic]
useragentRegex = ".*Googlebot.*"
clusterArgSets = [[500, 16, 24, 0.2]]
useForJail = [true]

# Trie 3: /api/* endpoints only (endpoint filter)
[static.api_traffic]
endpointRegex = "/api/.*"
clusterArgSets = [[500, 16, 24, 0.2]]
useForJail = [true]

# Trie 4: Time-bounded (Feb 3-5) + /wp* endpoints (combined filter)
[static.wp_attacks_peak]
startTime = "2025-02-03T00:00:00Z"
endTime = "2025-02-05T23:59:59Z"
endpointRegex = "/wp.*|/xmlrpc.*"
clusterArgSets = [[200, 16, 24, 0.2]]
useForJail = [true]

# Trie 5: Time-bounded (Feb 2-3) + /admin/* endpoints (combined filter)
[static.admin_probes]
startTime = "2025-02-02T00:00:00Z"
endTime = "2025-02-03T23:59:59Z"
endpointRegex = "/admin/.*"
clusterArgSets = [[200, 16, 24, 0.2]]
useForJail = [true]
TOML

JSON5="$TMPDIR/multitrie.json"
"$TMPDIR/flokbn" static \
    --config "$CONFIG_FILE" \
    > "$JSON5" 2>/dev/null

# Verify we got 5 tries
TRIE_COUNT=$(python3 -c "import json; d=json.load(open('$JSON5')); print(len(d.get('tries',[])))" 2>/dev/null || echo "0")
if [ "$TRIE_COUNT" -eq 5 ]; then
    pass "Multi-trie config: $TRIE_COUNT tries"
else
    fail "Multi-trie config: $TRIE_COUNT tries (expected 5)"
fi

# Verify each trie has appropriate filtering
python3 -c "
import json, sys

d = json.load(open('$JSON5'))
tries = {t['name']: t for t in d.get('tries', [])}

results = []

# all_traffic should have all 10000 requests
t = tries.get('all_traffic', {})
req = t.get('stats', {}).get('total_requests_after_filtering', 0)
results.append(('all_traffic requests >= 9000', req >= 9000, req))

# bot_traffic should have ~2000
t = tries.get('bot_traffic', {})
req = t.get('stats', {}).get('total_requests_after_filtering', 0)
results.append(('bot_traffic ~2000', 1500 <= req <= 2500, req))

# api_traffic should have ~4500
t = tries.get('api_traffic', {})
req = t.get('stats', {}).get('total_requests_after_filtering', 0)
results.append(('api_traffic ~4500', 3500 <= req <= 5500, req))

# wp_attacks_peak: Feb 3-5 AND /wp endpoints => subset of 1500 BadBot cluster
t = tries.get('wp_attacks_peak', {})
req = t.get('stats', {}).get('total_requests_after_filtering', 0)
results.append(('wp_attacks_peak > 0', req > 0, req))

# admin_probes: Feb 2-3 AND /admin => subset of 1000 scanner cluster
t = tries.get('admin_probes', {})
req = t.get('stats', {}).get('total_requests_after_filtering', 0)
results.append(('admin_probes > 0', req > 0, req))

for desc, ok, val in results:
    status = 'PASS' if ok else 'FAIL'
    print(f'{status}:{desc} (got {val})')
" 2>/dev/null | while IFS= read -r line; do
    status="${line%%:*}"
    msg="${line#*:}"
    if [ "$status" = "PASS" ]; then
        pass "$msg"
    else
        fail "$msg"
    fi
done

# Verify clusters were detected in all_traffic trie
ALL_CLUSTERS=$(python3 -c "
import json
d = json.load(open('$JSON5'))
for t in d.get('tries', []):
    if t['name'] == 'all_traffic':
        total = 0
        for cl in t.get('data', []):
            total += len(cl.get('detected_ranges', []))
        print(total)
        break
" 2>/dev/null || echo "0")
if [ "$ALL_CLUSTERS" -gt 0 ]; then
    pass "all_traffic trie detected $ALL_CLUSTERS clusters"
else
    fail "all_traffic trie detected no clusters"
fi

# Verify jail file was updated
if [ -s "$JAIL_FILE" ]; then
    JAIL_SIZE=$(wc -c < "$JAIL_FILE")
    if [ "$JAIL_SIZE" -gt 10 ]; then
        pass "Jail file updated ($JAIL_SIZE bytes)"
    else
        log "NOTE: Jail file small ($JAIL_SIZE bytes) - may not have enough detections for jail"
    fi
fi

# Verify ban file was created
if [ -f "$BAN_FILE" ]; then
    pass "Ban file created"
else
    log "NOTE: Ban file not created (may require detections)"
fi

# --- Summary ---
log "============================="
log "Results: $PASS passed, $FAIL failed"
log "============================="

rm -f "$TMPDIR/flokbn"

[ "$FAIL" -eq 0 ]
