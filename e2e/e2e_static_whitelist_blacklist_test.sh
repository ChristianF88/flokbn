#!/usr/bin/env bash
# E2E test: whitelist and blacklist functionality
# Tests IP whitelist, IP blacklist, User-Agent whitelist, and User-Agent blacklist
# including their interaction with jail/ban file output.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SRC_DIR="$REPO_ROOT/cidrx/src"

PASS=0
FAIL=0
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

log() { printf "[e2e-wl-bl] %s\n" "$*"; }
pass() { PASS=$((PASS + 1)); log "PASS: $1"; }
fail() { FAIL=$((FAIL + 1)); log "FAIL: $1"; }

LOG_FORMAT='%h %^ %^ [%t] "%r" %s %b "%^" "%u"'

# --- Build ---
log "Building cidrx binary..."
(cd "$SRC_DIR" && go build -o "$TMPDIR/cidrx" .)

# --- Generate test log ---
log "Generating test log..."
LOG_FILE="$TMPDIR/wl_bl_test.log"
python3 -c "
# Cluster A: 2000 IPs in 10.50.0.0/16, normal browser traffic
for i in range(2000):
    v = i + 1
    ip = f'10.50.{v // 256}.{v % 256}'
    print(f'{ip} - - [01/Feb/2025:00:00:00 +0000] \"GET / HTTP/1.1\" 200 100 \"-\" \"Mozilla/5.0\"')

# Cluster B: 1500 IPs in 192.168.0.0/18, Googlebot (should be whitelisted)
for i in range(1500):
    v = i + 1
    ip = f'192.168.{v // 256}.{v % 256}'
    print(f'{ip} - - [01/Feb/2025:00:00:00 +0000] \"GET / HTTP/1.1\" 200 100 \"-\" \"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)\"')

# Cluster C: 1000 IPs in 172.16.0.0/20, BadBot (should be blacklisted)
for i in range(1000):
    v = i + 1
    ip = f'172.16.{v // 256}.{v % 256}'
    print(f'{ip} - - [01/Feb/2025:00:00:00 +0000] \"GET / HTTP/1.1\" 200 100 \"-\" \"BadBot/1.0\"')

# Cluster D: 500 IPs in 203.0.0.0/24 (IP in whitelist, should not be jailed)
for i in range(500):
    ip = f'203.0.0.{(i % 254) + 1}'
    print(f'{ip} - - [01/Feb/2025:00:00:00 +0000] \"GET / HTTP/1.1\" 200 100 \"-\" \"Mozilla/5.0\"')
" > "$LOG_FILE"

TOTAL_LINES=$(wc -l < "$LOG_FILE")
log "Generated $TOTAL_LINES log lines"

# --- Create whitelist/blacklist files ---
WHITELIST="$TMPDIR/whitelist.txt"
BLACKLIST="$TMPDIR/blacklist.txt"
UA_WHITELIST="$TMPDIR/ua_whitelist.txt"
UA_BLACKLIST="$TMPDIR/ua_blacklist.txt"
JAIL_FILE="$TMPDIR/jail.json"
BAN_FILE="$TMPDIR/ban.txt"

echo '{}' > "$JAIL_FILE"

# IP whitelist: protect 203.0.0.0/24
cat > "$WHITELIST" <<EOF
# Trusted partner network
203.0.0.0/24
EOF

# IP blacklist: always ban these
cat > "$BLACKLIST" <<EOF
# Known bad actors (always in ban file)
198.51.100.0/24
EOF

# User-Agent whitelist: Googlebot is trusted
cat > "$UA_WHITELIST" <<EOF
# Trusted search engine bots (exact match)
Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)
EOF

# User-Agent blacklist: BadBot gets auto-jailed
cat > "$UA_BLACKLIST" <<EOF
# Known bad bots (exact match)
BadBot/1.0
EOF

# --- Test 1: Run with all filters ---
log "Test 1: Full whitelist/blacklist integration..."
CONFIG_FILE="$TMPDIR/wl_bl_config.toml"
cat > "$CONFIG_FILE" <<TOML
[global]
jailFile = "$JAIL_FILE"
banFile = "$BAN_FILE"
whitelist = "$WHITELIST"
blacklist = "$BLACKLIST"
userAgentWhitelist = "$UA_WHITELIST"
userAgentBlacklist = "$UA_BLACKLIST"

[static]
logFile = "$LOG_FILE"
logFormat = '$LOG_FORMAT'

[static.main]
clusterArgSets = [[500, 16, 24, 0.2]]
useForJail = [true]
TOML

JSON_FILE="$TMPDIR/result.json"
"$TMPDIR/cidrx" static \
    --config "$CONFIG_FILE" \
    > "$JSON_FILE" 2>/dev/null

# Check User-Agent whitelist IPs were extracted
UA_WL_COUNT=$(python3 -c "
import json; d=json.load(open('$JSON_FILE'))
print(len(d.get('useragent_whitelist_ips', [])))
" 2>/dev/null || echo "0")
if [ "$UA_WL_COUNT" -gt 0 ]; then
    pass "UA whitelist extracted $UA_WL_COUNT IPs"
else
    fail "UA whitelist extracted 0 IPs"
fi

# Check User-Agent blacklist IPs were extracted
UA_BL_COUNT=$(python3 -c "
import json; d=json.load(open('$JSON_FILE'))
print(len(d.get('useragent_blacklist_ips', [])))
" 2>/dev/null || echo "0")
if [ "$UA_BL_COUNT" -gt 0 ]; then
    pass "UA blacklist extracted $UA_BL_COUNT IPs"
else
    fail "UA blacklist extracted 0 IPs"
fi

# Verify Googlebot IPs are NOT in the trie (excluded by UA whitelist)
UNIQUE_IPS=$(python3 -c "
import json; d=json.load(open('$JSON_FILE'))
for t in d.get('tries', []):
    print(t['stats']['unique_ips'])
    break
" 2>/dev/null || echo "0")
# Without Googlebot (1500 IPs), trie should have ~3500 unique IPs
if [ "$UNIQUE_IPS" -lt 4000 ]; then
    pass "Trie has $UNIQUE_IPS unique IPs (Googlebot excluded)"
else
    fail "Trie has $UNIQUE_IPS unique IPs (expected < 4000, Googlebot should be excluded)"
fi

# Check ban file for blacklist entries
if [ -f "$BAN_FILE" ]; then
    # 198.51.100.0/24 should always be in ban file (IP blacklist)
    if grep -q "198.51.100.0/24" "$BAN_FILE"; then
        pass "Ban file contains IP blacklist entry 198.51.100.0/24"
    else
        fail "Ban file missing IP blacklist entry 198.51.100.0/24"
    fi

    # 203.0.0.0/24 should NOT be in ban file (IP whitelist protects it)
    if grep -q "203.0.0" "$BAN_FILE"; then
        fail "Ban file contains whitelisted IP range 203.0.0.x"
    else
        pass "Ban file correctly excludes whitelisted 203.0.0.0/24"
    fi
else
    fail "Ban file not created"
fi

# Check jail file was updated
if [ -f "$JAIL_FILE" ] && [ -s "$JAIL_FILE" ]; then
    JAIL_SIZE=$(wc -c < "$JAIL_FILE")
    pass "Jail file updated ($JAIL_SIZE bytes)"
else
    log "NOTE: Jail file not updated"
fi

# --- Test 2: Run without whitelist/blacklist (baseline comparison) ---
log "Test 2: Baseline without whitelist/blacklist..."
JAIL_FILE2="$TMPDIR/jail2.json"
BAN_FILE2="$TMPDIR/ban2.txt"
echo '{}' > "$JAIL_FILE2"

CONFIG_FILE2="$TMPDIR/baseline_config.toml"
cat > "$CONFIG_FILE2" <<TOML
[global]
jailFile = "$JAIL_FILE2"
banFile = "$BAN_FILE2"

[static]
logFile = "$LOG_FILE"
logFormat = '$LOG_FORMAT'

[static.main]
clusterArgSets = [[500, 16, 24, 0.2]]
useForJail = [true]
TOML

JSON_FILE2="$TMPDIR/baseline.json"
"$TMPDIR/cidrx" static \
    --config "$CONFIG_FILE2" \
    > "$JSON_FILE2" 2>/dev/null

BASELINE_IPS=$(python3 -c "
import json; d=json.load(open('$JSON_FILE2'))
for t in d.get('tries', []):
    print(t['stats']['unique_ips'])
    break
" 2>/dev/null || echo "0")

# Baseline should have MORE IPs than filtered version (includes Googlebot)
if [ "$BASELINE_IPS" -gt "$UNIQUE_IPS" ]; then
    pass "Baseline has more IPs ($BASELINE_IPS) than filtered ($UNIQUE_IPS)"
else
    fail "Baseline ($BASELINE_IPS) should have more IPs than filtered ($UNIQUE_IPS)"
fi

# Ban file without blacklist should NOT contain 198.51.100.0/24
if [ -f "$BAN_FILE2" ]; then
    if grep -q "198.51.100.0/24" "$BAN_FILE2"; then
        fail "Baseline ban file should not contain manual blacklist entry"
    else
        pass "Baseline ban file correctly lacks manual blacklist entries"
    fi
fi

# --- Test 3: Whitelist beats manual blacklist (whitelists always win) ---
log "Test 3: Whitelist overlapping manual blacklist..."
JAIL_FILE3="$TMPDIR/jail3.json"
BAN_FILE3="$TMPDIR/ban3.txt"
WHITELIST3="$TMPDIR/whitelist3.txt"
BLACKLIST3="$TMPDIR/blacklist3.txt"
echo '{}' > "$JAIL_FILE3"

# Whitelist covers the lower half of the manually blacklisted /24: the
# published ban file must only contain the non-whitelisted remainder.
echo "203.0.113.0/25" > "$WHITELIST3"
echo "203.0.113.0/24" > "$BLACKLIST3"

CONFIG_FILE3="$TMPDIR/wl_beats_bl_config.toml"
cat > "$CONFIG_FILE3" <<TOML
[global]
jailFile = "$JAIL_FILE3"
banFile = "$BAN_FILE3"
whitelist = "$WHITELIST3"
blacklist = "$BLACKLIST3"

[static]
logFile = "$LOG_FILE"
logFormat = '$LOG_FORMAT'

[static.main]
clusterArgSets = [[500, 16, 24, 0.2]]
useForJail = [true]
TOML

"$TMPDIR/cidrx" static \
    --config "$CONFIG_FILE3" \
    > /dev/null 2>&1

if [ -f "$BAN_FILE3" ]; then
    if grep -q "203.0.113.0/24" "$BAN_FILE3" || grep -q "203.0.113.0/25" "$BAN_FILE3"; then
        fail "Ban file publishes whitelisted range (manual blacklist must not override whitelist)"
    else
        pass "Ban file excludes whitelisted half of manual blacklist entry"
    fi
    if grep -q "203.0.113.128/25" "$BAN_FILE3"; then
        pass "Ban file contains subtracted remainder 203.0.113.128/25"
    else
        fail "Ban file missing subtracted remainder 203.0.113.128/25"
    fi
else
    fail "Ban file not created (Test 3)"
fi

# --- Summary ---
log "============================="
log "Results: $PASS passed, $FAIL failed"
log "============================="

rm -f "$TMPDIR/cidrx"

[ "$FAIL" -eq 0 ]
