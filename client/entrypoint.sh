#!/bin/sh
# Traffic generator: simulate COUNT clients from one container.
#
# Env contract (set by docker-compose):
#   IP_BASE    - first three octets of the subnet, e.g. "172.16.16"
#   IP_START   - last octet of the first client IP, e.g. 32
#   COUNT      - number of client IPs (primary + secondaries)
#   INTERVAL   - sleep between requests per IP, seconds (may be fractional)
#   TARGET_URL - URL to curl
#
# Docker assigns the primary address $IP_BASE.$IP_START via the service's
# static ipv4_address; this script adds the remaining COUNT-1 addresses as
# secondary IPs on eth0, then runs one background curl loop per IP
# (--interface pins the source address). A background loop per IP preserves
# the per-IP request rate; a sequential round-robin would cap below INTERVAL
# at 33 IPs.
set -eu

LAST=$((IP_START + COUNT - 1))
echo "traffic-gen: ${COUNT} IPs ${IP_BASE}.${IP_START}-${IP_BASE}.${LAST}, interval ${INTERVAL}s, target ${TARGET_URL}"

# Add secondary IPs (primary .IP_START already assigned by docker).
i=1
while [ "$i" -lt "$COUNT" ]; do
    ip addr add "${IP_BASE}.$((IP_START + i))/24" dev eth0
    i=$((i + 1))
done

# One request loop per IP.
i=0
while [ "$i" -lt "$COUNT" ]; do
    addr="${IP_BASE}.$((IP_START + i))"
    while true; do
        curl -s -o /dev/null --fail --interface "$addr" "$TARGET_URL" \
            && echo "[$addr] OK" || echo "[$addr] FAIL"
        sleep "$INTERVAL"
    done &
    i=$((i + 1))
done

wait
