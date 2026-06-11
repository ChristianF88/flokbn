#!/bin/sh
# Firewall-like enforcement inside the nginx container (CIDRX-045).
#
# Polls BANLIST_URL (cidrx GET /bans) every BANPOLL_INTERVAL seconds,
# renders the CIDRs as `deny <cidr>;` lines into the include consumed by
# default.conf, and reloads nginx when the set changes. Tolerates the 503
# cidrx serves before its first snapshot (wget fails -> retry next tick).
#
# Only lines that look like an IPv4 address or CIDR are accepted; the ban
# file's `#` comments and blanks fall out of the same filter. The filter is
# shape-only on purpose (it does not range-check octets or the prefix):
# cidrx renders /bans from its own jail of parsed CIDRs, so the grep guards
# against non-banlist bodies (proxy error pages, comments), not bad values.
set -u

DENY_CONF=/etc/nginx/banned/deny.conf
INTERVAL="${BANPOLL_INTERVAL:-2}"

echo "banpoller: polling ${BANLIST_URL} every ${INTERVAL}s"

while :; do
    if body=$(wget -q -T 5 -O - "$BANLIST_URL" 2>/dev/null); then
        printf '%s\n' "$body" \
            | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$' \
            | sed 's|.*|deny &;|' > "$DENY_CONF.new" || true
        if cmp -s "$DENY_CONF.new" "$DENY_CONF"; then
            rm -f "$DENY_CONF.new"
        else
            mv "$DENY_CONF.new" "$DENY_CONF"
            nginx -s reload
            echo "banpoller: applied $(grep -c '^deny' "$DENY_CONF") deny rules"
        fi
    fi
    sleep "$INTERVAL"
done
