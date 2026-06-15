#!/bin/sh
set -e

# Firewall-like enforcement (FLOKBN-045): when BANLIST_URL is set (firewall
# compose overlay), poll flokbn's /bans in the background and reload nginx
# on changes. Unset in the base stack -> plain nginx, no poller.
if [ -n "${BANLIST_URL:-}" ]; then
    /banpoller.sh &
fi

# finally, nginx
exec nginx -g 'daemon off;'
