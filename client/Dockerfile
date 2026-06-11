# Traffic-generator image: one container simulates a whole subnet of clients
# by adding secondary IPs to eth0 and running one curl loop per IP.
# Needs root + NET_ADMIN (granted via compose `cap_add`) for `ip addr add`.
FROM alpine:3.20

RUN apk add --no-cache curl iproute2

COPY --chmod=755 entrypoint.sh /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
