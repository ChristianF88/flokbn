---
title: "Docker Test & Demo Stacks"
description: "Using the flokbn Docker test environment and the closed-loop firewall demo"
summary: "The Docker-based test stack with simulated traffic, and the demo stack with firewall enforcement, Prometheus, and Grafana"
date: 2025-10-09T10:00:00+00:00
lastmod: 2026-06-11T10:00:00+00:00
draft: false
weight: 830
slug: "docker-testing"
toc: true
seo:
  title: "flokbn Docker Testing Guide"
  description: "Learn how to use the flokbn Docker test environment with simulated traffic"
  canonical: ""
  noindex: false
---

flokbn ships two Docker Compose stacks that simulate attack traffic against a real nginx: a fast **test** stack used by the e2e suites, and a slow-paced **demo** stack with a closed-loop firewall, Prometheus, and a provisioned Grafana dashboard. Use them to test detection parameters, validate configurations, and watch flokbn work end to end.

## Architecture

Both stacks share the same topology:

- **nginx (proxy)** - web server receiving simulated traffic, logs to `/var/log/nginx/access.log`
- **Filebeat** - ships logs to flokbn via the Lumberjack protocol
- **flokbn** - runs in live mode with detection enabled; HTTP endpoints `/stats`, `/bans`, and Prometheus `/metrics` on port 8666
- **traffic clients** (45 in the test stack, 44 in the demo) - spread across 5 Docker networks: four attack clusters (net1-net4) plus one slow negative-control client (172.30.99.32) that must never be banned

### Ports

| Port | Service | Published to host | Purpose |
|------|---------|-------------------|---------|
| 9000 | flokbn | yes (`9000:9000`) | Lumberjack ingest (Filebeat connects here) |
| 8666 | flokbn | yes (`8666:8666`) | HTTP stats: `GET /stats`, `GET /bans`, `GET /metrics` |
| 80 | proxy (nginx) | container-internal | Target for the simulated clients |
| 9090 | prometheus | yes (monitoring overlay) | Prometheus UI / API |
| 3000 | grafana | yes (monitoring overlay) | Grafana dashboard |

The configs bind `statsListen = "0.0.0.0:8666"` so the published port is reachable from the host across the isolated compose network. That `0.0.0.0` bind is a documented demo-only exception - outside Docker, bind the stats server to localhost.

## Quick Start (test stack)

From the repository root:

```bash
docker compose -f docker-compose.test.yml up --build
```

Watch detections in a separate terminal (flokbn logs leveled progress lines to stderr; for machine-readable data query `http://localhost:8666/stats`):

```bash
docker compose -f docker-compose.test.yml logs -f flokbn
```

Check the ban list and jail state:

```bash
docker compose -f docker-compose.test.yml exec flokbn cat /data/blocklist.txt
docker compose -f docker-compose.test.yml exec flokbn cat /data/jail.json
```

The jail file uses a tiered cell structure. See [Internals]({{< relref "/docs/architecture/internals/" >}}) for the data model.

Stop the environment:

```bash
docker compose -f docker-compose.test.yml down       # stop containers
docker compose -f docker-compose.test.yml down -v    # also remove volumes
```

{{< callout context="caution" title="Jail state persists" icon="outline/alert-triangle" >}}
The jail file lives in the `flokbn_data` volume and survives restarts: a plain `down`/`up` reloads old bans. Use `down -v` for a clean run.
{{< /callout >}}

## Demo: closed-loop firewall with monitoring

The demo stack adds enforcement and observability on top of the same topology.

{{< callout context="note" title="Not an actual firewall" icon="outline/info-circle" >}}
The demo does **not** run a real firewall (no iptables/nftables). Enforcement is a deliberately simple deny mechanism that stands in for one: a small poller inside the nginx container fetches `GET /bans` from flokbn every 2 s and renders the CIDRs into nginx `deny` rules, so banned clients get HTTP 403. In a real deployment the same `/bans` endpoint (or the ban file) would drive iptables, nftables, or your WAF - the signal flow is identical, only the enforcement point changes.
{{< /callout >}}

Denied requests are excluded from the shipped log, so the sliding window decays, the ban expires, traffic reappears and gets re-banned - the loop closes. Prometheus scrapes flokbn (`GET /metrics`) and an nginx log exporter; Grafana is fully provisioned with a 14-panel dashboard.

### Signal flow

```
clients: net1-net4 (attack pacing) + 172.30.99.32 (negative control)
   │  HTTP requests
   ▼
nginx proxy ──── 403 for CIDRs in deny.conf (denied requests are NOT logged)
   │  access.log (only requests that got through)
   ▼
Filebeat ─── Lumberjack protocol, port 9000
   ▼
flokbn live ─── sliding windows → clustering → jail (escalating stages)
   │
   ├──► /data/jail.json + /data/blocklist.txt   (files)
   └──► HTTP :8666 ── GET /stats · GET /bans · GET /metrics
            │                │
            │                │  banpoller (inside the nginx container)
            │                │  polls /bans every 2 s, writes deny.conf,
            │                │  reloads nginx ──► loop closed
            │                ▼
            │           nginx deny.conf
            ▼
      Prometheus :9090 ──► Grafana :3000   (monitoring overlay)
```

While it runs, watch the loop from the host: `curl localhost:8666/stats` for the JSON snapshot of the last iteration, `curl localhost:8666/bans` for exactly what the poller sees (both return 503 until the first detection iteration completes).

```bash
docker compose -f docker-compose.demo.yml \
               -f docker-compose-firewall-with-monitoring.demo.yml \
               up --build -d
```

Then open:

- **Grafana dashboard**: <http://localhost:3000/d/flokbn> (anonymous access enabled)
- **Prometheus**: <http://localhost:9090>
- **flokbn stats**: <http://localhost:8666/stats>

Traffic is paced so the four attack clusters cross the detection threshold at clearly different times - bans land staggered across the first two minutes:

| Time | Banned CIDR | Cluster |
|------|-------------|---------|
| ~20 s | 172.16.16.32/27 | net4, 32 IPs (main attack) |
| ~50 s | 172.16.3.32/28 | net3, 5 IPs |
| ~79 s | 172.16.1.32/28 (or /30) | net1, 4 IPs |
| ~113 s | 172.16.2.32/28 (or /31) | net2, 2 IPs |

The pacing comes from the demo config's `min_size=450`: time-to-ban is roughly 450 divided by the cluster's request rate. The negative-control client (172.30.99.32, 1 request per 3 s) stays far below every threshold and keeps humming with 200s throughout - it must never be banned. Stage-1 bans expire after 10 minutes, traffic returns, and re-detection escalates repeat offenders to longer stages - the dashboard's ban timeline shows the cycle per CIDR.

The monitoring overlay is pacing-neutral; it also composes with the fast test base (`-f docker-compose.test.yml -f docker-compose-firewall-with-monitoring.demo.yml`), which is what the firewall e2e suite uses. The test and demo stacks pin the same subnets, so only one can run at a time.

## Expected Results (test stack)

With the fast pacing and low thresholds of `docker-test-config.toml`, all four attack networks are detected and jailed within seconds. Detections land on the *balanced subtree* of each cluster rather than the full /24 (clustering only reports a node whose children are evenly loaded), so expect CIDRs like:

| Network | Typical detection | Clients |
|---------|-------------------|---------|
| net1 (172.16.1.0/24) | 172.16.1.32/30 or /28 | 4 |
| net2 (172.16.2.0/24) | 172.16.2.32/31 or /28 | 2 |
| net3 (172.16.3.0/24) | 172.16.3.32/28 | 5 |
| net4 (172.16.16.0/24) | 172.16.16.32/27 (+ .64 via the coarser sets) | 33 |
| net5 (172.30.99.0/24) | never detected | 1 (negative control) |

## Test Configuration

The test stack mounts `docker-test-config.toml`, the demo stack `docker-test-config.demo.toml`. The structure (abridged):

```toml
[global]
jailFile = "/data/jail.json"
banFile = "/data/blocklist.txt"

[live]
port = "9000"
statsListen = "0.0.0.0:8666"

[live.general_detection]
slidingWindowMaxTime = "5m"
slidingWindowMaxSize = 10000
sleepBetweenIterations = 1
clusterArgSets = [
    [50, 24, 32, 0.2],
]
useForJail = [true]

[live.aggressive_detection]
slidingWindowMaxTime = "2m"
slidingWindowMaxSize = 5000
sleepBetweenIterations = 1
clusterArgSets = [
    [10, 20, 28, 0.15],
    [20, 16, 24, 0.2],
]
useForJail = [true, true]
```

These parameters are tuned for quick detection in the test environment; the demo variant uses min_size 450 and depth >= 24 in every set to pace the bans and keep detections per-network. Production values should be higher. See [Clustering]({{< relref "/docs/reference/clustering/" >}}) for tuning guidance.

Edit without rebuilding (the config is bind-mounted, read at startup):

```bash
nano docker-test-config.toml
docker compose -f docker-compose.test.yml restart flokbn
docker compose -f docker-compose.test.yml logs -f flokbn
```

## Building Custom Images

From the repository root (the Dockerfile lives in the `flokbn/` subdirectory):

```bash
docker build -t flokbn:latest ./flokbn
```

The Dockerfile uses a multi-stage build (Go build, then a small Alpine runtime image).

## Running Static Mode in Docker

```bash
docker run -v /var/log/nginx:/logs flokbn:latest \
  static --logfile /logs/access.log \
  --clusterArgSets 1000,24,32,0.1 --plain
```

With config file:

```bash
docker run -v /etc/flokbn:/config -v /var/log:/logs \
  flokbn:latest static --config /config/flokbn.toml --plain
```

## Production Docker Deployment

```yaml
# docker-compose.prod.yml
version: '3.8'
services:
  flokbn:
    image: flokbn:latest
    restart: always
    ports:
      - "8080:8080"            # Lumberjack ingest ([live] port)
      - "127.0.0.1:8666:8666"  # HTTP stats (statsListen), host-local only
    volumes:
      - /etc/flokbn/config.toml:/config/config.toml:ro
      - /var/lib/flokbn:/data
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 2G
```

For better performance, use `network_mode: host` to eliminate Docker network overhead.

## Troubleshooting

### No Detections

```bash
COMPOSE="docker compose -f docker-compose.test.yml"
$COMPOSE ps                                            # All containers running?
$COMPOSE logs clients_net1                             # Attack clients working?
$COMPOSE exec proxy tail -f /var/log/nginx/access.log  # Logs being generated?
$COMPOSE exec filebeat filebeat test output            # Filebeat connected?
```

If bans existed before a restart, remember the jail persists in the
`flokbn_data` volume - a stale wide ban suppresses all traffic and with it
any new detections. `down -v` resets it.

### Container Crashes

```bash
docker compose -f docker-compose.test.yml ps -a
docker compose -f docker-compose.test.yml logs --tail=100 flokbn
```

### Permission Issues

```bash
docker compose -f docker-compose.test.yml exec flokbn ls -la /data
```
