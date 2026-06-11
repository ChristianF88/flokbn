---
title: "Docker Testing Guide"
description: "Using cidrx with the Docker test environment"
summary: "Complete guide to the Docker-based test environment with simulated traffic"
date: 2025-10-09T10:00:00+00:00
lastmod: 2026-06-11T10:00:00+00:00
draft: false
weight: 830
slug: "docker-testing"
toc: true
seo:
  title: "cidrx Docker Testing Guide"
  description: "Learn how to use the cidrx Docker test environment with simulated traffic"
  canonical: ""
  noindex: false
---

cidrx ships two Docker Compose stacks that simulate attack traffic against a real nginx: a fast **test** stack used by the e2e suites, and a slow-paced **demo** stack with a closed-loop firewall, Prometheus, and a provisioned Grafana dashboard. Use them to test detection parameters, validate configurations, and watch cidrx work end to end.

## Architecture

Both stacks share the same topology:

- **nginx (proxy)** -- web server receiving simulated traffic, logs to `/var/log/nginx/access.log`
- **Filebeat** -- ships logs to cidrx via the Lumberjack protocol
- **cidrx** -- runs in live mode with detection enabled; HTTP endpoints `/stats`, `/bans`, and Prometheus `/metrics` on port 8666
- **traffic clients** (45 in the test stack, 44 in the demo) -- spread across 5 Docker networks: four attack clusters (net1-net4) plus one slow negative-control client (172.30.99.32) that must never be banned

## Quick Start (test stack)

From the repository root:

```bash
docker compose -f docker-compose.test.yml up --build
```

Watch detections in a separate terminal (cidrx logs leveled progress lines to stderr; for machine-readable data query `http://localhost:8666/stats`):

```bash
docker compose -f docker-compose.test.yml logs -f cidrx
```

Check the ban list and jail state:

```bash
docker compose -f docker-compose.test.yml exec cidrx cat /data/blocklist.txt
docker compose -f docker-compose.test.yml exec cidrx cat /data/jail.json
```

The jail file uses a tiered cell structure. See [Internals]({{< relref "/docs/architecture/internals/" >}}) for the data model.

Stop the environment:

```bash
docker compose -f docker-compose.test.yml down       # stop containers
docker compose -f docker-compose.test.yml down -v    # also remove volumes
```

{{< callout context="caution" title="Jail state persists" icon="outline/alert-triangle" >}}
The jail file lives in the `cidrx_data` volume and survives restarts: a plain `down`/`up` reloads old bans. Use `down -v` for a clean run.
{{< /callout >}}

## Demo: closed-loop firewall with monitoring

The demo stack adds enforcement and observability on top of the same topology. nginx runs a banlist poller that fetches `GET /bans` from cidrx every 2 s and renders the CIDRs into `deny` rules -- banned clients get 403, denied requests are excluded from the shipped log, and the ban -> traffic decay -> expiry -> re-ban loop closes. Prometheus scrapes cidrx and an nginx log exporter; Grafana is fully provisioned with a 14-panel dashboard.

```bash
docker compose -f docker-compose.demo.yml \
               -f docker-compose-firewall-with-monitoring.demo.yml \
               up --build -d
```

Then open:

- **Grafana dashboard**: <http://localhost:3000/d/cidrx> (anonymous access enabled)
- **Prometheus**: <http://localhost:9090>
- **cidrx stats**: <http://localhost:8666/stats>

Traffic is paced so the four attack clusters cross the detection threshold at clearly different times -- bans land staggered across the first two minutes:

| Time | Banned CIDR | Cluster |
|------|-------------|---------|
| ~20 s | 172.16.16.32/27 | net4, 32 IPs (main attack) |
| ~50 s | 172.16.3.32/28 | net3, 5 IPs |
| ~80 s | 172.16.1.32/28 | net1, 4 IPs |
| ~113 s | 172.16.2.32/28 | net2, 2 IPs |

The negative-control client keeps humming with 200s throughout. Stage-1 bans expire after 10 minutes, traffic returns, and re-detection escalates repeat offenders to longer stages -- the dashboard's ban timeline shows the cycle per CIDR.

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
docker compose -f docker-compose.test.yml restart cidrx
docker compose -f docker-compose.test.yml logs -f cidrx
```

## Building Custom Images

```bash
cd cidrx/cidrx
docker build -t cidrx:latest .
```

The Dockerfile uses a multi-stage build (Go build then Alpine runtime), producing a ~20MB image.

## Running Static Mode in Docker

```bash
docker run -v /var/log/nginx:/logs cidrx:latest \
  static --logfile /logs/access.log \
  --clusterArgSets 1000,24,32,0.1 --plain
```

With config file:

```bash
docker run -v /etc/cidrx:/config -v /var/log:/logs \
  cidrx:latest static --config /config/cidrx.toml --plain
```

## Production Docker Deployment

```yaml
# docker-compose.prod.yml
version: '3.8'
services:
  cidrx:
    image: cidrx:latest
    restart: always
    ports:
      - "8080:8080"
    volumes:
      - /etc/cidrx/config.toml:/config/config.toml:ro
      - /var/lib/cidrx:/data
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
`cidrx_data` volume -- a stale wide ban suppresses all traffic and with it
any new detections. `down -v` resets it.

### Container Crashes

```bash
docker compose -f docker-compose.test.yml ps -a
docker compose -f docker-compose.test.yml logs --tail=100 cidrx
```

### Permission Issues

```bash
docker compose -f docker-compose.test.yml exec cidrx ls -la /data
```
