---
title: "Docker Testing Guide"
description: "Using cidrx with the Docker test environment"
summary: "Complete guide to the Docker-based test environment with simulated traffic"
date: 2025-10-09T10:00:00+00:00
lastmod: 2025-11-26T10:00:00+00:00
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

cidrx includes a Docker Compose environment that simulates realistic traffic scenarios with 44 traffic clients across multiple networks. Use it to test detection parameters, validate configurations, and understand how cidrx works.

## Architecture

The test environment includes:

- **nginx** -- web server receiving simulated traffic, logs to `/var/log/nginx/access.log`
- **Filebeat** -- ships logs to cidrx via Lumberjack protocol
- **cidrx** -- runs in live mode with detection enabled
- **44 traffic clients** -- spread across 4 Docker networks

## Quick Start

```bash
cd cidrx/cidrx
docker compose up --build
```

Watch detections in a separate terminal (cidrx logs leveled progress lines to stderr; for machine-readable data query `http://localhost:8666/stats`):

```bash
docker compose logs -f cidrx
```

Check the ban list:

```bash
docker compose exec cidrx cat /data/blocklist.txt
```

View the jail state:

```bash
docker compose exec cidrx cat /data/jail.json
```

The jail file uses a tiered cell structure. See [Internals]({{< relref "/docs/architecture/internals/" >}}) for the data model.

Stop the environment:

```bash
docker compose down       # stop containers
docker compose down -v    # also remove volumes
```

## Expected Results

Within 1-2 minutes, cidrx detects:

| Network | CIDR Range | Clients | Notes |
|---------|------------|---------|-------|
| net1 (172.16.1.0/24) | 172.16.1.32/30 | 4 | Detected |
| net2 (172.16.2.0/24) | 172.16.2.32/31 | 2 | Detected |
| net3 (172.16.3.0/24) | 172.16.3.32/30 | 4 | Detected |
| net3 (172.16.3.0/24) | 172.16.3.36/32 | 1 | Detected |
| net4 (172.16.16.0/24) | 172.16.16.32/27 | 32 | Main cluster |
| net4 (172.16.16.0/24) | 172.16.16.64/32 | 1 | Detected |

## Test Configuration

The environment uses `docker-test-config.toml`:

```toml
[global]
jailFile = "/data/jail.json"
banFile = "/data/blocklist.txt"

[live]
port = "8080"

[live.default]
slidingWindowMaxTime = "5m"
slidingWindowMaxSize = 10000
sleepBetweenIterations = 10
clusterArgSets = [
  [10, 30, 32, 0.1],
  [50, 28, 32, 0.2]
]
useForJail = [true, true]
```

These parameters are tuned for quick detection in the test environment. Production values should be higher. See [Clustering]({{< relref "/docs/reference/clustering/" >}}) for tuning guidance.

Edit without rebuilding:

```bash
nano docker-test-config.toml
docker compose restart cidrx
docker compose logs -f cidrx
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
docker compose ps                                           # All containers running?
docker compose logs attack-net1-client-1                    # Attack clients working?
docker compose exec nginx tail -f /var/log/nginx/access.log # Logs being generated?
docker compose exec filebeat filebeat test output           # Filebeat connected?
```

### Container Crashes

```bash
docker compose ps -a
docker compose logs --tail=100 cidrx
```

### Permission Issues

```bash
docker compose exec cidrx ls -la /data
```
