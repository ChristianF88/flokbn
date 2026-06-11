---
title: "Quick Start"
description: "Get started with cidrx in minutes"
summary: "Quick examples to get you analyzing logs immediately"
date: 2025-10-09T10:00:00+00:00
lastmod: 2026-06-11T10:00:00+00:00
draft: false
weight: 120
toc: true
seo:
  title: "cidrx Quick Start Guide"
  description: "Learn how to use cidrx for IP clustering and blacklist generation in minutes with practical examples"
  canonical: ""
  noindex: false
---

## Your First Analysis

```bash
./cidrx static --logfile /var/log/nginx/access.log \
  --clusterArgSets 1000,24,32,0.1 \
  --plain
```

This detects clusters of 1000+ requests from IPs in /24 to /32 ranges using a 10% threshold. See [Clustering]({{< relref "/docs/reference/clustering/" >}}) for parameter details.

### Understanding the Output

```
═══════════════════════════════════════════════════════════════════════════════
                               cidrx Analysis Results
═══════════════════════════════════════════════════════════════════════════════

📊 ANALYSIS OVERVIEW
────────────────────────────────────────────────────────────────────────────────
Log File:        /var/log/nginx/access.log
Analysis Type:   static
Generated:       2026-06-11 10:00:00 UTC
Duration:        570 ms

⚡ PARSING PERFORMANCE
────────────────────────────────────────────────────────────────────────────────
Total Requests:  2,345,057
Parse Time:      534 ms
Parse Rate:      4,388,769 requests/sec

🔍 CLUSTERING RESULTS (1 set)
...............................................................................
  Set 1: min_size=1000, depth=24-32, threshold=0.10
  Execution Time: 95 μs
  Detected Threat Ranges:
    198.51.100.192/26            3,083 requests  (  0.13%)
    203.0.113.91/32           1,308 requests  (  0.06%)
    ───────────────────        4,391 requests  (  0.19%) [TOTAL]
```

The detected CIDR ranges represent high-volume IP ranges you can investigate or block.

## Common Use Cases

### Emergency Response

Catch different cluster sizes with multiple cluster arg sets:

```bash
./cidrx static --logfile access.log \
  --clusterArgSets 500,28,32,0.1 \
  --clusterArgSets 2000,20,28,0.2 \
  --clusterArgSets 10000,16,24,0.3 \
  --plain
```

### Time-Specific Analysis

```bash
./cidrx static --logfile access.log \
  --startTime "2025-01-15" \
  --endTime "2025-01-15 23:59" \
  --clusterArgSets 1000,24,32,0.1 \
  --plain
```

### Generating Block Lists

```bash
./cidrx static --logfile access.log \
  --whitelist /etc/cidrx/whitelist.txt \
  --jailFile /tmp/jail.json \
  --banFile /tmp/ban.txt \
  --clusterArgSets 1000,24,32,0.1 \
  --plain
```

## Real-Time Protection

Switch to live mode for continuous monitoring:

```bash
./cidrx live --port 8080 \
  --jailFile /etc/cidrx/jail.json \
  --banFile /etc/cidrx/ban.txt \
  --slidingWindowMaxTime 2h \
  --slidingWindowMaxSize 100000
```

See the [Live Protection Guide]({{< relref "/docs/guides/live-protection/" >}}) for Filebeat setup and production deployment.

## Using Configuration Files

For complex scenarios, use a TOML config file:

```bash
./cidrx static --config cidrx.toml --plain
```

See [Config File]({{< relref "/docs/reference/config-file/" >}}) for the complete schema and examples.

## Output Formats

```bash
./cidrx static --logfile access.log --clusterArgSets 1000,24,32,0.1           # JSON (default)
./cidrx static --logfile access.log --clusterArgSets 1000,24,32,0.1 --compact # Compact JSON
./cidrx static --logfile access.log --clusterArgSets 1000,24,32,0.1 --plain   # Plain text
./cidrx static --config cidrx.toml --tui                                       # Interactive TUI
```

See [Output Formats]({{< relref "/docs/reference/output-formats/" >}}) for JSON schemas and firewall integration.

## Testing Your Setup

Use the [Docker test environment]({{< relref "/docs/guides/docker-testing/" >}}) to verify cidrx is working:

```bash
docker compose -f docker-compose.test.yml up --build
docker compose -f docker-compose.test.yml logs -f cidrx
docker compose -f docker-compose.test.yml down
```

## Next Steps

- [Static Analysis Guide]({{< relref "/docs/guides/static-analysis/" >}}) - Detailed walkthrough with filtering and multi-tier detection
- [CLI Flags]({{< relref "/docs/reference/cli-flags/" >}}) - Complete command-line reference
- [Clustering]({{< relref "/docs/reference/clustering/" >}}) - Parameter tuning guide
- [Filtering]({{< relref "/docs/reference/filtering/" >}}) - Whitelist/blacklist file formats
- [Log Formats]({{< relref "/docs/reference/log-formats/" >}}) - Custom log format configuration
