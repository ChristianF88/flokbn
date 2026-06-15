---
title: "Quick Start"
description: "Get started with flokbn in minutes"
summary: "Quick examples to get you analyzing logs immediately"
date: 2025-10-09T10:00:00+00:00
lastmod: 2026-06-11T10:00:00+00:00
draft: false
weight: 120
toc: true
seo:
  title: "flokbn Quick Start Guide"
  description: "Learn how to use flokbn for IP clustering and blacklist generation in minutes with practical examples"
  canonical: ""
  noindex: false
---

## Your First Analysis

```bash
./flokbn static --logfile /var/log/nginx/access.log \
  --clusterArgSets 1000,24,32,0.1 \
  --plain
```

This detects clusters of 1000+ requests from IPs in /24 to /32 ranges using a 10% threshold. See [Clustering]({{< relref "/docs/reference/clustering/" >}}) for parameter details.

### Understanding the Output

```
═══════════════════════════════════════════════════════════════════════════════
                               flokbn Analysis Results
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

### Multi-Tier Detection

To catch small, medium, and large clusters in one run, pass several `--clusterArgSets` - see the [Static Analysis guide]({{< relref "/docs/guides/static-analysis/#multi-tier-detection" >}}) for the pattern.

### Time-Specific Analysis

```bash
./flokbn static --logfile access.log \
  --startTime "2025-01-15" \
  --endTime "2025-01-15 23:59" \
  --clusterArgSets 1000,24,32,0.1 \
  --plain
```

### Generating Block Lists

```bash
./flokbn static --logfile access.log \
  --whitelist /etc/flokbn/whitelist.txt \
  --jailFile /tmp/jail.json \
  --banFile /tmp/ban.txt \
  --clusterArgSets 1000,24,32,0.1 \
  --plain
```

Detected ranges (minus whitelisted ones) are jailed and written to the ban file. The jail file only appears once at least one range has actually been jailed; the ban file is always written. See [Output Formats]({{< relref "/docs/reference/output-formats/#ban-file-format" >}}) for the file formats and firewall integration.

## Real-Time Protection

For continuous monitoring and automatic blocking, run flokbn in live mode - the [Live Protection guide]({{< relref "/docs/guides/live-protection/" >}}) covers the command, Filebeat setup, and production deployment.

## Using Configuration Files

For complex scenarios, use a TOML config file:

```bash
./flokbn static --config flokbn.toml --plain
```

See [Config File]({{< relref "/docs/reference/config-file/" >}}) for the complete schema and examples.

## Output Formats

Besides `--plain`, static mode can emit JSON (default), compact JSON (`--compact`), or an interactive TUI (`--tui`) - see [Output Formats]({{< relref "/docs/reference/output-formats/" >}}) for the schemas and examples.

## Testing Your Setup

The [Docker test and demo stacks]({{< relref "/docs/guides/docker-testing/" >}}) let you verify flokbn end-to-end against simulated traffic - including a closed-loop demo with firewall enforcement, Prometheus, and Grafana.

## Next Steps

- [Static Analysis]({{< relref "/docs/guides/static-analysis/" >}}) - Detailed walkthrough with filtering and multi-tier detection
- [CLI Flags]({{< relref "/docs/reference/cli-flags/" >}}) - Complete command-line reference
- [Clustering]({{< relref "/docs/reference/clustering/" >}}) - Parameter tuning guide
- [Filtering]({{< relref "/docs/reference/filtering/" >}}) - Whitelist/blacklist file formats
- [Log Formats]({{< relref "/docs/reference/log-formats/" >}}) - Custom log format configuration
