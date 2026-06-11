---
title: "Output Formats"
description: "JSON, plain text, compact JSON, and TUI output modes"
summary: "Complete reference for all cidrx output formats with schemas and examples"
date: 2025-10-09T10:00:00+00:00
lastmod: 2026-06-11T10:00:00+00:00
draft: false
weight: 260
slug: "output-formats"
toc: true
seo:
  title: "cidrx Output Formats"
  description: "Learn about cidrx output formats including JSON, plain text, and interactive TUI"
  canonical: ""
  noindex: false
---

## Overview

| Format | Flag | Best For |
|--------|------|----------|
| JSON | *(default)* | APIs, automation, parsing with `jq` |
| Compact JSON | `--compact` | SIEM integration, log aggregation |
| Plain Text | `--plain` | Terminal reading, reports, email |
| TUI | `--tui` | Interactive exploration, demos |

## JSON (Default)

```bash
./cidrx static --logfile access.log --clusterArgSets 1000,24,32,0.1
```

### Schema

```json
{
  "metadata": {
    "log_file": "string",
    "analysis_type": "static|live",
    "generated_at": "RFC3339 timestamp",
    "duration_ms": "number"
  },
  "parsing": {
    "total_requests": "number",
    "parse_time_ms": "number",
    "parse_rate": "number (requests/sec)",
    "log_format": "string"
  },
  "trie": {
    "name": "string",
    "requests_after_filtering": "number",
    "unique_ips": "number",
    "build_time_ms": "number",
    "active_filters": ["string"]
  },
  "cidr_ranges": [
    {
      "cidr": "string",
      "count": "number",
      "percentage": "number"
    }
  ],
  "clustering": [
    {
      "set_number": "number",
      "parameters": {
        "min_size": "number",
        "min_depth": "number",
        "max_depth": "number",
        "threshold": "number"
      },
      "execution_time_us": "number",
      "detected_ranges": [
        {
          "cidr": "string",
          "count": "number",
          "percentage": "number"
        }
      ],
      "total_count": "number",
      "total_percentage": "number"
    }
  ]
}
```

### Processing with jq

```bash
# Extract all detected CIDRs
./cidrx static --logfile access.log --clusterArgSets 1000,24,32,0.1 | \
  jq -r '.clustering[].detected_ranges[].cidr'

# Get CIDRs with > 1000 requests
./cidrx static --logfile access.log --clusterArgSets 1000,24,32,0.1 | \
  jq -r '.clustering[].detected_ranges[] | select(.count > 1000) | .cidr'

# Total flagged requests
./cidrx static --logfile access.log --clusterArgSets 1000,24,32,0.1 | \
  jq '.clustering[].total_count'
```

### Python Processing

```python
import json, subprocess

result = subprocess.run(
    ['./cidrx', 'static', '--logfile', 'access.log',
     '--clusterArgSets', '1000,24,32,0.1'],
    capture_output=True, text=True
)

data = json.loads(result.stdout)
for cluster_set in data['clustering']:
    for detected in cluster_set['detected_ranges']:
        print(f"Block: {detected['cidr']} ({detected['count']} requests)")
```

## Compact JSON

Single-line minified JSON, same schema as above.

```bash
./cidrx static --logfile access.log --clusterArgSets 1000,24,32,0.1 --compact
```

Useful for SIEM ingestion, message queues, and log aggregation:

```bash
# Send to Elasticsearch
./cidrx static --logfile access.log --clusterArgSets 1000,24,32,0.1 --compact | \
  curl -X POST "localhost:9200/cidrx-detections/_doc" \
       -H 'Content-Type: application/json' -d @-

# Append to log file
./cidrx static --logfile access.log --clusterArgSets 1000,24,32,0.1 --compact >> \
  /var/log/cidrx/detections.log
```

## Plain Text

Human-readable formatted output with box-drawing characters and aligned columns.

```bash
./cidrx static --logfile access.log --clusterArgSets 1000,24,32,0.1 --plain
```

Example output:

```
═══════════════════════════════════════════════════════════════════════════════
                               cidrx Analysis Results
═══════════════════════════════════════════════════════════════════════════════

📊 ANALYSIS OVERVIEW
────────────────────────────────────────────────────────────────────────────────
Log File:        /var/log/nginx/access.log
Analysis Type:   static
Generated:       2026-06-11 10:15:23 UTC
Duration:        570 ms

⚡ PARSING PERFORMANCE
────────────────────────────────────────────────────────────────────────────────
Total Requests:  2,345,057
Parse Time:      534 ms
Parse Rate:      4,388,769 requests/sec

🎯 TRIE: cli_trie
────────────────────────────────────────────────────────────────────────────────
Requests After Filtering: 1,230,755
Unique IPs:              1,230,755
Trie Build Time:         47 ms
Active Filters:          None

🔍 CLUSTERING RESULTS (1 set)
...............................................................................
  Set 1: min_size=1000, depth=24-32, threshold=0.10
  Execution Time: 95 μs
  Detected Threat Ranges:
    192.0.2.2/32               1,574 requests  (  0.13%)
    198.51.100.192/26          3,083 requests  (  0.25%)
    203.0.113.91/32            1,308 requests  (  0.11%)
    ───────────────────        5,965 requests  (  0.48%) [TOTAL]

═══════════════════════════════════════════════════════════════════════════════
```

Useful for terminal display, reports, and email alerts:

```bash
# Daily report
./cidrx static --logfile access.log \
  --startTime "2025-10-09" --endTime "2025-10-09 23:59" \
  --clusterArgSets 1000,24,32,0.1 --plain > daily-report.txt

# Email
./cidrx static --logfile access.log --clusterArgSets 1000,24,32,0.1 --plain | \
  mail -s "cidrx Report" admin@example.com
```

## TUI (Interactive)

Terminal user interface with heatmaps, interactive tables, and real-time updates.

```bash
./cidrx static --config cidrx.toml --tui
./cidrx static --logfile access.log --clusterArgSets 1000,24,32,0.1 --tui
```

**Navigation**: Arrow keys to navigate, Tab to switch panels, Enter to drill down, Q to quit.

**Panels**: Overview (summary stats), Detection (detected ranges), Detail (selected range info), Timeline (temporal distribution).

Works both with `--config` and CLI-only parameters. Available in static mode only (not live mode).

## Ban File Format

When `--banFile` is specified, cidrx writes one CIDR per line:

```
198.51.100.192/26
203.0.113.91/32
192.0.2.2/32
```

This can be consumed directly by iptables, nginx deny directives, or cloud firewall rules:

```bash
# iptables
while read cidr; do
  iptables -I INPUT -s "$cidr" -j DROP
done < /tmp/ban.txt

# nginx format
sed 's/^/deny /; s/$/;/' /tmp/ban.txt > /etc/nginx/cidrx-bans.conf
```

## Jail File Format

The jail file (`--jailFile`) persists detection state as JSON. See [Internals]({{< relref "/docs/architecture/internals/" >}}) for the full jail structure.

## Generating Firewall Rules from JSON

```bash
# iptables rules
./cidrx static --logfile access.log --clusterArgSets 1000,24,32,0.1 | \
  jq -r '.clustering[].detected_ranges[].cidr' | \
  sed 's/^/iptables -A INPUT -s /; s/$/ -j DROP/' > rules.sh

# nginx deny directives
./cidrx static --logfile access.log --clusterArgSets 1000,24,32,0.1 | \
  jq -r '.clustering[].detected_ranges[].cidr' | \
  sed 's/^/deny /; s/$/;/' > nginx-deny.conf
```

## Performance Impact

| Format | Speed | Notes |
|--------|-------|-------|
| JSON | Fast | Minimal formatting overhead |
| Compact JSON | Fast | Same as JSON, less whitespace |
| Plain Text | Medium | Box drawing and alignment |
| TUI | Slow | Full terminal rendering |

Use `--compact` for automated pipelines. Use `--plain` for human consumption. Avoid TUI for very large datasets.

## Error Output

On error, JSON output includes:
```json
{
  "error": true,
  "message": "Failed to open log file: /var/log/nginx/access.log",
  "code": "FILE_NOT_FOUND"
}
```

Check exit code in scripts:
```bash
if ./cidrx static --logfile access.log --clusterArgSets 1000,24,32,0.1 > output.json 2>&1; then
    jq -r '.clustering[].detected_ranges[].cidr' output.json > blocklist.txt
else
    echo "Analysis failed"
    exit 1
fi
```
