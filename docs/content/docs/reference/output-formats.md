---
title: "Output Formats"
description: "Static report formats (JSON, plain text, TUI) and live mode outputs (ban file, jail file, HTTP endpoints)"
summary: "Complete reference for flokbn output: static analysis reports and the files and HTTP endpoints live mode produces"
date: 2025-10-09T10:00:00+00:00
lastmod: 2026-06-12T10:00:00+00:00
draft: false
weight: 260
slug: "output-formats"
toc: true
seo:
  title: "flokbn Output Formats"
  description: "Learn about flokbn output formats including JSON, plain text, TUI, and the live mode ban file and HTTP endpoints"
  canonical: ""
  noindex: false
---

flokbn's two modes produce fundamentally different output, and this page is split accordingly:

- **[Static mode](#static-mode-output)** runs once and writes an analysis **report to stdout** - JSON, compact JSON, plain text, or an interactive TUI.
- **[Live mode](#live-mode-output)** runs forever and writes **no report at all**. Its output is the continuously updated jail and ban files, leveled log lines on stderr, and three HTTP endpoints (`/stats`, `/bans`, `/metrics`).

The [ban file](#ban-file-format) and [jail file](#jail-file-format) formats at the end apply to both modes.

## Static Mode Output

| Format | Flag | Best For |
|--------|------|----------|
| JSON | *(default)* | APIs, automation, parsing with `jq` |
| Compact JSON | `--compact` | SIEM integration, log aggregation |
| Plain Text | `--plain` | Terminal reading, reports, email |
| TUI | `--tui` | Interactive exploration, demos |

### JSON (Default)

```bash
./flokbn static --logfile access.log --clusterArgSets 1000,24,32,0.1
```

#### Schema

The top level contains `metadata`, `general`, one entry per trie under `tries`, and `warnings`/`errors` arrays:

```json
{
  "metadata": {
    "generated_at": "RFC3339 timestamp",
    "analysis_type": "static",
    "version": "string",
    "duration_ms": "number"
  },
  "general": {
    "log_file": "string",
    "total_requests": "number",
    "unique_ips": "number",
    "parsing": {
      "duration_ms": "number",
      "rate_per_second": "number",
      "format": "string"
    }
  },
  "tries": [
    {
      "name": "string (e.g. cli_trie, or the [static.NAME] label)",
      "parameters": {
        "useragent_regex": "string (omitted if unset)",
        "endpoint_regex": "string (omitted if unset)",
        "time_range": { "start": "...", "end": "..." },
        "cidr_ranges": ["string"],
        "use_for_jail": ["bool"]
      },
      "stats": {
        "total_requests_after_filtering": "number",
        "unique_ips": "number",
        "skipped_invalid_ips": "number (present only when lines with invalid/missing IPs were skipped)",
        "insert_time_ms": "number",
        "cidr_analysis": [
          { "cidr": "string", "requests": "number", "percentage": "number" }
        ]
      },
      "data": [
        {
          "parameters": {
            "min_cluster_size": "number",
            "min_depth": "number",
            "max_depth": "number",
            "mean_subnet_difference": "number"
          },
          "execution_time_us": "number",
          "detected_ranges": [
            { "cidr": "string", "requests": "number", "percentage": "number" }
          ],
          "merged_ranges": [
            { "cidr": "string", "requests": "number", "percentage": "number" }
          ]
        }
      ]
    }
  ],
  "warnings": [ { "type": "string", "message": "string", "count": "number" } ],
  "errors":   [ { "type": "string", "message": "string", "count": "number" } ],
  "useragent_whitelist_ips": ["string (present only when a User-Agent whitelist matched)"],
  "useragent_blacklist_ips": ["string (present only when a User-Agent blacklist matched)"]
}
```

`tries[].data` holds one entry per cluster arg set. `detected_ranges` are the raw per-set detections; `merged_ranges` are the same detections after overlapping/adjacent CIDRs are merged - the merged list is what feeds the jail. Empty/optional fields are omitted (`omitempty`).

#### Processing with jq

```bash
# Extract all merged CIDRs from every trie and cluster set
./flokbn static --logfile access.log --clusterArgSets 1000,24,32,0.1 | \
  jq -r '.tries[].data[].merged_ranges[].cidr'

# Get CIDRs with > 1000 requests
./flokbn static --logfile access.log --clusterArgSets 1000,24,32,0.1 | \
  jq -r '.tries[].data[].merged_ranges[] | select(.requests > 1000) | .cidr'

# Total requests parsed
./flokbn static --logfile access.log --clusterArgSets 1000,24,32,0.1 | \
  jq '.general.total_requests'
```

#### Python Processing

```python
import json, subprocess

result = subprocess.run(
    ['./flokbn', 'static', '--logfile', 'access.log',
     '--clusterArgSets', '1000,24,32,0.1'],
    capture_output=True, text=True
)

data = json.loads(result.stdout)
for trie in data['tries']:
    for cluster_set in trie['data']:
        for detected in cluster_set['merged_ranges']:
            print(f"Block: {detected['cidr']} ({detected['requests']} requests)")
```

### Compact JSON

Single-line minified JSON, same schema as above.

```bash
./flokbn static --logfile access.log --clusterArgSets 1000,24,32,0.1 --compact
```

Useful for SIEM ingestion, message queues, and log aggregation:

```bash
# Send to Elasticsearch
./flokbn static --logfile access.log --clusterArgSets 1000,24,32,0.1 --compact | \
  curl -X POST "localhost:9200/flokbn-detections/_doc" \
       -H 'Content-Type: application/json' -d @-

# Append to log file
./flokbn static --logfile access.log --clusterArgSets 1000,24,32,0.1 --compact >> \
  /var/log/flokbn/detections.log
```

### Plain Text

Human-readable formatted output with box-drawing characters and aligned columns.

```bash
./flokbn static --logfile access.log --clusterArgSets 1000,24,32,0.1 --plain
```

Example output (illustrative; RFC 5737 ranges):

```
═══════════════════════════════════════════════════════════════════════════════
                               flokbn Analysis Results
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
Unique IPs:              1,201,344
Trie Build Time:         47 ms
Active Filters:          useragent regex

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
./flokbn static --logfile access.log \
  --startTime "2025-10-09" --endTime "2025-10-09 23:59" \
  --clusterArgSets 1000,24,32,0.1 --plain > daily-report.txt

# Email
./flokbn static --logfile access.log --clusterArgSets 1000,24,32,0.1 --plain | \
  mail -s "flokbn Report" admin@example.com
```

### TUI (Interactive)

Terminal user interface that runs the analysis and presents the results in scrollable panels, plus an address-space visualization of the detected clusters.

```bash
./flokbn static --config flokbn.toml --tui
./flokbn static --logfile access.log --clusterArgSets 1000,24,32,0.1 --tui
```

**Views**: a results view with four panels - Summary, Clustering, CIDR Analysis, Diagnostics - and a visualization view showing where detections sit in the address space.

**Keys**: `Tab`/`Shift+Tab` switch panels, arrow keys scroll, `t` cycles tries (multi-trie configs), `v` opens the visualization (`←`/`→` change cluster set, `l` toggles linear/sqrt/log scale), `r` returns to results, `p` shows progress, `q` quits.

Works both with `--config` and CLI-only parameters. Available in static mode only (not live mode).

### Generating Firewall Rules from JSON

```bash
# iptables rules
./flokbn static --logfile access.log --clusterArgSets 1000,24,32,0.1 | \
  jq -r '.tries[].data[].merged_ranges[].cidr' | \
  sed 's/^/iptables -A INPUT -s /; s/$/ -j DROP/' > rules.sh

# nginx deny directives
./flokbn static --logfile access.log --clusterArgSets 1000,24,32,0.1 | \
  jq -r '.tries[].data[].merged_ranges[].cidr' | \
  sed 's/^/deny /; s/$/;/' > nginx-deny.conf
```

### Performance Impact

Format choice barely affects runtime - use `--compact` for automated pipelines, `--plain` for human consumption, and avoid the TUI for very large datasets (full terminal rendering is the slowest path).

### Error Output

Fatal errors (missing log file, invalid flags, bad config) are printed as a plain message and the process exits with code 1 - no JSON is produced. Non-fatal problems during an analysis (a failed heatmap, jail-processing errors, whitelist notices) land in the JSON `warnings` and `errors` arrays:

```json
{
  "warnings": [
    { "type": "whitelist_applied", "message": "Whitelist filtering prevented 2 CIDRs from being added to jail" }
  ],
  "errors": [
    { "type": "jail_processing", "message": "failed to process jail with whitelist/blacklist: ...", "count": 1 }
  ]
}
```

Check the exit code in scripts:
```bash
if ./flokbn static --logfile access.log --clusterArgSets 1000,24,32,0.1 > output.json; then
    jq -r '.tries[].data[].merged_ranges[].cidr' output.json > blocklist.txt
else
    echo "Analysis failed"
    exit 1
fi
```

## Live Mode Output

Live mode produces **no stdout report** - `--plain`, `--compact`, and `--tui` are static-only flags, and the live command rejects them with an error. Its output consists of:

1. **The jail and ban files**, rewritten after every detection iteration (formats [below](#ban-file-format)).
2. **Leveled log lines on stderr** - one summary line per iteration (window size, batch size, detected/merged/jailed counts, timings) plus warnings and errors. Configured via the `[log]` section or `--logLevel`.
3. **HTTP endpoints**, when `statsListen` is set in the `[live]` config section (config file only - there is no CLI flag for it).

### HTTP Endpoints

```toml
[live]
port = "8080"
statsListen = "127.0.0.1:8666"
topTalkers = 5   # optional: top-N IPs per window in /stats
```

| Endpoint | Content |
|----------|---------|
| `GET /stats` | JSON snapshot of the last iteration: `ingest` (connection, queue, totals, parse errors), `windows` (size, accepted/rejected counts, per-set detections and timings, optional `top_talkers`), `jail` (active bans per stage with start/expiry), `lists`, `loop` |
| `GET /bans` | The ban file content last written to disk, verbatim (`text/plain`) - what enforcement tooling should poll |
| `GET /metrics` | Prometheus exposition format; all metrics are prefixed `flokbn_` (ingest, window, cluster, jail, ban-file, and loop families) |

All three return `503` with a `Retry-After` header until the loop has completed its first iteration. The snapshot updates once per iteration, not per request. Bind to localhost unless you have a reason not to.

See the [Live Protection guide]({{< relref "/docs/guides/live-protection/" >}}) for deployment and the [Docker demo]({{< relref "/docs/guides/docker-testing/" >}}) for a working closed-loop example that polls `/bans`.

## Ban File Format

Written when both `--jailFile` and `--banFile` are specified (static: once at the end of the run; live: after every iteration). The file contains a timestamp header, the active jail bans, and - when a manual blacklist is configured - a blacklist section. Comment lines start with `#`:

```
# This file was generated automatically. Last modification 2026-06-11 10:15:23 
# Active jail bans:
198.51.100.192/26
203.0.113.91/32
# Manual blacklist entries:
192.0.2.2/32
# End of manual blacklist
```

The file is written atomically, so readers never observe a partial file. **Filter out the `#` comment lines** before feeding it to a firewall:

```bash
# iptables
grep -v '^#' /tmp/ban.txt | while read -r cidr; do
  [ -n "$cidr" ] && iptables -I INPUT -s "$cidr" -j DROP
done

# nginx format
grep -v '^#' /tmp/ban.txt | sed 's/^/deny /; s/$/;/' > /etc/nginx/flokbn-bans.conf
```

In live mode the same content is served over HTTP as `GET /bans`, which avoids file-distribution entirely - poll the endpoint instead of shipping the file.

## Jail File Format

The jail file (`--jailFile`) persists detection state as JSON. It is only created once at least one range has actually been jailed - a run with no detections leaves no jail file behind (the ban file, in contrast, is always written, header-only if nothing is banned). See [Internals]({{< relref "/docs/architecture/internals/" >}}) for the full jail structure.
