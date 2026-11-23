---
title: "Output Formats"
description: "Static report formats (JSON, plain text, TUI) and live mode outputs (ban file, jail file, HTTP endpoints)"
summary: "Complete reference for flokbn output: static analysis reports and the files and HTTP endpoints live mode produces"
date: 2025-10-09T10:00:00+00:00
lastmod: 2026-11-23T10:00:00+00:00
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
- **[Live mode](#live-mode-output)** runs forever and writes **no report at all**. Its output is the jail and ban files (rewritten whenever their content changes), leveled log lines on stderr, and three HTTP endpoints (`/stats`, `/bans`, `/metrics`).

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
flokbn static --logfile access.log --clusterArgSets 1000,24,32,0.1
```

#### Schema

The top level contains `metadata`, `general`, one entry per trie under `tries`, the `warnings`/`errors` arrays, and `global_filters`:

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
    "unique_ips": "number (distinct client IPs in the whole log, before any trie filter)",
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
        "ua_whitelist_excluded": "number (requests kept out of this trie by the User-Agent whitelist; present only when > 0)",
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
  "useragent_blacklist_ips": ["string (present only when a User-Agent blacklist matched)"],
  "global_filters": {
    "ip_whitelist_cidrs": "number",
    "ua_whitelist_patterns": "number"
  }
}
```

`tries[].data` holds one entry per cluster arg set. `detected_ranges` are the raw per-set detections; `merged_ranges` are the same detections after overlapping/adjacent CIDRs are merged - the merged list is what feeds the jail. Empty/optional fields are omitted (`omitempty`).

`global_filters` is **always present**, with zero counts when no whitelist is configured. It carries only the number of entries in the IP whitelist and in the User-Agent whitelist, not the entries. Only the User-Agent whitelist removes requests from the tries (the per-trie effect is `stats.ua_whitelist_excluded`); the IP whitelist acts in the jail/ban pipeline alone, so whitelisted traffic is still counted in every statistic.

`useragent_whitelist_ips` and `useragent_blacklist_ips` list each address once, in ascending order.

All clustering results and CIDR range statistics are per trie: read `tries[].data` and `tries[].stats.cidr_analysis`. There are no top-level `clustering` or `cidr_analysis` keys. Earlier versions emitted both as objects whose `data` array was always empty; they have been removed, so a consumer that iterated over `.clustering.data` or `.cidr_analysis.data` (and never got an element) must switch to the per-trie paths.

#### Processing with jq

```bash
# Extract all merged CIDRs from every trie and cluster set
flokbn static --logfile access.log --clusterArgSets 1000,24,32,0.1 | \
  jq -r '.tries[].data[].merged_ranges[].cidr'

# Get CIDRs with > 1000 requests
flokbn static --logfile access.log --clusterArgSets 1000,24,32,0.1 | \
  jq -r '.tries[].data[].merged_ranges[] | select(.requests > 1000) | .cidr'

# Total requests parsed
flokbn static --logfile access.log --clusterArgSets 1000,24,32,0.1 | \
  jq '.general.total_requests'
```

#### Python Processing

```python
import json, subprocess

result = subprocess.run(
    ['flokbn', 'static', '--logfile', 'access.log',
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
flokbn static --logfile access.log --clusterArgSets 1000,24,32,0.1 --compact
```

Useful for SIEM ingestion, message queues, and log aggregation:

```bash
# Send to Elasticsearch
flokbn static --logfile access.log --clusterArgSets 1000,24,32,0.1 --compact | \
  curl -X POST "localhost:9200/flokbn-detections/_doc" \
       -H 'Content-Type: application/json' -d @-

# Append to log file
flokbn static --logfile access.log --clusterArgSets 1000,24,32,0.1 --compact >> \
  /var/log/flokbn/detections.log
```

### Plain Text

Human-readable formatted output with box-drawing characters and aligned columns.

```bash
flokbn static --logfile access.log --clusterArgSets 1000,24,32,0.1 --plain
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
flokbn static --logfile access.log \
  --startTime "2025-10-09" --endTime "2025-10-09 23:59" \
  --clusterArgSets 1000,24,32,0.1 --plain > daily-report.txt

# Email
flokbn static --logfile access.log --clusterArgSets 1000,24,32,0.1 --plain | \
  mail -s "flokbn Report" admin@example.com
```

### TUI (Interactive)

Terminal user interface that runs the analysis and presents the results in scrollable panels, plus an address-space visualization of the detected clusters.

```bash
flokbn static --config flokbn.toml --tui
flokbn static --logfile access.log --clusterArgSets 1000,24,32,0.1 --tui
```

**Views**: a results view with four panels - Summary, Clustering, CIDR Analysis, Diagnostics - and a visualization view showing where detections sit in the address space.

**Keys**: `Tab`/`Shift+Tab` switch panels, arrow keys scroll, `t` cycles tries (multi-trie configs), `v` opens the visualization (`←`/`→` change cluster set, `l` toggles linear/sqrt/log scale), `r` returns to results, `p` shows progress, `q` quits.

Works both with `--config` and CLI-only parameters. Available in static mode only (not live mode).

### Generating Firewall Rules from JSON

```bash
# iptables rules
flokbn static --logfile access.log --clusterArgSets 1000,24,32,0.1 | \
  jq -r '.tries[].data[].merged_ranges[].cidr' | \
  sed 's/^/iptables -A INPUT -s /; s/$/ -j DROP/' > rules.sh

# nginx deny directives
flokbn static --logfile access.log --clusterArgSets 1000,24,32,0.1 | \
  jq -r '.tries[].data[].merged_ranges[].cidr' | \
  sed 's/^/deny /; s/$/;/' > nginx-deny.conf
```

### Performance Impact

Format choice barely affects runtime - use `--compact` for automated pipelines, `--plain` for human consumption, and avoid the TUI for very large datasets (full terminal rendering is the slowest path).

### Error Output

Fatal errors (missing log file, invalid flags, bad config) are printed as a plain message and the process exits with code 1 - no JSON is produced. Non-fatal problems during an analysis (a failed heatmap, jail-processing errors, whitelist notices, skipped lines) land in the JSON `warnings` and `errors` arrays:

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

The warning types an analysis can report:

| `type` | Meaning |
|--------|---------|
| `oversized_lines` | Lines longer than 2 MiB (2,097,152 bytes) were skipped; the message gives the number. The rest of the file is analysed normally. |
| `invalid_ips_skipped` | Requests whose `%h` field is not a valid IPv4 address were left out of the named trie - usually a `logFormat` that does not match the log. |
| `malformed_field` | Requests with a non-numeric status or bytes field; the lines are kept with that field as 0. |
| `empty_logfile` | No request was parsed. When a jail and ban file are configured they are still refreshed (expired bans leave the ban file). |
| `time_filter_no_results` | A trie's `startTime`/`endTime` matched no request. |
| `invalid_cidr`, `cidr_parse_error` | A range could not be counted or parsed. |
| `whitelist_applied` | Detected ranges were kept out of the jail by the whitelist. |
| `blacklist_applied` | Manual blacklist entries were added to the ban file. |
| `jail_update` | Some ranges could not be added to the jail. |
| `config_warning` | A trie configuration was empty or missing. |
| `info` | Informational notices, for example where the heatmap was written. |

Check the exit code in scripts:
```bash
if flokbn static --logfile access.log --clusterArgSets 1000,24,32,0.1 > output.json; then
    jq -r '.tries[].data[].merged_ranges[].cidr' output.json > blocklist.txt
else
    echo "Analysis failed"
    exit 1
fi
```

## Live Mode Output

Live mode produces **no stdout report** - `--plain`, `--compact`, and `--tui` are static-only flags, and the live command rejects them with an error. Its output consists of:

1. **The jail and ban files** (formats [below](#ban-file-format)). Each is written only when its content changed: an iteration that re-detects ranges which are already banned writes nothing.
2. **Leveled log lines on stderr** - one summary line per iteration (window size, batch size, detected/merged/jailed counts, timings) plus connection events, warnings and errors (see [Log Lines](#log-lines)). Configured via the `[log]` section or `--logLevel`.
3. **HTTP endpoints**, when `statsListen` is set in the `[live]` config section (config file only - there is no CLI flag for it).

### Log Lines

Every iteration that processed a batch logs one `iteration` line at level `info`:

| Field | Meaning |
|-------|---------|
| `window` | Requests currently held, summed over all windows |
| `batch` | Requests read in this iteration (without those dropped by the User-Agent whitelist) |
| `detected` | Ranges detected by all cluster arg sets of all windows |
| `merged` | Jail-eligible ranges after merging |
| `jailed` | Ranges handed to the jail (after dropping fully whitelisted ones, plus User-Agent-blacklisted `/32`s) |
| `pruned` | Long-expired entries removed from the jail |
| `active_bans` | Jail bans published to the ban file (after the whitelist) |
| `ban_file_written` | `true` when the ban file was rewritten in this iteration: the published list changed, or it is the first write since startup |
| `jail_file_written` | `true` when the jail file was rewritten in this iteration: the jail content changed, or it is the first write since startup |
| `loop_ms`, `cluster_ms` | Duration of the iteration and of its clustering part |

While no batch arrives, an idle heartbeat runs instead, once the loop has been idle for `sleepBetweenIterations` seconds (the largest value across windows, and at least one second). It expires window entries and bans, rewrites the files if that changed them, and logs a `heartbeat` line at level `debug` with `expired` (bans that ran out), `active_bans`, `ban_file_written` and `window_expired` (requests that aged out of the windows).

Other lines worth alerting on or grepping for:

| Message | Level | Meaning |
|---------|-------|---------|
| `Filebeat connected` / `Filebeat disconnected` | info | A shipper connection was opened or closed (`remote`, `open_connections`, and a `reason` when it did not end cleanly). `waiting for Filebeat to connect` at startup only says the listener is up. |
| `Filebeat disconnected: protocol violation` | warn | The peer broke the protocol or one of the [size limits]({{< relref "/docs/guides/live-protection/#protocol-limits" >}}). |
| `ingest connection rejected: connection limit reached` | warn | More than 64 simultaneous connections. |
| `ingest listener is reachable from other hosts and does not authenticate clients ...` | warn | Logged at startup when `listen` is not a loopback address and mutual TLS is not enabled. |
| `most request timestamps fall outside the sliding window on arrival` | warn | More than half of a batch was stamped older than the window (`stale`) or more than a minute in the future (`future`). Log time and the clock of the flokbn host disagree - typically a log format without a UTC offset on a host that is not on UTC - so requests expire on arrival and nothing is detected. At most once per minute and window. |
| `[live.NAME] startTime has no effect in live mode and is ignored ...` | warn | A `[live.NAME]` table sets `startTime`, `endTime` or `cidrRanges`. |

Per-connection lines are rate-limited (20 per 10 seconds); a `suppressed_log_lines` field reports how many were dropped.

### HTTP Endpoints

```toml
[live]
port = "8080"
statsListen = "127.0.0.1:8666"
topTalkers = 5   # optional: top-N IPs per window in /stats
```

| Endpoint | Content |
|----------|---------|
| `GET /stats` | JSON snapshot of the last iteration: `ingest` (open shipper connections, queue, totals, parse errors), `windows` (size, accepted/rejected counts, per-set detections and timings, optional `top_talkers`), `jail` (active bans per stage with start/expiry), `lists`, `loop` |
| `GET /bans` | The ban file content last written to disk, verbatim (`text/plain`) - what enforcement tooling should poll |
| `GET /metrics` | Prometheus exposition format; all metrics are prefixed `flokbn_` (ingest, window, cluster, jail, ban-file, and loop families) |

All three return `503` with a `Retry-After` header until the loop has published its first snapshot (after the first iteration or the first idle heartbeat). The snapshot updates once per iteration or heartbeat, not per request. Bind to localhost unless you have a reason not to.

#### /stats fields

| Field | Meaning |
|-------|---------|
| `ingest.connected` | `true` while at least one shipper connection is open (`open_connections > 0`). A listener nobody is connected to reports `false`. |
| `ingest.open_connections` | Shipper connections open right now |
| `ingest.queue_depth` | Batches received but not yet read by the detection loop |
| `ingest.last_batch_at`, `ingest.batches_total`, `ingest.requests_total` | Time of the last batch, batches and parsed requests since startup |
| `ingest.parse_errors_total` | Events dropped because they could not be decoded or parsed |
| `ingest.malformed_fields_total` | Non-numeric status/bytes fields in lines that were kept |
| `windows[].size_ips`, `windows[].requests` | Distinct IPs and requests currently in the window |
| `windows[].accepted_total`, `windows[].rejected_by_filter_total` | Requests accepted into, or rejected by the regex filters of, the window since startup |
| `windows[].cluster_sets[]` | Per cluster arg set: `params`, `use_for_jail`, `last_duration_us`, `detected_now` (ranges with request counts) |
| `windows[].top_talkers` | Top-N IPs, only with `topTalkers > 0` |
| `jail.total_active`, `jail.stages[]` | Active bans in total and per stage. This is the jail before the whitelist is applied. |
| `jail.active_bans[]`, `jail.active_bans_truncated` | Up to 500 active bans (`cidr`, `stage`, `ban_start`, `expires_at`); `active_bans_truncated` is `true` when there are more. `total_active` is always exact. |
| `lists.whitelist`, `lists.blacklist` | `path`, `entries`, and up to 1000 `cidrs` |
| `lists.user_agent_lists` | Hit counters and currently tracked IPs of the User-Agent lists |
| `lists.ban_file` | `path`, `entries`, and `last_written`: the time the ban file was last rewritten, which is the last time the published list **changed** (not the last iteration) |
| `lists.jail_file.path` | Path of the jail file |
| `loop.iterations`, `loop.heartbeats_total` | Iterations that processed a batch, and idle heartbeats |
| `loop.last_duration_ms`, `loop.sleep_s` | Duration of the last iteration, and the effective `sleepBetweenIterations` |

**The window numbers decay while the loop is idle.** The idle heartbeat expires entries from the sliding windows, so `size_ips`, `requests`, `detected_now` and `top_talkers` (and the matching metrics) shrink as traffic ages out instead of staying frozen at their last busy values. Detections recomputed by a heartbeat are for display only: bans are raised solely by iterations that process traffic.

#### /metrics

| Metric | Type | Meaning |
|--------|------|---------|
| `flokbn_uptime_seconds` | gauge | Seconds since the live loop started |
| `flokbn_ingest_connected` | gauge | `1` while at least one shipper connection is open, else `0` |
| `flokbn_ingest_open_connections` | gauge | Shipper connections currently open |
| `flokbn_ingest_queue_depth` | gauge | Batches buffered in the ingest queue |
| `flokbn_ingest_batches_total`, `flokbn_ingest_requests_total` | counter | Batches received / requests parsed |
| `flokbn_ingest_parse_errors_total`, `flokbn_ingest_malformed_fields_total` | counter | Dropped events / malformed fields in kept lines |
| `flokbn_window_unique_ips{window}`, `flokbn_window_requests{window}` | gauge | Distinct IPs / requests currently in the window |
| `flokbn_window_accepted_total{window}`, `flokbn_window_rejected_by_filter_total{window}` | counter | Requests accepted into / rejected by the filters of the window |
| `flokbn_cluster_detected{window,set}` | gauge | Ranges detected by this cluster arg set in its latest run (`set` is the zero-based index of the set within the window) |
| `flokbn_cluster_duration_seconds{window,set}` | gauge | Clustering runtime of that run |
| `flokbn_jail_active` | gauge | Active bans in the jail (before the whitelist); always the full count |
| `flokbn_jail_stage_active{stage}` | gauge | Active bans per jail stage |
| `flokbn_ban_active{cidr,stage}` | gauge | One series (value `1`) per actively banned range, capped at 500 series |
| `flokbn_ban_active_truncated` | gauge | `1` when the `flokbn_ban_active` series were cut off at the cap, `0` when they are complete |
| `flokbn_ban_file_entries` | gauge | Entries in the last published ban file |
| `flokbn_ua_list_hits_total{list}`, `flokbn_ua_list_active_ips{list}` | counter / gauge | User-Agent list hits and currently tracked IPs (`list` is `whitelist` or `blacklist`) |
| `flokbn_loop_iterations_total`, `flokbn_loop_heartbeats_total` | counter | Iterations that processed a batch / idle heartbeats |
| `flokbn_loop_duration_seconds` | gauge | Duration of the last iteration |

Count bans with `flokbn_jail_active`, not with `count(flokbn_ban_active)`: the per-range series stop at 500, and `flokbn_ban_active_truncated` tells whether that happened.

See the [Live Protection guide]({{< relref "/docs/guides/live-protection/" >}}) for deployment and the [Docker demo]({{< relref "/docs/guides/docker-testing/" >}}) for a working closed-loop example that polls `/bans`.

## Ban File Format

Written when both `--jailFile` and `--banFile` are specified. Static mode writes it once at the end of every run. Live mode writes it when the published list changes (a ban was added, expired or whitelisted away), on the first heartbeat or iteration after startup, and when the file has gone missing - not on every iteration. In live mode the timestamp in the header therefore is the time of the **last content change**; a ban file with an old timestamp is normal while the set of bans is stable. The file contains that timestamp header, the active jail bans, and - when a manual blacklist is configured - a blacklist section. Comment lines start with `#`:

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
grep -v '^#' /var/lib/flokbn/ban.txt | while read -r cidr; do
  [ -n "$cidr" ] && iptables -I INPUT -s "$cidr" -j DROP
done

# nginx format
grep -v '^#' /var/lib/flokbn/ban.txt | sed 's/^/deny /; s/$/;/' > /etc/nginx/flokbn-bans.conf
```

In live mode the same content is served over HTTP as `GET /bans`, which avoids file-distribution entirely - poll the endpoint instead of shipping the file.

## Jail File Format

The jail file (`--jailFile`) persists detection state as JSON. In static mode it is only created once at least one range has actually been jailed - a run with no detections leaves no jail file behind (the ban file, in contrast, is always written, header-only if nothing is banned). Live mode writes it in the first iteration that processes a batch and afterwards only when the jail content changed (a new or escalated ban, an expiry, a pruned entry) or the file has gone missing. See [Internals]({{< relref "/docs/architecture/internals/" >}}) for the full jail structure.
