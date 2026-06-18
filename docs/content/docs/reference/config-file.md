---
title: "Config File"
description: "TOML configuration file schema and reference"
summary: "Complete reference for flokbn TOML configuration files"
date: 2025-10-09T10:00:00+00:00
lastmod: 2026-06-18T10:00:00+00:00
draft: false
weight: 220
slug: "config-file"
toc: true
seo:
  title: "flokbn Config File Reference"
  description: "Complete TOML configuration file reference for flokbn static and live modes"
  canonical: ""
  noindex: false
---

flokbn uses TOML configuration files for complex multi-trie setups. Both CLI flags and TOML build the same internal `*config.Config` struct.

## File Structure

```toml
[global]        # Shared settings (jail, ban, whitelist/blacklist files)
[log]           # Logging settings (level, format) - live mode
[static]        # Static mode base settings (logFile, logFormat)
[static.NAME]   # One or more named tries for static mode
[live]          # Live mode base settings (port)
[live.NAME]     # One or more named windows for live mode
```

A config file may contain both `[static]` and `[live]` sections; the `static` command only reads `[static]` (plus `[global]`/`[log]`), the `live` command only reads `[live]`. Keeping one file per mode is still the clearer setup.

## [global] Section

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `jailFile` | string | Live: yes, Static: no | Path to jail state file |
| `banFile` | string | Live: yes, Static: no | Path to ban list output |
| `whitelist` | string | No | Path to IP whitelist file |
| `blacklist` | string | No | Path to IP blacklist file |
| `userAgentWhitelist` | string | No | Path to User-Agent whitelist file |
| `userAgentBlacklist` | string | No | Path to User-Agent blacklist file |

All paths should be absolute.

## [static] Section

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `logFile` | string | Yes | Path to log file |
| `logFormat` | string | No | Log format string (see [Log Formats]({{< relref "/docs/reference/log-formats/" >}})) |
| `plotPath` | string | No | Path for heatmap HTML output |

> **Note on casing:** the TOML key is `logFile` (camelCase). The equivalent CLI flag is `--logfile` (all lowercase). This divergence is intentional and the two are not interchangeable - use `logFile` in config files and `--logfile` on the command line.

### Static Tries: [static.NAME]

Each `[static.NAME]` section defines an independent analysis trie. The `NAME` is a freeform label.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `clusterArgSets` | array of arrays | No | Cluster parameters. Without it the trie only reports parse stats and `cidrRanges` analysis. See [Clustering]({{< relref "/docs/reference/clustering/" >}}). |
| `useForJail` | array of bools | No | Which cluster arg sets contribute to the jail. **Omit it entirely** and every set is detected and reported but never jailed. If you *do* provide it, it must have **exactly one entry per `clusterArgSets` row** - a present-but-mismatched length aborts the load (see [Validation Rules](#validation-rules)). |
| `cidrRanges` | array of strings | No | Report request counts for specific networks (reporting only, not a filter). **IPv4 CIDRs only**; an IPv6 entry aborts the load (IPv4-only tool). |
| `useragentRegex` | string | No | User-Agent filter regex |
| `endpointRegex` | string | No | Endpoint filter regex |
| `startTime` | string | No | Start of time window (RFC3339, e.g. `"2025-01-15T00:00:00Z"`) |
| `endTime` | string | No | End of time window (RFC3339) |

## [live] Section

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `port` | string | Yes | Lumberjack protocol listening port |
| `readTimeout` | string | No | TCP read timeout for the ingestor (duration string; default `5s`) |
| `statsListen` | string | No | `host:port` for the HTTP stats server (`GET /stats`, `GET /bans`, Prometheus `GET /metrics`); empty = off |
| `topTalkers` | int | No | Include the top-N IPs per window in `/stats`; `0` = off |

### Live Windows: [live.NAME]

Each `[live.NAME]` section defines an independent sliding window (own filters, own time/size bounds, own cluster arg sets). All windows share the same jail and ban file.

All windows are processed by a **single detection loop**: each iteration reads one batch, updates every window, runs every cluster arg set, then sleeps. The sleep is the **largest** `sleepBetweenIterations` across all windows - a window asking for `5` will not run more often than another asking for `10`.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `slidingWindowMaxTime` | string | Yes | Window time span (e.g. `"2h"`, `"30m"`); validated `> 0` at load |
| `slidingWindowMaxSize` | int | Yes | Maximum requests in window; validated `> 0` at load |
| `sleepBetweenIterations` | int | No | Seconds between detection runs (largest value across windows wins, see above); not load-validated, omitted/`0` is accepted (an internal heartbeat floor still ticks the loop) |
| `clusterArgSets` | array of arrays | Yes | Cluster parameters; at least one row is required at load |
| `useForJail` | array of bools | No | Which cluster arg sets contribute to the jail. Omit it entirely and every set is detected but never jailed; if present it must have one entry per `clusterArgSets` row or the load aborts. |
| `useragentRegex` | string | No | User-Agent filter regex |
| `endpointRegex` | string | No | Endpoint filter regex |

The fields marked **Yes** are validated at load: a window missing `slidingWindowMaxTime`, `slidingWindowMaxSize`, or `clusterArgSets` (or setting either size/time to `0`) aborts startup with an error naming the offending `[live.NAME]` window. See [Validation Rules](#validation-rules).

Duration strings accept any Go duration: `s` (seconds), `m` (minutes), `h` (hours), also `ms` etc. Examples: `"2h"`, `"30m"`, `"1h30m"`.

## [log] Section

Configures the leveled log lines live mode writes to **stderr** (timestamps included). Machine-readable live data is served by the HTTP endpoints (`GET /stats`, `GET /bans`, `GET /metrics`); static mode's report output is unaffected.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `level` | string | No | `debug`, `info`, `warn`, or `error` (default: `info`) |
| `format` | string | No | `text` or `json` (default: `text`) |

```toml
[log]
level = "info"
format = "text"
```

Unknown keys in `[log]` are rejected at load time, as are invalid `level`/`format` values. The `--logLevel` CLI flag overrides `level`.

## Time Formats

TOML config files use RFC3339 for absolute timestamps:

```toml
startTime = "2025-01-15T00:00:00Z"
endTime = "2025-01-15T23:59:59Z"
startTime = "2025-01-15T00:00:00-05:00"  # with timezone
```

CLI flags use a flexible format instead (`YYYY-MM-DD`, `YYYY-MM-DD HH`, `YYYY-MM-DD HH:MM`).

## Validation Rules

Enforced at load/startup (the run aborts with an error):

1. `[static]` requires an existing `logFile`
2. `[live]` requires `port`, plus `jailFile` and `banFile` in `[global]`, plus at least one `[live.NAME]` window
3. `statsListen`, when set, must be a valid `host:port`; `topTalkers` must be >= 0
4. Regex patterns and duration strings must compile/parse
5. When using `--config`, most other CLI flags produce an error (static allows `--tui`, `--compact`, `--plain`; live allows only `--logLevel`)
6. **Unknown top-level sections and unknown keys are rejected.** A misspelled section header (e.g. `[gloabl]`, `[satic]`) aborts the load naming the unknown section. Unknown keys in `[global]`, `[static]`, `[live]`, `[log]`, and every `[static.NAME]`/`[live.NAME]` trie sub-table are rejected naming the offending key and section. A wrong-typed scalar (e.g. `port = 8080` as an integer instead of a string) also fails loud at load.
7. `[log]` rejects invalid `level`/`format` values.
8. **Each `clusterArgSets` row must have exactly 4 numeric values** `[minSize, minDepth, maxDepth, threshold]` with `minDepth <= maxDepth <= 32`. A malformed row (wrong count, non-numeric value, or out-of-range depth) aborts the load naming the offending row index - identical to the CLI flag path.
9. **A present `useForJail` must have exactly one entry per `clusterArgSets` row.** A present-but-mismatched length aborts the load. (Omitting `useForJail` entirely is still valid and means "never jail any set".)
10. **`[live.NAME]` windows are validated per window**: `slidingWindowMaxSize > 0`, `slidingWindowMaxTime > 0`, and at least one `clusterArgSets` row. A window missing or zeroing any of these aborts startup with a message naming the `[live.NAME]` window.
11. `cidrRanges` entries must be valid **IPv4** CIDRs; an IPv6 entry aborts the load (IPv4-only tool), in both static and live tries.

**Not** enforced - silently tolerated, so double-check it by hand:

- An invalid RFC3339 `startTime`/`endTime` in `[static.NAME]` does **not** abort the run: it surfaces as a diagnostic in the output and the time filter is silently skipped (all requests are analyzed).

## Complete Static Example

```toml
[global]
jailFile = "/var/lib/flokbn/jail.json"
banFile = "/var/lib/flokbn/ban.txt"
whitelist = "/etc/flokbn/whitelist.txt"
blacklist = "/etc/flokbn/blacklist.txt"

[static]
logFile = "/var/log/nginx/access.log"
logFormat = "%^ %^ %^ [%t] \"%r\" %s %b %^ \"%u\" \"%h\""
plotPath = "/tmp/heatmap.html"

# General detection across all traffic
[static.comprehensive_scan]
cidrRanges = ["203.0.113.0/24", "198.51.100.0/24"]
clusterArgSets = [
  [1000, 24, 32, 0.1],   # Small clusters
  [5000, 20, 28, 0.2]    # Medium clusters
]
useForJail = [true, true]

# Filtered by User-Agent
[static.filtered]
clusterArgSets = [[100, 30, 32, 0.05]]
useForJail = [true]

# API abuse in a specific time window
[static.api_abuse]
endpointRegex = "/api/.*"
startTime = "2025-10-09T00:00:00Z"
endTime = "2025-10-09T23:59:59Z"
clusterArgSets = [[500, 28, 32, 0.1]]
useForJail = [true]
```

## Complete Live Example

```toml
[global]
jailFile = "/var/lib/flokbn/jail.json"
banFile = "/var/lib/flokbn/ban.txt"
whitelist = "/etc/flokbn/whitelist.txt"
blacklist = "/etc/flokbn/blacklist.txt"
userAgentWhitelist = "/etc/flokbn/ua_whitelist.txt"
userAgentBlacklist = "/etc/flokbn/ua_blacklist.txt"

[live]
port = "8080"
statsListen = "127.0.0.1:8666"  # HTTP /stats, /bans, /metrics (optional)
topTalkers = 5                  # top-N IPs per window in /stats (optional)

# Main detection - 2 hour window
[live.detection]
slidingWindowMaxTime = "2h"
slidingWindowMaxSize = 100000
sleepBetweenIterations = 10
clusterArgSets = [
  [1000, 24, 32, 0.1],
  [5000, 20, 28, 0.2]
]
useForJail = [true, true]

# Fast filtering - 1 hour window
[live.fast]
slidingWindowMaxTime = "1h"
slidingWindowMaxSize = 50000
sleepBetweenIterations = 5
clusterArgSets = [[100, 30, 32, 0.05]]
useForJail = [true]

# API abuse - 30 minute window
[live.api_abuse]
slidingWindowMaxTime = "30m"
slidingWindowMaxSize = 25000
sleepBetweenIterations = 5
endpointRegex = "/api/.*"
clusterArgSets = [[500, 28, 32, 0.1]]
useForJail = [true]
```

For a complete, working live config you can run immediately, see `docker-test-config.demo.toml` in the repository root - it drives the [Docker demo stack]({{< relref "/docs/guides/docker-testing/" >}}).

## Troubleshooting

**TOML syntax error**: Use `=` not `:` for assignments. Strings must be quoted.

**Missing required field**: Check the required columns in the tables above.

**Invalid cluster arguments**: A malformed `clusterArgSets` row now **aborts the load** with a message naming the offending row index. Each row needs exactly 4 numeric values `[minSize, minDepth, maxDepth, threshold]` with `minDepth <= maxDepth <= 32`; fix the named row and rerun.

**`useForJail` length mismatch**: If you provide `useForJail`, it must have exactly one entry per `clusterArgSets` row or the load aborts naming both lengths. Either match the lengths or omit `useForJail` entirely (which means "never jail any set").

**File not found**: Verify the path exists and is absolute.

**Detections never banned**: Check `useForJail` - sets with a `false` (or omitted `useForJail` entirely) are reported but never jailed.
