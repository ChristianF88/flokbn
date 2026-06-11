---
title: "Config File"
description: "TOML configuration file schema and reference"
summary: "Complete reference for cidrx TOML configuration files"
date: 2025-10-09T10:00:00+00:00
lastmod: 2026-06-11T10:00:00+00:00
draft: false
weight: 220
slug: "config-file"
toc: true
seo:
  title: "cidrx Config File Reference"
  description: "Complete TOML configuration file reference for cidrx static and live modes"
  canonical: ""
  noindex: false
---

cidrx uses TOML configuration files for complex multi-trie setups. Both CLI flags and TOML build the same internal `*config.Config` struct.

## File Structure

```toml
[global]        # Shared settings (jail, ban, whitelist/blacklist files)
[log]           # Logging settings (level, format) — live mode
[static]        # Static mode base settings (logFile, logFormat)
[static.NAME]   # One or more named tries for static mode
[live]          # Live mode base settings (port)
[live.NAME]     # One or more named windows for live mode
```

A config file contains **either** `[static]` or `[live]` sections, not both.

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

### Static Tries: [static.NAME]

Each `[static.NAME]` section defines an independent analysis trie. The `NAME` is a freeform label.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `clusterArgSets` | array of arrays | Yes | Cluster parameters. See [Clustering]({{< relref "/docs/reference/clustering/" >}}). |
| `useForJail` | array of bools | Yes | Which cluster arg sets contribute to jail. Must match `clusterArgSets` length. |
| `cidrRanges` | array of strings | No | Focus on specific CIDR ranges |
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

Each `[live.NAME]` section defines an independent sliding window. All windows run concurrently and share the same jail.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `slidingWindowMaxTime` | string | Yes | Window time span (e.g. `"2h"`, `"30m"`) |
| `slidingWindowMaxSize` | int | Yes | Maximum requests in window |
| `sleepBetweenIterations` | int | Yes | Seconds between detection runs |
| `clusterArgSets` | array of arrays | Yes | Cluster parameters |
| `useForJail` | array of bools | Yes | Which cluster arg sets contribute to jail |
| `useragentRegex` | string | No | User-Agent filter regex |
| `endpointRegex` | string | No | Endpoint filter regex |

Duration strings support: `s` (seconds), `m` (minutes), `h` (hours). Examples: `"2h"`, `"30m"`, `"1h30m"`.

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

1. `useForJail` must have the same length as `clusterArgSets`
2. `clusterArgSets` entries must have exactly 4 values: `[minSize, minDepth, maxDepth, threshold]`
3. `[static]` requires `logFile`
4. `[live]` requires `port`
5. Live mode requires `jailFile` and `banFile` in `[global]`
6. When using `--config`, most other CLI flags produce an error (static allows `--tui`, `--compact`, `--plain`; live allows `--compact`, `--plain`, `--logLevel`)
7. `[log]` rejects unknown keys and invalid `level`/`format` values

## Complete Static Example

```toml
[global]
jailFile = "/var/lib/cidrx/jail.json"
banFile = "/var/lib/cidrx/ban.txt"
whitelist = "/etc/cidrx/whitelist.txt"
blacklist = "/etc/cidrx/blacklist.txt"

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
jailFile = "/var/lib/cidrx/jail.json"
banFile = "/var/lib/cidrx/ban.txt"
whitelist = "/etc/cidrx/whitelist.txt"
blacklist = "/etc/cidrx/blacklist.txt"
userAgentWhitelist = "/etc/cidrx/ua_whitelist.txt"
userAgentBlacklist = "/etc/cidrx/ua_blacklist.txt"

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

## Troubleshooting

**TOML syntax error**: Use `=` not `:` for assignments. Strings must be quoted.

**Missing required field**: Check the required columns in the tables above.

**Invalid cluster arguments**: Each entry needs exactly 4 values: `[[minSize, minDepth, maxDepth, threshold]]`.

**File not found**: Verify the path exists and is absolute.

**Array length mismatch**: `useForJail` must have the same number of entries as `clusterArgSets`.
