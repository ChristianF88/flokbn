---
title: "Config File"
description: "TOML configuration file schema and reference"
summary: "Complete reference for flokbn TOML configuration files"
date: 2025-10-09T10:00:00+00:00
lastmod: 2026-11-23T10:00:00+00:00
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
[live]          # Live mode base settings (port, listen address, TLS, stats server)
[live.NAME]     # One or more named windows for live mode
```

A config file may contain both `[static]` and `[live]` sections; the `static` command only reads `[static]` (plus `[global]`/`[log]`), the `live` command only reads `[live]`. Keeping one file per mode is still the clearer setup.

Each of the four top-level names must be a table: a `[global]` header followed by `key = value` lines. Writing one as a value (`global = "x"`) or as an array of tables (`[[global]]`) aborts the load with `section [global] must be a table`.

## [global] Section

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `jailFile` | string | Live: yes, Static: no | Path to jail state file |
| `banFile` | string | Live: yes, Static: no | Path to ban list output |
| `whitelist` | string | No | Path to IP whitelist file (one IPv4 CIDR or bare IPv4 address per line) |
| `blacklist` | string | No | Path to IP blacklist file (same format) |
| `userAgentWhitelist` | string | No | Path to User-Agent whitelist file (one exact User-Agent string per line) |
| `userAgentBlacklist` | string | No | Path to User-Agent blacklist file (same format) |

All paths should be absolute. See [Filtering]({{< relref "/docs/reference/filtering/" >}}) for the list file formats. In static mode the User-Agent lists need a `%u` field in `logFormat` (see [Validation Rules](#validation-rules)).

## [static] Section

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `logFile` | string | Yes | Path to log file |
| `logFormat` | string | No | Log format string (see [Log Formats]({{< relref "/docs/reference/log-formats/" >}})) |
| `plotPath` | string | No | Path for heatmap HTML output |

> **Note on casing:** the TOML key is `logFile` (camelCase) and only that spelling is accepted in a config file. On the command line the flag is `--logfile`, with `--logFile` accepted as an alias.

### Static Tries: [static.NAME]

Each `[static.NAME]` section defines an independent analysis trie. The `NAME` is a freeform label.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `clusterArgSets` | array of arrays | No | Cluster parameters. Without it the trie only reports parse stats and `cidrRanges` analysis. See [Clustering]({{< relref "/docs/reference/clustering/" >}}). |
| `useForJail` | array of bools | No | Which cluster arg sets contribute to the jail. **Omit it entirely** and every set is detected and reported but never jailed. If you *do* provide it, it must have **exactly one entry per `clusterArgSets` row** - a present-but-mismatched length aborts the load (see [Validation Rules](#validation-rules)). |
| `cidrRanges` | array of strings | No | Report request counts for specific networks (reporting only, not a filter). **IPv4 only**: a CIDR (`"203.0.113.0/24"`) or a bare address (`"203.0.113.7"`, counted as `/32`); an IPv6 entry aborts the load (IPv4-only tool). |
| `useragentRegex` | string | No | User-Agent filter regex. Needs `%u` in `logFormat`. |
| `endpointRegex` | string | No | Endpoint filter regex. Needs `%r` or `%U` in `logFormat`. |
| `startTime` | string | No | Start of time window, e.g. `"2025-01-15T00:00:00Z"` or `"2025-01-15 14:00"` (see [Time Formats](#time-formats)). Needs `%t` in `logFormat`. |
| `endTime` | string | No | End of time window (same formats). Needs `%t` in `logFormat`. |

A filter whose field the effective `logFormat` does not extract is rejected at startup instead of silently matching nothing (or, for `endTime`, everything) - see [Validation Rules](#validation-rules).

## [live] Section

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `port` | string | Yes | Lumberjack protocol listening port |
| `listen` | string | No | Address the Lumberjack listener binds to (default `127.0.0.1`): an IP address or host name **without** a port. The port does not authenticate shippers unless `tlsClientCA` is set, so use another address (e.g. `0.0.0.0`) only with client certificates or when access to the port is restricted to your log shippers. A non-loopback address without mutual TLS logs a warning at startup. Also available as `--listen`. |
| `tlsCert` | string | No | PEM certificate of the Lumberjack listener. Together with `tlsKey` it makes the listener speak TLS (encrypted, but any client is accepted). Config file only. |
| `tlsKey` | string | No | PEM private key for `tlsCert`. The two must be set together. |
| `tlsClientCA` | string | No | PEM bundle of CA certificates. When set (requires `tlsCert` and `tlsKey`), shippers must present a certificate signed by one of them (mutual TLS) - the only authentication the port has. |
| `readTimeout` | string | No | How long a shipper may take to deliver a batch it has announced, to complete the TLS handshake, or to accept an acknowledgement (duration string; default `5s`). An idle connection between batches is not timed out. |
| `statsListen` | string | No | `host:port` for the HTTP stats server (`GET /stats`, `GET /bans`, Prometheus `GET /metrics`); empty = off. **Unauthenticated**, and `/stats` returns whitelist/blacklist CIDRs, file paths and detection thresholds: keep it on loopback or behind an authenticating proxy. |
| `topTalkers` | int | No | Include the top-N IPs per window in `/stats`; `0` = off |

The TLS files are read once at startup (restart to rotate a certificate); a missing or mismatched file aborts the start before the port is bound. See [TLS and mutual TLS]({{< relref "/docs/guides/live-protection/#tls-and-mutual-tls-for-the-ingest-listener" >}}) for the Filebeat side and [Protocol limits]({{< relref "/docs/guides/live-protection/#protocol-limits" >}}) for the fixed size and connection limits of the listener.

**There is no `logFormat` for live mode.** `[live]` rejects the key, and a `logFormat` under `[static]` does not apply. Live mode always reads the client IP from the first space-separated field of each line and expects the combined log layout after it - see [Live Protection]({{< relref "/docs/guides/live-protection/#expected-log-line-format" >}}).

### Live Windows: [live.NAME]

Each `[live.NAME]` section defines an independent sliding window (own filters, own time/size bounds, own cluster arg sets). All windows share the same jail and ban file.

All windows are processed by a **single detection loop**: each iteration reads one batch, updates every window, runs every cluster arg set, then sleeps. The sleep is the **largest** `sleepBetweenIterations` across all windows - a window asking for `5` will not run more often than another asking for `10`.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `slidingWindowMaxTime` | string | Yes | Window time span (e.g. `"2h"`, `"30m"`); validated `> 0` at load |
| `slidingWindowMaxSize` | int | Yes | Maximum requests in window; validated `> 0` at load |
| `sleepBetweenIterations` | int | No | Seconds between detection runs (largest value across windows wins, see above). Default `10` when omitted, the same as the `--sleepBetweenIterations` flag. An explicit `0` means no pause (an idle loop still polls once per second); a negative value aborts startup. |
| `clusterArgSets` | array of arrays | Yes | Cluster parameters; at least one row is required at load |
| `useForJail` | array of bools | No | Which cluster arg sets contribute to the jail. Omit it entirely and every set is detected but never jailed; if present it must have one entry per `clusterArgSets` row or the load aborts. |
| `useragentRegex` | string | No | User-Agent filter regex |
| `endpointRegex` | string | No | Endpoint filter regex |

The fields marked **Yes** are validated at load: a window missing `slidingWindowMaxTime`, `slidingWindowMaxSize`, or `clusterArgSets` (or setting either size/time to `0`) aborts startup with an error naming the offending `[live.NAME]` window. See [Validation Rules](#validation-rules).

`startTime`, `endTime` and `cidrRanges` are accepted in a `[live.NAME]` table so a trie copied from a static config keeps loading, but they **do nothing** in live mode: the window is bounded by `slidingWindowMaxTime`, and range counts are a static-mode report. The values are still validated (a malformed time or an IPv6 range aborts startup), and each such key produces a startup warning, for example `[live.detection] startTime has no effect in live mode and is ignored (the window is bounded by slidingWindowMaxTime)`.

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

`startTime` and `endTime` accept the same syntaxes in a config file and on the command line (`--startTime`, `--endTime`). In TOML the value is always a quoted string.

| Form | Example | Compared as |
|------|---------|-------------|
| RFC3339 | `"2025-01-15T00:00:00Z"`, `"2025-01-15T00:00:00-05:00"` | a true instant |
| Short form with offset | `"2025-01-15 +0100"`, `"2025-01-15 14 +0100"`, `"2025-01-15 14:00 +0100"` | a true instant |
| Short form without offset | `"2025-01-15"`, `"2025-01-15 14"`, `"2025-01-15 14:00"` | the wall-clock time of each log line, whatever offset the line carries |

```toml
startTime = "2025-01-15T00:00:00Z"
endTime = "2025-01-15T23:59:59Z"
startTime = "2025-01-15T00:00:00-05:00"  # with timezone
startTime = "2025-01-15 14:00"           # 14:00 on each log line's own clock
```

A bound with an offset selects one instant for all log lines. A bound without one matches a log line whose own clock reads that time: `"2025-01-15 06:00"` selects lines stamped `06:00 +0200` and lines stamped `06:00 -0500` alike. Log timestamps without an offset are read as UTC (see [Log Formats]({{< relref "/docs/reference/log-formats/#timestamp-t" >}})).

## Validation Rules

Enforced at load/startup (the run aborts with an error):

1. `[static]` requires an existing `logFile`
2. `[live]` requires `port`, plus `jailFile` and `banFile` in `[global]`, plus at least one `[live.NAME]` window
3. `statsListen`, when set, must be a valid `host:port`; `topTalkers` must be >= 0. `listen`, when set, must be an IP address or host name without a port. `tlsCert` and `tlsKey` must be set together and load as a key pair; `tlsClientCA` requires both and must contain at least one PEM certificate.
4. Regex patterns and duration strings must compile/parse
5. When using `--config`, most other CLI flags produce an error (static allows `--tui`, `--compact`, `--plain`; live allows only `--logLevel`)
6. **Unknown top-level sections and unknown keys are rejected.** A misspelled section header (e.g. `[gloabl]`, `[satic]`) aborts the load naming the unknown section. A known section that is not a table (`global = "x"`, `[[global]]`) aborts the load with `section [global] must be a table`. Unknown keys in `[global]`, `[static]`, `[live]`, `[log]`, and every `[static.NAME]`/`[live.NAME]` trie sub-table are rejected naming the offending key and section. A wrong-typed scalar (e.g. `port = 8080` as an integer instead of a string) also fails loud at load.
7. `[log]` rejects invalid `level`/`format` values.
8. **Each `clusterArgSets` row must have exactly 4 numeric values** `[minSize, minDepth, maxDepth, threshold]`:
   - `minSize`: a whole number from `1` to `4294967295`
   - `minDepth`, `maxDepth`: whole numbers from `0` to `32`, with `minDepth <= maxDepth`
   - `threshold`: a number from `0` to `2`

   A malformed row (wrong count, non-numeric value, fractional or negative size or depth, out-of-range value) aborts the load naming the row index and every problem in that row. The `--clusterArgSets` / `--clusterArgSet` flags apply the same rules.
9. **A present `useForJail` must have exactly one entry per `clusterArgSets` row.** A present-but-mismatched length aborts the load. (Omitting `useForJail` entirely is still valid and means "never jail any set".)
10. **`[live.NAME]` windows are validated per window**: `slidingWindowMaxSize > 0`, `slidingWindowMaxTime > 0`, `sleepBetweenIterations >= 0`, and at least one `clusterArgSets` row. A window violating any of these aborts startup with a message naming the `[live.NAME]` window.
11. `cidrRanges` entries must be valid **IPv4** CIDRs or bare IPv4 addresses (a bare address is treated as `/32`); an IPv6 entry aborts the load (IPv4-only tool), in both static and live tries. The same holds for every line of the whitelist and blacklist files and for `--rangesCidr`.
12. **`startTime`/`endTime` must parse.** A bound that is neither RFC3339 nor one of the short forms (`YYYY-MM-DD`, `YYYY-MM-DD HH`, `YYYY-MM-DD HH:MM`, each optionally followed by ` ±HHMM`) aborts the run with a diagnostic naming the trie and the offending value, as does an `endTime` before its `startTime`. The time filter is never silently skipped.
13. **Static mode: a filter needs its field in `logFormat`.** `useragentRegex`, `userAgentWhitelist` and `userAgentBlacklist` need `%u`; `endpointRegex` needs `%r` or `%U`; `startTime` and `endTime` need `%t`. The check runs against the effective format (the default when `logFormat` is omitted) and aborts the run naming the section, the key and the missing specifier, for example `[static.bots] useragentRegex needs the User-Agent of each request, but logFormat "%h" has no %u field`. Live mode has no `logFormat` and is not affected.

Not an error, but reported: `startTime`, `endTime` and `cidrRanges` in a `[live.NAME]` table each produce a startup **warning**, because they have no effect in live mode (see [Live Windows](#live-windows-livename)).

## Complete Static Example

```toml
[global]
jailFile = "/var/lib/flokbn/jail.json"
banFile = "/var/lib/flokbn/ban.txt"
whitelist = "/etc/flokbn/whitelist.txt"
blacklist = "/etc/flokbn/blacklist.txt"

[static]
logFile = "/var/log/nginx/access.log"
logFormat = "%^ %^ %^ [%t] \"%r\" %s %b \"%^\" \"%u\" \"%h\""
plotPath = "/var/lib/flokbn/heatmap.html"

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

**Invalid cluster arguments**: A malformed `clusterArgSets` row **aborts the load** with a message naming the offending row index and what is wrong with it. Each row needs exactly 4 numeric values `[minSize, minDepth, maxDepth, threshold]`: a whole `minSize >= 1`, whole depths with `0 <= minDepth <= maxDepth <= 32`, and a `threshold` between `0` and `2`; fix the named row and rerun.

**Filter needs a field the log format lacks**: In static mode a regex, User-Agent list or time bound whose field is not in `logFormat` aborts the run. Add the named specifier (`%u`, `%r`/`%U`, `%t`) to `logFormat` or remove the filter.

**`useForJail` length mismatch**: If you provide `useForJail`, it must have exactly one entry per `clusterArgSets` row or the load aborts naming both lengths. Either match the lengths or omit `useForJail` entirely (which means "never jail any set").

**File not found**: Verify the path exists and is absolute.

**Detections never banned**: Check `useForJail` - sets with a `false` (or omitted `useForJail` entirely) are reported but never jailed.
