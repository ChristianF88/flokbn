---
title: "CLI Flags"
description: "Complete command-line reference for flokbn"
summary: "Every flokbn command-line flag with type, default value, and description"
date: 2025-10-09T10:00:00+00:00
lastmod: 2026-11-23T10:00:00+00:00
draft: false
weight: 210
slug: "cli-flags"
toc: true
seo:
  title: "flokbn CLI Reference"
  description: "Complete command-line interface reference for flokbn including all flags and options"
  canonical: ""
  noindex: false
---

## Command Structure

```bash
flokbn [global options] command [command options]
```

Three commands: **`static`** (historical log analysis), **`live`** (real-time monitoring), and **`generate`** (generate ready-to-run example inputs).

## Global Options

| Flag | Description |
|------|-------------|
| `--help`, `-h` | Show help |
| `--version`, `-v` | Print the version |

## Static Mode

```bash
flokbn static [options]
```

### Core Options

| Flag | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `--config` | string | No | - | Path to TOML config file. When used, only `--tui`, `--compact`, `--plain` are allowed alongside it. All other flags produce an error. |
| `--logfile` | string | Yes (unless `--config`) | - | Path to log file to analyze. Alias: `--logFile` (the spelling of the TOML key `logFile`). |
| `--logFormat` | string | No | `%^ %^ %^ [%t] "%r" %s %b "%^" "%u" "%h"` | Log format string. See [Log Formats]({{< relref "/docs/reference/log-formats/" >}}). |
| `--startTime` | string | No | - | Start of time window. Formats: `YYYY-MM-DD`, `YYYY-MM-DD HH`, `YYYY-MM-DD HH:MM`, each optionally followed by ` ±HHMM`, or RFC3339 (`2025-07-06T06:00:00+01:00`). Needs `%t` in the log format. |
| `--endTime` | string | No | - | End of time window. Same formats as `--startTime` |

The time flags accept exactly what the TOML `startTime`/`endTime` keys accept. A value without an offset (`"2025-07-06 06:00"`) is compared with the wall-clock time of each log line, whatever offset the line carries; a value with an offset (`"2025-07-06 06:00 +0100"`, or any RFC3339 value) is compared as a true instant. See [Time Formats]({{< relref "/docs/reference/config-file/#time-formats" >}}).

### Clustering Options

| Flag | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `--clusterArgSets` | string | No | `1000,30,32,0.2` (injected) | Comma-separated `minSize,minDepth,maxDepth,threshold`. Repeat the flag for several sets; there is no separator for putting two sets into one value. Alias: `--clusterArgSet` (the spelling of the live flag). If omitted, flags mode injects the default set `1000,30,32,0.2` (jailed), matching live flags mode - clusters are still detected and jailed. Note: a `[static.NAME]` TOML trie has **no** such default - without `clusterArgSets` it detects nothing. See [Clustering]({{< relref "/docs/reference/clustering/" >}}). |

Each set is validated before the run starts, with the same rules as the TOML `clusterArgSets` rows: `minSize` a whole number >= 1, `minDepth` and `maxDepth` whole numbers with `0 <= minDepth <= maxDepth <= 32`, `threshold` between `0` and `2`. A set that breaks a rule aborts the command naming every problem in it.

### Filtering Options

| Flag | Type | Description |
|------|------|-------------|
| `--useragentRegex` | string | Regex to filter by User-Agent |
| `--endpointRegex` | string | Regex to filter by URL path |
| `--whitelist` | string | Path to IP/CIDR whitelist file |
| `--blacklist` | string | Path to IP/CIDR blacklist file |
| `--userAgentWhitelist` | string | Path to User-Agent whitelist file |
| `--userAgentBlacklist` | string | Path to User-Agent blacklist file |

See [Filtering]({{< relref "/docs/reference/filtering/" >}}) for file formats.

In static mode a filter is rejected when the log format does not extract the field it reads: `--useragentRegex` and the User-Agent list files need `%u`, `--endpointRegex` needs `%r` or `%U`, `--startTime`/`--endTime` need `%t`. The default format has all of them; this matters when you pass a shorter `--logFormat`.

### Analysis Options

| Flag | Type | Description |
|------|------|-------------|
| `--rangesCidr` | string | Count the requests inside an IPv4 CIDR range or a single IPv4 address (a bare address is treated as `/32`). Repeatable. Alias: `--cidrRanges` (the spelling of the TOML key). |
| `--plotPath` | string | Path for HTML heatmap output |

### Output Options

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--plain` | bool | false | Human-readable plain text output |
| `--compact` | bool | false | Single-line JSON output |
| `--tui` | bool | false | Interactive terminal UI |

Default output (no flag) is pretty-printed JSON. See [Output Formats]({{< relref "/docs/reference/output-formats/" >}}).

### Ban Management Options

| Flag | Type | Description |
|------|------|-------------|
| `--jailFile` | string | Path to jail state file (JSON) |
| `--banFile` | string | Path to ban list output (CIDRs plus `#` comment headers) |

Static mode writes the jail and ban files only when **both** flags are set; with only one of them, no jail/ban output is produced. All cluster arg sets passed via `--clusterArgSets` count toward jailing (matching live mode; per-set control is config-file only). Note that the jail file is only created when at least one range was actually jailed - a run with no detections leaves no jail file, while the ban file is always written (header-only if empty).

---

## Live Mode

```bash
flokbn live [options]
```

### Core Options

| Flag | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `--config` | string | No | - | Path to TOML config file. When used, only `--logLevel` is allowed alongside it. |
| `--port` | string | Yes (unless `--config`) | - | Port for Lumberjack protocol listener |
| `--listen` | string | No | `127.0.0.1` | Address the Lumberjack listener binds to (an IP address or host name, without a port). The port does not authenticate shippers, so pass another address such as `0.0.0.0` only when access to the port is restricted; flokbn then logs a warning at startup. Same as `[live] listen`. |
| `--jailFile` | string | Yes (unless `--config`) | - | Path to jail state file (JSON) |
| `--banFile` | string | Yes (unless `--config`) | - | Path to ban list output (CIDRs plus `#` comment headers) |
| `--logLevel` | string | No | `info` | Verbosity of the live-mode log lines on stderr: `debug`, `info`, `warn`, or `error`. Overrides the `[log]` level from the config file. |

Live mode logs leveled, timestamped progress lines to stderr (one summary line per detection iteration). Machine-readable live data is served by the HTTP endpoints (`GET /stats`, `GET /bans`, Prometheus `GET /metrics`) when `statsListen` is configured.

### Window Options

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--slidingWindowMaxTime` | duration | `2h0m0s` | Maximum time span of sliding window |
| `--slidingWindowMaxSize` | int | `100000` | Maximum requests in sliding window |
| `--sleepBetweenIterations` | int | `10` | Seconds between detection iterations. `0` means no pause; a negative value is rejected. |

Flags-only live mode creates a **single** sliding window (internally named `cli_default`). Multiple windows, TLS for the ingest listener (`tlsCert`, `tlsKey`, `tlsClientCA`), the HTTP stats server (`statsListen`, `topTalkers`), and the ingestor `readTimeout` are only available via `--config` - there are no CLI flags for them. See [Config File]({{< relref "/docs/reference/config-file/" >}}).

### Clustering Options

| Flag | Type | Description |
|------|------|-------------|
| `--clusterArgSet` | string | Comma-separated `minSize,minDepth,maxDepth,threshold`. Repeat the flag for several sets. Alias: `--clusterArgSets` (the spelling of the static flag and the TOML key). Same validation as in static mode. When omitted, a default set of `1000,30,32,0.2` is used. All sets passed this way are jailed (`useForJail` true). |

### Filtering Options

Live mode supports the same filter flags as static mode: `--useragentRegex`, `--endpointRegex`, `--whitelist`, `--blacklist`, `--userAgentWhitelist`, `--userAgentBlacklist`.

`--rangesCidr`, `--plotPath`, `--startTime`, `--endTime`, `--logfile`, `--logFormat`, `--plain`, `--compact`, and `--tui` are static-only flags - the live command rejects them with an error. Live mode produces log lines, the jail/ban files, and the optional HTTP endpoints, not a report.

---

## Generate Mode

```bash
flokbn generate <subcommand> [options]
```

Generates ready-to-run example inputs so you can try the full analysis without
a Go toolchain or your own logs.

### `generate static-demo`

```bash
flokbn generate static-demo [--out <dir>]
```

Writes a complete, self-contained static-analysis demo into the directory given
by `--out`: a fixed 1,000,000-line synthetic access log (`access.log`), the
matching [complex static-analysis configuration]({{< relref "/docs/guides/complex-static-analysis/" >}})
whose cluster thresholds are calibrated for that log, and the four IP/UA list
files the config references. Every path in the generated config is rewritten to
an absolute, co-located target, so it runs from any working directory.

The synthetic log is deterministic, with a known traffic shape (weighted `/16`
hotspots over a uniform public-IP background, Zipf endpoint popularity, and
exact-match whitelist User-Agents). There is no line-count flag - the demo
always generates exactly 1,000,000 lines.

| Flag | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `--out` | directory | No | `.` (current directory) | Directory to create the demo in. Receives the generated `access.log`, the calibrated config, and the IP/UA list files. |

A complete run from the binary alone:

```bash
flokbn generate static-demo --out ./demo
flokbn static --config ./demo/complex-static.toml --plain
```

Running the analysis additionally writes `heatmap.html`, `flokbn_jail.json`,
and `flokbn_ban.txt` into the same directory.

---

## Exit Codes

| Code | Description |
|------|-------------|
| `0` | Success |
| `1` | Any error (invalid arguments, file not found, configuration error). The message is printed to stdout/stderr. |

## CLI vs Config File

| Use CLI flags when... | Use `--config` when... |
|---|---|
| Quick ad-hoc analysis | Production deployments |
| Scripting and automation | Multiple tries/windows |
| Testing parameters | Reproducible configurations |
| Simple single-trie runs | Live mode |

Both build the same internal `*config.Config` struct. See [Config File]({{< relref "/docs/reference/config-file/" >}}) for TOML format.
