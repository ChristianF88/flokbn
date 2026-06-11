---
title: "CLI Flags"
description: "Complete command-line reference for cidrx"
summary: "Every cidrx command-line flag with type, default value, and description"
date: 2025-10-09T10:00:00+00:00
lastmod: 2026-06-11T10:00:00+00:00
draft: false
weight: 210
slug: "cli-flags"
toc: true
seo:
  title: "cidrx CLI Reference"
  description: "Complete command-line interface reference for cidrx including all flags and options"
  canonical: ""
  noindex: false
---

## Command Structure

```bash
cidrx [global options] command [command options]
```

Two commands: **`static`** (historical log analysis) and **`live`** (real-time monitoring).

## Global Options

| Flag | Description |
|------|-------------|
| `--help`, `-h` | Show help |

## Static Mode

```bash
cidrx static [options]
```

### Core Options

| Flag | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `--config` | string | No | - | Path to TOML config file. When used, only `--tui`, `--compact`, `--plain` are allowed alongside it. All other flags produce an error. |
| `--logfile` | string | Yes (unless `--config`) | - | Path to log file to analyze |
| `--logFormat` | string | No | `%^ %^ %^ [%t] "%r" %s %b %^ "%u" "%h"` | Log format string. See [Log Formats]({{< relref "/docs/reference/log-formats/" >}}). |
| `--startTime` | string | No | - | Start of time window. Formats: `YYYY-MM-DD`, `YYYY-MM-DD HH`, `YYYY-MM-DD HH:MM` |
| `--endTime` | string | No | - | End of time window. Same formats as `--startTime` |

### Clustering Options

| Flag | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `--clusterArgSets` | string | Yes (unless `--config`) | - | Comma-separated `minSize,minDepth,maxDepth,threshold`. Repeatable. See [Clustering]({{< relref "/docs/reference/clustering/" >}}). |

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

### Analysis Options

| Flag | Type | Description |
|------|------|-------------|
| `--rangesCidr` | string | Analyze specific CIDR range. Repeatable. |
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
| `--banFile` | string | Path to ban list output (one CIDR per line) |

---

## Live Mode

```bash
cidrx live [options]
```

### Core Options

| Flag | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `--config` | string | No | - | Path to TOML config file. When used, only `--compact`, `--plain`, and `--logLevel` are allowed alongside it. |
| `--port` | string | Yes (unless `--config`) | - | Port for Lumberjack protocol listener |
| `--jailFile` | string | Yes (unless `--config`) | - | Path to jail state file (JSON) |
| `--banFile` | string | Yes (unless `--config`) | - | Path to ban list output (one CIDR per line) |
| `--logLevel` | string | No | `info` | Verbosity of the live-mode log lines on stderr: `debug`, `info`, `warn`, or `error`. Overrides the `[log]` level from the config file. |

Live mode logs leveled, timestamped progress lines to stderr (one summary line per detection iteration). Machine-readable live data is served by the HTTP endpoints (`GET /stats`, `GET /bans`, Prometheus `GET /metrics`) when `statsListen` is configured.

### Window Options

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--slidingWindowMaxTime` | duration | `2h0m0s` | Maximum time span of sliding window |
| `--slidingWindowMaxSize` | int | `100000` | Maximum requests in sliding window |
| `--sleepBetweenIterations` | int | `10` | Seconds between detection iterations |

### Clustering Options

| Flag | Type | Description |
|------|------|-------------|
| `--clusterArgSet` | string | Comma-separated `minSize,minDepth,maxDepth,threshold`. Repeatable. Note: singular form (not `--clusterArgSets`). |

### Filtering, Analysis, and Output Options

Live mode supports the same optional flags as static mode: `--useragentRegex`, `--endpointRegex`, `--whitelist`, `--blacklist`, `--userAgentWhitelist`, `--userAgentBlacklist`, `--rangesCidr`, `--plotPath`, `--plain`, `--compact`. (`--jailFile` and `--banFile` are required in live mode; see Core Options above.)

---

## Exit Codes

| Code | Description |
|------|-------------|
| `0` | Success |
| `1` | General error (invalid arguments, file not found) |
| `2` | Configuration error |

## CLI vs Config File

| Use CLI flags when... | Use `--config` when... |
|---|---|
| Quick ad-hoc analysis | Production deployments |
| Scripting and automation | Multiple tries/windows |
| Testing parameters | Reproducible configurations |
| Simple single-trie runs | Live mode |

Both build the same internal `*config.Config` struct. See [Config File]({{< relref "/docs/reference/config-file/" >}}) for TOML format.
