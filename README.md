# cidrx

Fast IP clustering from HTTP access logs. cidrx parses Nginx, Apache, or custom-format
access logs, builds a binary trie of every observed IP address, and clusters them into
CIDR ranges based on configurable balance thresholds — processing 1M+ requests/sec on
commodity hardware.

**[Documentation](https://christianf88.github.io/cidrx/)**

## Quick Start

```bash
git clone https://github.com/ChristianF88/cidrx.git
cd cidrx/cidrx/src
go build -o cidrx .
```

Analyze a log file and cluster high-volume IP ranges:

```bash
./cidrx static \
  --logfile /var/log/nginx/access.log \
  --startTime "2025-01-15" \
  --endTime "2025-01-15 23:59" \
  --useragentRegex ".*bot.*|.*scanner.*" \
  --clusterArgSets 1000,24,32,0.1 \
  --plain
```

```
═══════════════════════════════════════════════════════════════════════════════
                               cidrx Analysis Results
═══════════════════════════════════════════════════════════════════════════════

ANALYSIS OVERVIEW
────────────────────────────────────────────────────────────────────────────────
Total Requests:  1,046,826
Parse Rate:      1,373,322 requests/sec
Duration:        1078 ms

CLUSTERING RESULTS
────────────────────────────────────────────────────────────────────────────────
Set 1: min_size=1000, depth=24-32, threshold=0.10
  198.51.100.192/26    3,083 requests  (  0.29%)
  203.0.113.91/32      1,308 requests  (  0.12%)
  ─────────────────    4,391 requests  (  0.41%) [TOTAL]
```

Each clustering parameter set specifies a minimum request count, a CIDR depth range
to search, and a balance threshold. In the example above: at least 1000 requests,
search /24 through /32, and report a subtree once the traffic is spread evenly enough
across it (threshold 0.1 tolerates 10% imbalance between its two halves).
Multiple `--clusterArgSets` can run concurrently for multi-tier analysis (e.g. broad /12-/16
sweeps alongside narrow /24-/32 scans in a single pass).

## How It Works

cidrx processes logs through a four-stage pipeline:

1. **Parse** — Reads log entries at 1M+ req/sec using a configurable format string
   (`%h`, `%t`, `%r`, `%s`, `%u`, etc.) that maps to Nginx, Apache, or custom layouts.
2. **Filter** — Optionally narrows results by time window, URL regex, User-Agent regex,
   status code, or whitelist/blacklist files.
3. **Trie** — Inserts every qualifying IP into a binary trie. Multiple independent tries
   can run in parallel, each with its own filter set.
4. **Cluster** — Walks the trie at configurable depths and flags evenly loaded subtrees
   (traffic spread across the subnet, not one deep source), collapsing them into CIDR
   ranges with request counts.

Output formats: plain text, JSON, compact JSON, or an interactive TUI.

## Modes

**Static** — Analyze log files after the fact. Useful for traffic auditing, forensic
analysis, or generating firewall rules from historical data.

**Live** — Receive logs in real time via the Lumberjack protocol (Filebeat/Logstash).
cidrx keeps sliding windows of recent traffic, re-runs detection on a configurable
interval, and maintains a persistent jail with escalating ban durations, writing ban
files (CIDR lists compatible with iptables, nginx deny, etc.) as new clusters emerge.
Optional HTTP endpoints expose live state: `GET /stats` (JSON), `GET /bans` (ban list),
and `GET /metrics` (Prometheus).

## Use Cases

- **Traffic auditing** — Which subnets send the most requests? How is traffic distributed
  across IP ranges?
- **Firewall rule generation** — Produce CIDR-based block or allow lists from observed
  traffic patterns.
- **Coordinated activity analysis** — Identify IP ranges with unusually concentrated
  request volumes.
- **Post-incident forensics** — Replay access logs to understand the origin and structure
  of high-volume events.
- **Real-time monitoring** — Tail logs and automatically generate ban files when clusters
  cross thresholds.
- **Capacity planning** — Understand which networks drive load and how traffic distributes
  across prefixes.

## Features

- Parses 1M+ requests/sec with zero-copy log extraction
- Multiple concurrent clustering parameter sets in a single analysis pass
- Regex filtering on URL path and User-Agent (with automatic required-literal prefiltering)
- Time-window filtering with flexible date/time parsing
- IP whitelist (never banned) and blacklist (always banned) files
- User-Agent whitelist (immunize) and blacklist (force-jail) files
- Persistent jail with escalating ban durations for repeat offenders
- Live HTTP endpoints: `/stats`, `/bans`, Prometheus `/metrics`
- Named trie instances with independent filter chains
- Predefined CIDR ranges for targeted subnet analysis
- TOML config file support (all CLI flags have config equivalents)
- JSON, compact JSON, plain text, and interactive TUI output
- Docker demo stack with closed-loop firewall enforcement and a Grafana dashboard

## Documentation

Full docs, guides, and reference: **https://christianf88.github.io/cidrx/**

- [Installation](https://christianf88.github.io/cidrx/docs/getting-started/installation/)
- [Static Analysis Guide](https://christianf88.github.io/cidrx/docs/guides/static-analysis/)
- [Live Monitoring Guide](https://christianf88.github.io/cidrx/docs/guides/live-protection/)
- [CLI & Config Reference](https://christianf88.github.io/cidrx/docs/reference/)
- [Docker Testing](https://christianf88.github.io/cidrx/docs/guides/docker-testing/)

## License

MIT — see [LICENSE](LICENSE).
