<h1>
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset=".github/assets/flokbn-mark-dark.svg">
    <img src=".github/assets/flokbn-mark-light.svg" alt="flokbn logo" width="32" height="32">
  </picture>
  flokbn
</h1>

[![tests](https://img.shields.io/github/actions/workflow/status/ChristianF88/flokbn/ci.yml?branch=main&label=tests)](https://github.com/ChristianF88/flokbn/actions/workflows/ci.yml)
[![release](https://img.shields.io/github/v/release/ChristianF88/flokbn)](https://github.com/ChristianF88/flokbn/releases/latest)
[![license](https://img.shields.io/github/license/ChristianF88/flokbn)](LICENSE)

flokbn is a command-line tool that reads web server access logs and reports the CIDR ranges where the traffic concentrates. It is meant for botnet detection, abuse analysis and building ban lists. A botnet that spreads its requests over thousands of addresses is hard to see one IP at a time, because no single address sends much. Grouped by network, the same traffic shows up as a few ranges that can be banned as a unit.

flokbn is written in Go. It puts every client IPv4 address into a binary trie and walks the trie to find the ranges. A 2-million-line log takes about a second on an ordinary workstation. `flokbn static` analyzes log files. `flokbn live` receives log lines from Filebeat over the Lumberjack protocol, keeps a sliding window of recent traffic, and maintains a persistent jail with escalating ban durations that firewall automation can read.

The name is pronounced "flok ban": a flock of IPs, banned together.

[Documentation](https://christianf88.github.io/flokbn/) · [Quick start](https://christianf88.github.io/flokbn/docs/getting-started/quick-start/) · [CLI reference](https://christianf88.github.io/flokbn/docs/reference/cli-flags/)

<p align="center">
  <img src="docs/static/images/tui-demo.gif" width="820" alt="Recording of flokbn's terminal UI on the generated demo log: the results of four tries and a heatmap of the traffic with the detected ranges marked">
</p>

The recording shows static mode in the terminal UI (`--tui`) on the generated demo:

- **One pass over a 1,000,000-line access log.** The log is read once, and every trie is built from that pass.
- **Four tries with different filters:** no filter, a User-Agent regex, an endpoint regex, and all of User-Agent, endpoint, time window and CIDR range combined.
- **Three arg sets per trie.** Each set is a different definition of what counts as an offending range, from large subnets carrying a lot of traffic down to small groups of hosts.
- **A heatmap to check the result.** The traffic is plotted over the IPv4 address space, with a red dot on the cells that lie in detected ranges, so you can see whether the detected ranges are where the traffic is.

## Quick start

### Install

Prebuilt static binaries are on the [releases page](https://github.com/ChristianF88/flokbn/releases/latest) for Linux (x86_64, arm64, armv7), macOS (Intel and Apple Silicon) and Windows (x86_64). They do not require Go. Unpack the archive, put `flokbn` on your `PATH`, and verify the download with `sha256sum -c checksums.txt`.

To build from source you need Go 1.23+:

```bash
git clone https://github.com/ChristianF88/flokbn.git
cd flokbn/flokbn/src
go build -o flokbn .
```

### Run the demo

If you have no logs to try it on, flokbn can generate a demo. The command below writes a 1,000,000-line synthetic access log, a calibrated config, and the whitelist and blacklist files the config refers to, with absolute paths already filled in.

```bash
flokbn generate static-demo --out ./demo
```

```
generate static-demo: wrote a 1,000,000-line demo into /home/you/demo
Run it with:
  flokbn static --config /home/you/demo/complex-static.toml --plain
```

The command it suggests prints the analysis below. The synthetic log is generated from a fixed seed, so your ranges and counts will match these exactly and only the timings will differ.

```
📊 ANALYSIS OVERVIEW
────────────────────────────────────────────
Analysis Type:   static
Duration:        1511 ms

⚡ PARSING PERFORMANCE
────────────────────────────────────────────
Total Requests:  1,000,000
Parse Time:      301 ms
Parse Rate:      3,321,302 requests/sec

🎯 TRIE: t1_baseline
────────────────────────────────────────────
Requests After Filtering: 895,978
Excluded (UA whitelist): 104,022
Unique IPs:              884,202
Active Filters:          UA whitelist (58 patterns)

🔍 CLUSTERING RESULTS (3 sets)
............................................
  Set 1: min_size=10000, depth=12-18, threshold=0.20
  Execution Time: 34 μs
  Detected Threat Ranges:
    23.253.0.0/16             17,838 requests  (  1.99%)
    35.217.0.0/16             11,220 requests  (  1.25%)
    50.231.0.0/16             11,938 requests  (  1.33%)
    87.26.0.0/16              15,018 requests  (  1.68%)
    143.173.0.0/16            15,955 requests  (  1.78%)
    166.94.0.0/16             12,563 requests  (  1.40%)
    183.77.0.0/16             15,046 requests  (  1.68%)
    ───────────────────       99,578 requests  ( 11.11%) [TOTAL]

  [... two more arg sets, then tries t2_bots, t3_hot_endpoints,
       t4_targeted_window ...]
```

The demo config defines four tries, each with its own detection profile, and all four run over the same log in one pass. The first is a baseline, the second is filtered to bot User-Agents, the third to hot endpoints, and the fourth is narrowed by User-Agent, endpoint, time window, and CIDR range at once. Besides the report, the run writes `flokbn_ban.txt` (the ban list), `flokbn_jail.json` (the jail state), and `heatmap.html` (a traffic heatmap).

`demo/complex-static.toml` is commented and walks through the config format. Each trie lists its `clusterArgSets` as `minSize,minDepth,maxDepth,threshold`. `minSize` is a minimum request count, the two depths bound the CIDR depth range to search, and `threshold` is a balance threshold. At 0.1, a subtree is reported once traffic spreads across it with at most 10% imbalance between its halves. Each set is a detection tier. Tight sets catch single hot hosts and loose sets catch whole subnets. `useForJail` selects which tiers feed the ban list.

### Run it on your own logs

flokbn can be driven by a TOML config file, as in the demo, or by flags:

```bash
flokbn static --logfile /var/log/nginx/access.log \
  --clusterArgSets 1000,24,32,0.1 \
  --clusterArgSets 10000,16,24,0.2 --plain
```

## How it works

1. The log is parsed with a configurable format string, which covers Nginx, Apache, and custom layouts. An IP-only fast path skips every field the analysis does not need.
2. Requests are filtered by time window, by whitelist and blacklist files, and by regular expressions on User-Agent and endpoint. A literal prefilter means the regex engine rarely runs.
3. Every IP that passes the filters is inserted into a binary trie.
4. A walk over the trie, bounded by the configured depth ranges and balance thresholds, emits the CIDR ranges where traffic concentrates.
5. Detected ranges go into a persistent jail, which is the state your firewall automation reads to ban and unban. The ban-candidate list is inspired by fail2ban.

## Static and live mode

`flokbn static` analyzes historical log files. It runs several detection tiers in one pass, can restrict a trie to a time window for forensic work, and writes its report as JSON, compact JSON, plain text, or an interactive TUI.

`flokbn live` runs continuously and ingests over the Lumberjack protocol, which is compatible with Filebeat. The ingest listener binds `127.0.0.1` unless you set `listen`, and it can require TLS client certificates. Sliding windows watch recent traffic, and detected ranges go into a persistent jail with escalating ban stages. HTTP endpoints expose `/stats`, `/bans`, and Prometheus `/metrics`. The repository includes a Docker demo stack that connects live mode to closed-loop deny enforcement and a Grafana dashboard.

> **Static and live mode have different default log formats.** Both accept the same `logFormat` strings. By default, static mode reads the client IP from the *last* field (an `X-Forwarded-For` layout), and live mode reads it from the *first* field (what a web server writes and Filebeat ships unchanged). If the lines you ship have a proxy address first and the client in `X-Forwarded-For`, set `[live] logFormat` (or `live --logFormat`) to match. Otherwise flokbn will ban your proxy.

## Performance

The figures below were measured on a 2.3M-request real-world dataset on a single Linux workstation. Your numbers will vary with hardware and log shape. The [performance docs](https://christianf88.github.io/flokbn/docs/architecture/performance/) have the details.

- ~4M requests/sec full parse with a User-Agent filter active (measured)
- ~50 ms trie build for ~1.2M requests
- <1 ms cluster detection across multiple arg sets
- ~50 B of memory per unique IP in the trie

## Limitations

- Only IPv4 is supported. IPv6 is not implemented.
- Live mode ingests via Lumberjack only. HTTP/JSON ingest is planned.
- A log format must contain exactly one `%h` field and no duplicate field specifiers.

## Documentation

Full docs at **https://christianf88.github.io/flokbn/**:
[Getting Started](https://christianf88.github.io/flokbn/docs/getting-started/) ·
[Guides](https://christianf88.github.io/flokbn/docs/guides/) ·
[Reference](https://christianf88.github.io/flokbn/docs/reference/) ·
[Architecture](https://christianf88.github.io/flokbn/docs/architecture/) ·
[Contributing](https://christianf88.github.io/flokbn/docs/contributing/)

## License

MIT. See [LICENSE](LICENSE).
