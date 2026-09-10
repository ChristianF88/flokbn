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

**A million IPs. A handful of ranges.**

Say it "flok ban" - a *flock* of IPs, banned as one. Bots don't arrive alone; flokbn treats the flock as the unit.

flokbn is a Go CLI that clusters the IPs in your access logs into CIDR ranges. A binary trie does the heavy lifting - a 2-million-line log takes about a second on an ordinary workstation. Use it for botnet detection, abuse analysis, or building ban lists.

[Documentation](https://christianf88.github.io/flokbn/) · [Quick start](https://christianf88.github.io/flokbn/docs/getting-started/quick-start/) · [CLI reference](https://christianf88.github.io/flokbn/docs/reference/cli-flags/)

## Quick start

Grab a prebuilt static binary from the [releases page](https://github.com/ChristianF88/flokbn/releases/latest) (Linux x86_64/arm64/armv7, macOS Intel & Apple Silicon, Windows x86_64 - no Go required), unpack it, and put `flokbn` on your `PATH`. Verify downloads with `sha256sum -c checksums.txt`.

Or build from source (Go 1.23+):

```bash
git clone https://github.com/ChristianF88/flokbn.git
cd flokbn/flokbn/src
go build -o flokbn .
```

No logs at hand? flokbn builds its own demo - a 1,000,000-line synthetic access log, a calibrated config, and the whitelist/blacklist files it references, all with absolute paths already filled in:

```bash
flokbn generate static-demo --out ./demo
```

```
generate static-demo: wrote a 1,000,000-line demo into /home/you/demo
Run it with:
  flokbn static --config /home/you/demo/complex-static.toml --plain
```

Run that command and you get the analysis below. The synthetic log is generated from a fixed seed, so your ranges and counts match these exactly - only the timings differ:

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
    ───────────────────       99,578 requests  ( 11.11%) [TOTAL]

  [... two more arg sets, then tries t2_bots, t3_hot_endpoints,
       t4_targeted_window ...]
```

Four tries run over the same log in one pass, each a different detection profile: a baseline, one filtered to bot User-Agents, one to hot endpoints, and one narrowed by User-Agent, endpoint, time window, and CIDR range at once. Alongside the report, the run writes `flokbn_ban.txt` (the ban list), `flokbn_jail.json` (jail state), and `heatmap.html` (a traffic heatmap).

Open `demo/complex-static.toml` to see how it is put together - it is a commented tour of the config format. Each trie lists `clusterArgSets` as `minSize,minDepth,maxDepth,threshold`: a minimum request count, a CIDR depth range to search, and a balance threshold - 0.1 reports a subtree once traffic spreads across it with at most 10% imbalance between its halves. Each set is a detection tier: tight ones catch single hot hosts, loose ones whole subnets, all in one pass. `useForJail` picks which tiers feed the ban list.

Point it at your own logs with flags instead of a config:

```bash
flokbn static --logfile /var/log/nginx/access.log \
  --clusterArgSets 1000,24,32,0.1 \
  --clusterArgSets 10000,16,24,0.2 --plain
```

## How it works

1. **Parse** - configurable format strings read Nginx, Apache, or custom logs; an IP-only fast path skips every field the analysis doesn't need.
2. **Filter** - time windows, whitelist/blacklist files, and regex on User-Agent and endpoint, with a literal prefilter so the regex engine rarely runs.
3. **Build trie** - every surviving IP is inserted into a binary trie.
4. **Detect clusters** - configurable depth ranges and balance thresholds walk the trie and emit the CIDR ranges where traffic concentrates.
5. **Jail** - detected ranges land in a persistent jail: the state your firewall automation reads to ban and unban.

## Two modes

**`flokbn static`** analyzes historical log files: multi-tier detection in one pass, time-window slices for forensics, and JSON, compact JSON, plain-text, or interactive TUI output.

**`flokbn live`** monitors continuously, ingesting over the Lumberjack protocol (Filebeat-compatible). Sliding windows watch recent traffic; detected ranges go into a persistent jail with escalating ban stages. HTTP endpoints expose `/stats`, `/bans`, and Prometheus `/metrics`. A Docker demo stack wires it into closed-loop deny enforcement with a Grafana dashboard.

## Performance

- ~4M requests/sec full parse with a User-Agent filter active (measured)
- ~50 ms trie build for ~1.2M requests
- <1 ms cluster detection across multiple arg sets
- ~50 B of memory per unique IP in the trie

Measured on a 2.3M-request real-world dataset on a single Linux workstation - your numbers will vary with hardware and log shape. Details in the [performance docs](https://christianf88.github.io/flokbn/docs/architecture/performance/).

## What's in the box

- Automatic clustering - you tune size, depth, and threshold; the trie does the rest
- Multi-trie detection: several configurations in a single pass over the log
- Filtering: whitelist/blacklist files, regex with literal prefiltering, time windows
- Ban-candidate list generation, inspired by fail2ban
- Four output formats: JSON, compact JSON, plain text, interactive TUI
- TOML config files with full CLI-flag parity
- Docker demo stack with closed-loop firewall enforcement and Grafana

## Scope

- IPv4 only. IPv6 is not implemented.
- Live mode ingests via Lumberjack only; HTTP/JSON ingest is planned.
- One `%h` field per log format.
- No duplicate field specifiers in a format string.

## Documentation

Full docs at **https://christianf88.github.io/flokbn/**:
[Getting Started](https://christianf88.github.io/flokbn/docs/getting-started/) ·
[Guides](https://christianf88.github.io/flokbn/docs/guides/) ·
[Reference](https://christianf88.github.io/flokbn/docs/reference/) ·
[Architecture](https://christianf88.github.io/flokbn/docs/architecture/) ·
[Contributing](https://christianf88.github.io/flokbn/docs/contributing/)

## License

MIT - see [LICENSE](LICENSE).
