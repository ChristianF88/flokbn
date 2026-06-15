<h1>
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset=".github/assets/flokbn-mark-dark.svg">
    <img src=".github/assets/flokbn-mark-light.svg" alt="flokbn logo" width="32" height="32">
  </picture>
  flokbn
</h1>

**A million IPs. A handful of ranges.**

flokbn is a Go CLI that clusters the IPs in your access logs into CIDR ranges. A binary trie does the heavy lifting - a 2-million-line log takes about a second on an ordinary workstation. Use it for botnet detection, abuse analysis, or building ban lists.

[Documentation](https://christianf88.github.io/flokbn/) · [Quick start](https://christianf88.github.io/flokbn/docs/getting-started/quick-start/) · [CLI reference](https://christianf88.github.io/flokbn/docs/reference/cli-flags/)

<!-- DEMO:STATIC - replace this whole comment with the static-mode recording.
     Recommended (mp4): edit README on github.com, drag the .mp4 into the editor,
     and keep the generated https://github.com/user-attachments/assets/... URL
     on its own line with a blank line above and below (no markdown around it).
     Fallback (gif): commit to .github/assets/demo-static.gif and use:
     ![flokbn static mode: clustering a 2M-line access log](.github/assets/demo-static.gif)
-->

## Quick start

Grab a prebuilt static binary from the [releases page](https://github.com/ChristianF88/flokbn/releases/latest) (Linux x86_64/arm64/armv7, macOS Intel & Apple Silicon, Windows x86_64 - no Go required), unpack it, and put `flokbn` on your `PATH`. Verify downloads with `sha256sum -c checksums.txt`.

Or build from source (Go 1.23+):

```bash
git clone https://github.com/ChristianF88/flokbn.git
cd flokbn/flokbn/src
go build -o flokbn .
```

Point it at a log file with one or more cluster arg sets:

```bash
./flokbn static --logfile /var/log/nginx/access.log \
  --clusterArgSets 1000,24,32,0.1 \
  --clusterArgSets 10000,16,24,0.2 --plain
```

Illustrative output (RFC 5737 ranges):

```
ANALYSIS OVERVIEW
────────────────────────────────────────────
Total Requests:  2,345,057
Parse Rate:      4,388,769 requests/sec
Duration:        570 ms

CLUSTERING RESULTS (2 sets)
────────────────────────────────────────────
Set 1: min_size=1000, depth=24-32, threshold=0.10
  192.0.2.86/32        1,574 requests  (  0.07%)
  198.51.100.192/26    3,083 requests  (  0.13%)

Set 2: min_size=10000, depth=16-24, threshold=0.20
  203.0.113.0/24      52,868 requests  (  2.25%)
  198.51.100.0/24     28,812 requests  (  1.23%)
```

Each `--clusterArgSets` is `minSize,minDepth,maxDepth,threshold`: a minimum request count, a CIDR depth range to search, and a balance threshold - 0.1 reports a subtree once traffic spreads across it with at most 10% imbalance between its halves. Each set is a detection tier: tight ones catch single hot hosts, loose ones whole subnets, all in one pass.

## How it works

1. **Parse** - configurable format strings read Nginx, Apache, or custom logs; an IP-only fast path skips every field the analysis doesn't need.
2. **Filter** - time windows, whitelist/blacklist files, and regex on User-Agent and endpoint, with a literal prefilter so the regex engine rarely runs.
3. **Build trie** - every surviving IP is inserted into a binary trie.
4. **Detect clusters** - configurable depth ranges and balance thresholds walk the trie and emit the CIDR ranges where traffic concentrates.
5. **Jail** - detected ranges land in a persistent jail: the state your firewall automation reads to ban and unban.

## Two modes

**`flokbn static`** analyzes historical log files: multi-tier detection in one pass, time-window slices for forensics, and JSON, compact JSON, plain-text, or interactive TUI output.

**`flokbn live`** monitors continuously, ingesting over the Lumberjack protocol (Filebeat-compatible). Sliding windows watch recent traffic; detected ranges go into a persistent jail with escalating ban stages. HTTP endpoints expose `/stats`, `/bans`, and Prometheus `/metrics`. A Docker demo stack wires it into closed-loop deny enforcement with a Grafana dashboard.

<!-- DEMO:LIVE - replace this whole comment with the live-mode recording.
     Recommended (mp4): edit README on github.com, drag the .mp4 into the editor,
     and keep the generated https://github.com/user-attachments/assets/... URL
     on its own line with a blank line above and below (no markdown around it).
     Fallback (gif): commit to .github/assets/demo-live.gif and use:
     ![flokbn live mode: sliding-window detection and automatic banning](.github/assets/demo-live.gif)
-->

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
