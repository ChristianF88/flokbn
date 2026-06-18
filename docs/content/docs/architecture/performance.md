---
title: "Performance"
description: "Performance benchmarks and optimization guide for flokbn"
summary: "Benchmarks, memory management, scaling approaches, and optimization techniques"
date: 2025-10-09T10:00:00+00:00
lastmod: 2026-06-18T10:00:00+00:00
draft: false
weight: 420
toc: true
seo:
  title: "flokbn Performance Guide"
  description: "Learn about flokbn performance benchmarks and how to optimize for maximum throughput"
  canonical: ""
  noindex: false
---

flokbn processes millions of log entries per second on commodity hardware.

## Benchmarks

Measured on a 2.3M-request real-world dataset on a single Linux workstation - your numbers will vary with hardware and log shape:

| Metric | Measured | Notes |
|--------|----------|-------|
| Parse Rate (IP-only fast path) | several million requests/sec | When the analysis needs no UA/endpoint/status fields, only the IP is parsed |
| Parse Rate (full parse) | millions of requests/sec | With UA/endpoint filters active |
| End-to-end | under a second for 2.3M requests | Parse + trie build + clustering |
| Cluster Time | <1ms | Multiple cluster sets |

### Real-World Example

From the reference dataset (2,345,057 requests, full parse with a User-Agent filter active):

```
⚡ PARSING PERFORMANCE
────────────────────────────────────────────────────────────────────────────────
Total Requests:  2,345,057
Parse Time:      534 ms
Parse Rate:      4,388,769 requests/sec

🎯 TRIE: cli_trie
────────────────────────────────────────────────────────────────────────────────
Trie Build Time:         47 ms
```

Without filters the IP-only parse path is faster still. Clustering itself runs in microseconds per arg set on top of that.

## Performance Breakdown

### Stage 1: File I/O and Parsing (~60% of total)

**Bottleneck**: Disk I/O and log parsing

Optimizations applied: zero-copy chunked file reading, an IP-only parse path that skips all other fields when the analysis does not need them, optimized string parsing, minimal allocations.

The parser picks its I/O strategy by file size at a **500 MB** threshold: files smaller than 500 MB use single-stream sequential reading (lower overhead), while files at or above 500 MB use chunked concurrent I/O (multiple workers `ReadAt` distinct offsets in parallel). A non-EOF `ReadAt` failure during a chunked read is **recorded and surfaced** - the parse returns a non-nil error naming the file and offset rather than silently truncating the result and reporting success on a partial read.

### Stage 2: Filtering (~20% of total)

**Bottleneck**: Regex matching

Optimizations applied: regexes compiled once at startup, a required-literal prefilter that screens lines with fast substring checks before the regex engine runs, adaptive concurrent/sequential filtering, O(1) exact-match User-Agent lists.

Typical per-request cost:
- User-Agent list lookup: <1μs
- Regex matching: 1-10μs (often skipped entirely by the prefilter)
- Time window: <1μs

### Stage 3: Trie Building (~15% of total)

**Bottleneck**: Memory allocation, tree construction

Optimizations applied: memory pools, efficient trie node structure, batch insertions.

Typical: ~2-3M insertions/sec, ~50 bytes per unique IP.

### Stage 4: Cluster Detection (~5% of total)

**Bottleneck**: Tree traversal, threshold calculations

Optimizations applied: efficient depth-first traversal, early termination, minimal allocations.

Typical: <1ms for most datasets, scales linearly with unique IPs.

## Optimization Tips

### Avoid Unneeded Fields

If the analysis only clusters IPs (no UA/endpoint/time filters, no status breakdown), flokbn parses just the IP from each line - the fastest path by far. Every filter that needs another field forces the full parse.

### Regex Patterns

Prefer patterns with distinctive required literals so the prefilter can skip the regex engine for non-matching lines:

```
# Fast - prefilter screens on the literals "crawler", "spider", "fetcher"
crawler|spider|fetcher

# Slow - no required literal, every line runs the regex engine
.*
```

Use User-Agent whitelist/blacklist files instead of regex when matching exact strings (O(1) map lookup).

### Cluster Arg Sets (10-20% faster clustering)

Fewer sets = faster. Start with 2-3 cluster arg sets. Higher `minSize` and narrower depth ranges both reduce traversal time. See [Clustering]({{< relref "/docs/reference/clustering/" >}}).

## Memory Management

### Typical Memory Usage (1M requests)

| Component | Memory | Notes |
|-----------|--------|-------|
| Request storage | 50-100 MB | ~50-100 bytes per request |
| Trie structure | 25-50 MB | ~50 bytes per unique IP |
| Cluster results | <1 MB | Minimal overhead |
| **Total** | **75-150 MB** | Scales linearly |

### Reducing Memory

If memory usage is higher than expected (the usual causes are very many unique IPs or large sliding windows in live mode), or for large log files (>10M requests):

1. Use live mode with sliding windows instead of static mode
2. Split files and analyze time ranges separately
3. Increase `minSize` to reduce tracked IPs
4. Use whitelists to exclude traffic early

Live mode memory is bounded by `slidingWindowMaxSize` (~50MB per window at 50,000 requests).

### Monitoring Memory

```bash
/usr/bin/time -v flokbn static --logfile access.log \
  --clusterArgSets 1000,24,32,0.1 --plain
# Look for: Maximum resident set size
```

## Benchmarking

### Go Benchmarks

```bash
cd flokbn/src

go test -bench=. ./...              # Run all benchmarks
go test -bench=. -benchmem ./...    # With memory stats
go test -bench=BenchmarkStaticPipeline ./...  # Specific benchmark
```

### Real-World Benchmarking

For timing full runs against a real log file, use the recipe in the [Developer Guide]({{< relref "/docs/contributing/developer-guide/#real-world-performance-test" >}}).

## Scaling

### Horizontal Scaling

For very large datasets, split by time range:

```bash
flokbn static --logfile access.log \
  --startTime "2025-10-09" --endTime "2025-10-09 06" &

flokbn static --logfile access.log \
  --startTime "2025-10-09 06" --endTime "2025-10-09 12" &

wait  # Merge results
```

### Vertical Scaling

flokbn benefits from:

- **Fast CPU**: Faster parsing and clustering
- **Fast storage**: SSD for faster file I/O
- **More RAM**: Larger datasets in memory

Diminishing returns: >4 cores provides minimal benefit (most operations single-threaded), >16GB RAM only needed for 100M+ request datasets.

### Live Mode Scaling

Use multiple windows with different lengths, filters, and thresholds to cover different traffic patterns. Note that one detection loop drives all windows and paces itself at the **largest** `sleepBetweenIterations` - windows differ in what they look at, not in how often they run. See [Live Protection Guide]({{< relref "/docs/guides/live-protection/" >}}) for window configuration.

## Troubleshooting

### Slow Parsing (<1M requests/sec)

Possible causes: slow disk I/O, complex regex patterns, large whitelist.

Debug by testing without filters first:

```bash
time flokbn static --logfile access.log \
  --clusterArgSets 10000,24,32,0.5 --plain
```

### Slow Clustering (>100ms)

Possible causes: too many cluster arg sets, very wide depth ranges, too many unique IPs. Reduce to a single set with narrow depth range to isolate.

## Performance Goals

Based on project requirements:

| Goal | Target |
|------|--------|
| Parse rate | >1M requests/sec |
| Total time | <2 seconds for 2M requests |
| Memory | <512MB for typical workloads |
| Cluster detection | <5ms |
