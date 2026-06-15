---
title: "Clustering"
description: "Cluster detection parameters and tuning guide"
summary: "Complete reference for flokbn cluster detection parameters, CIDR sizes, and tuning guidance"
date: 2025-10-09T10:00:00+00:00
lastmod: 2026-06-11T10:00:00+00:00
draft: false
weight: 240
slug: "clustering"
toc: true
seo:
  title: "flokbn Clustering Reference"
  description: "Learn how to configure and tune flokbn cluster detection parameters"
  canonical: ""
  noindex: false
---

Cluster detection is the core algorithm that identifies groups of high-volume IPs and aggregates them into CIDR ranges.

## Parameter Format

CLI:
```bash
--clusterArgSets minSize,minDepth,maxDepth,threshold
```

TOML:
```toml
clusterArgSets = [[minSize, minDepth, maxDepth, threshold]]
```

## The Four Parameters

| Parameter | Type | Description | Typical Range |
|-----------|------|-------------|---------------|
| `minSize` | integer | Minimum requests to flag a cluster | 50-10000 |
| `minDepth` | integer | Smallest CIDR prefix (widest range) | 12-24 |
| `maxDepth` | integer | Largest CIDR prefix (narrowest range) | 24-32 |
| `threshold` | float | Subtree balance threshold (0.0-1.0) | 0.05-0.3 |

## minSize - Minimum Cluster Size

Minimum number of requests required for a cluster to be flagged.

| Traffic Volume | Recommended | Reasoning |
|----------------|-------------|-----------|
| < 10k req/day | 50-100 | Catch small clusters |
| 10k-100k req/day | 500-1000 | Balance signal/noise |
| 100k-1M req/day | 1000-5000 | Focus on significant clusters |
| > 1M req/day | 5000+ | Only major clusters |

## minDepth / maxDepth - CIDR Depth Range

Controls which CIDR prefix lengths the algorithm considers.

### CIDR Size Reference

| Prefix | IP Count | Use Case |
|--------|----------|----------|
| /12 | 1,048,576 | Entire ISPs, large networks |
| /16 | 65,536 | Large organizations, ASNs |
| /20 | 4,096 | Medium networks |
| /24 | 256 | Small networks, typical subnets |
| /28 | 16 | Small clusters |
| /30 | 4 | Tiny clusters |
| /32 | 1 | Single IP |

### minDepth Tuning

| Traffic Pattern | Recommended | Reasoning |
|-----------------|-------------|-----------|
| Large networks | 12-16 | Catch network-wide patterns |
| Distributed clusters | 20-24 | Balance coverage |
| Focused clusters | 28-30 | Target specific subnets |
| Single-host | 32 | Individual IPs only |

### maxDepth Tuning

| Goal | Recommended | Reasoning |
|------|-------------|-----------|
| Block networks only | 24 | Avoid blocking individuals |
| Include small clusters | 28-30 | Catch coordinated groups |
| Include single IPs | 32 | Maximum granularity |

## threshold - Subnet Balance Threshold

Controls where in the trie a cluster boundary is drawn (0.0-1.0).

A trie node between minDepth and maxDepth is reported as a cluster only when **both** of its children carry traffic and the load is balanced between them. With child request counts `a` and `b`, the node qualifies when:

```
2 * |a - b| < threshold * (a + b)
```

Lower values demand near-perfect balance and yield fewer, denser clusters; higher values tolerate lopsided subtrees and yield broader detections. A node with only one populated child is never reported at that depth - the search descends into the populated side instead. At maxDepth the balance check no longer applies: any node still holding at least minSize requests is reported. This is why detections land on the *balanced subtree* of an attack (e.g. a /27 inside a /24), not on the enclosing network.

Common presets: **Strict** 0.05-0.1 (only tightly balanced clusters, fewest false positives), **Balanced** 0.1-0.2 (good default), **Loose** 0.3+ (tolerates lopsided subtrees, broader detections).

## Multiple Cluster Arg Sets

Different cluster patterns require different parameters. Specify multiple sets to catch clusters at various scales:

```toml
clusterArgSets = [
  [10000, 16, 24, 0.3],   # Tier 1: Large clusters
  [1000, 24, 28, 0.1],    # Tier 2: Distributed clusters
  [100, 30, 32, 0.05]     # Tier 3: Focused clusters
]
useForJail = [true, true, true]
```

Or via CLI:
```bash
--clusterArgSets 10000,16,24,0.3 \
--clusterArgSets 1000,24,28,0.1 \
--clusterArgSets 100,30,32,0.05
```

Each set runs independently against the trie. Results are combined, and duplicates are deduplicated in the jail.

## Tuning Scenarios

### Emergency Response
Low minSize, multiple ranges, moderate thresholds:
```bash
--clusterArgSets 500,28,32,0.1 \
--clusterArgSets 2000,20,28,0.2 \
--clusterArgSets 10000,16,24,0.3
```

### Security Audit
Four tiers for comprehensive coverage, `useForJail = false` for analysis only:
```toml
clusterArgSets = [
  [100, 28, 32, 0.05],
  [1000, 24, 28, 0.1],
  [5000, 20, 24, 0.2],
  [10000, 16, 20, 0.3]
]
useForJail = [false, false, false, false]
```

### API Protection
Endpoint-filtered, moderate sensitivity:
```toml
endpointRegex = "/api/.*"
clusterArgSets = [[500, 28, 32, 0.1]]
```

### Brute Force Detection
Login-specific, low threshold:
```toml
endpointRegex = "/login|/wp-login\\.php|/admin"
clusterArgSets = [[100, 28, 32, 0.05]]
```

## Performance

Clustering is extremely fast - typically <1ms even with multiple sets (measured on one machine, varies with hardware and traffic shape):

| Cluster Sets | Typical Time (1M requests, 500k unique IPs) |
|---|---|
| 1 | ~100 us |
| 3 | ~300 us |
| 5 | ~500 us |

Narrower depth ranges and higher minSize values are slightly faster.

## Common Mistakes

**Threshold too low** (`0.001`): Demands near-perfect balance between subtree halves - you will detect almost nothing. Start at 0.05+.

**minSize too small for high traffic** (`10` on a 1M req/day site): Too much noise. Scale minSize with traffic volume.

**Depth range too wide** (`8-32`): Inefficient. Use focused ranges like 20-28.

**Only one cluster arg set**: Misses different cluster sizes. Use 2-3 sets with different scales.

## Interpreting Results

```
Set 1: min_size=1000, depth=24-32, threshold=0.10
Detected Threat Ranges:
  198.51.100.192/26            3,083 requests  (  0.29%)
  203.0.113.91/32           1,308 requests  (  0.12%)
```

- `/26` = 64 IPs, with 3,083 requests - a cluster of IPs in a single subnet
- `/32` = 1 IP, with 1,308 requests - a single high-volume IP
- The percentage shows each range's share of total requests after filtering

## Validation and Testing

Test parameters on known data:
```bash
flokbn static --logfile access.log \
  --clusterArgSets 1000,24,32,0.1 --plain > results-1.txt

flokbn static --logfile access.log \
  --clusterArgSets 500,24,32,0.05 --plain > results-2.txt

diff results-1.txt results-2.txt
```

Sweep thresholds:
```bash
for threshold in 0.05 0.1 0.2 0.3; do
  echo "threshold=$threshold"
  flokbn static --logfile access.log \
    --clusterArgSets 1000,24,32,$threshold --plain | grep "Detected"
done
```
