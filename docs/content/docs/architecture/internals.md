---
title: "Internals"
description: "flokbn internal architecture and design"
summary: "Deep dive into how flokbn works: pipeline, binary trie, cluster detection, jail system, and code organization"
date: 2025-10-09T10:00:00+00:00
lastmod: 2026-06-11T10:00:00+00:00
draft: false
weight: 410
toc: true
seo:
  title: "flokbn Internals"
  description: "Learn about flokbn's internal architecture including trie-based IP clustering and detection algorithms"
  canonical: ""
  noindex: false
---

## Pipeline

flokbn is built around a multi-stage pipeline:

```
Log Files → Parser → Filter → Trie → Cluster Detector → Jail → Ban File
```

### Core Components

1. **Log Parser**: Extracts IP, timestamp, User-Agent, endpoint, status, and bytes from each line
2. **Filter Engine**: Whitelist, blacklist, regex, time windows
3. **Trie Builder**: Constructs binary prefix tree of IPs
4. **Cluster Detector**: Identifies high-volume CIDR ranges
5. **Jail Manager**: Maintains persistent detection state with escalating bans
6. **Ban File Writer**: Outputs blockable CIDR list

## Static Mode Architecture

```
┌─────────────┐
│  Log File   │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   Parser    │ ← Parse entire file
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   Filter    │ ← Apply filters
└──────┬──────┘
       │
       ▼
┌─────────────┐
│    Trie     │ ← Build IP tree
└──────┬──────┘
       │
       ▼
┌─────────────┐
│  Cluster    │ ← Detect clusters
│  Detector   │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   Output    │ ← JSON/Plain/TUI
└─────────────┘
```

**Characteristics**:
- Entire log loaded into memory
- Single-pass processing
- Fast for files <10M requests
- Suitable for batch analysis

## Live Mode Architecture

```
┌─────────────┐
│  Filebeat   │
│  (Lumber-   │
│   jack)     │
└──────┬──────┘
       │
       ▼
┌─────────────────────────────────┐
│     flokbn Live Server           │
│  ┌───────────────────────────┐  │
│  │  Sliding Window Manager   │  │
│  │                           │  │
│  │  ┌─────────────────────┐  │  │
│  │  │    Window 1         │  │  │
│  │  │  ┌────────────┐     │  │  │
│  │  │  │  Filter    │     │  │  │
│  │  │  └─────┬──────┘     │  │  │
│  │  │        ▼            │  │  │
│  │  │  ┌────────────┐     │  │  │
│  │  │  │   Trie     │     │  │  │
│  │  │  └─────┬──────┘     │  │  │
│  │  │        ▼            │  │  │
│  │  │  ┌────────────┐     │  │  │
│  │  │  │  Cluster   │     │  │  │
│  │  │  └────────────┘     │  │  │
│  │  └─────────────────────┘  │  │
│  │                           │  │
│  │  ┌─────────────────────┐  │  │
│  │  │    Window 2         │  │  │
│  │  │     (similar)       │  │  │
│  │  └─────────────────────┘  │  │
│  └───────────┬───────────────┘  │
│              ▼                  │
│  ┌───────────────────────────┐  │
│  │    Jail Manager           │  │
│  └───────────┬───────────────┘  │
└──────────────┬──────────────────┘
               │
               ▼
       ┌───────────────┐
       │  Ban File     │
       └───────────────┘
```

**Characteristics**:
- Continuous operation; waits for the first shipper connection at startup
- Multiple windows with independent filters and bounds, driven by one detection loop (the loop sleeps for the largest `sleepBetweenIterations` across windows)
- Bounded memory (sliding windows)
- Automatic jail updates and atomic ban-file writes
- Optional HTTP stats server (`GET /stats`, `/bans`, `/metrics`) publishing an immutable snapshot per iteration

## Data Structures

### Request

Each log entry is parsed into a cache-line-optimized struct:

```go
type Request struct {
    // Hot fields - first cache line (accessed by trie insertion, filtering, clustering)
    IPUint32  uint32     // Primary IP storage - eliminates net.IP allocation
    Status    uint16     // Smaller type for status code
    Method    HTTPMethod // 1 byte enum
    _         byte       // explicit padding for alignment
    Bytes     uint32
    Timestamp time.Time  // Needed for time-range filtering

    // Cold fields - second cache line (only accessed during output or string filtering)
    URI       string
    UserAgent string
    IP        net.IP // Legacy: set only by the live TCP ingestor; nil from the log parser
}
```

IPs are stored as `uint32` - no string allocation per IP, no `net.IP` overhead. The struct also carries a legacy `net.IP` field that only the live ingestor path populates (the static log parser leaves it nil); non-hot-path code derives `net.IP` from `IPUint32` on demand.

### Binary Trie

IP addresses are stored in a binary prefix tree where each bit of the IP determines the path:

```
Example IPs: 192.168.1.1, 192.168.1.2, 192.168.2.1

           Root
          /    \
        0        1
       /        / \
      ...     1    ...
            /  \
          0      ...
         / \
        0   1
       /     \
  192.168  192.168
     |        |
     1        2
     |        |
     1        1
```

```go
type TrieNode struct {
    Children [2]*TrieNode   // 0 and 1 bit children
    Count    uint32          // Requests at this node
}
```

**Properties**:
- **O(32) insertion**: Fixed depth for IPv4 (32 bits)
- **O(32) lookup**: Fixed depth traversal
- **Memory efficient**: Shared prefixes reduce node count
- **Natural CIDR aggregation**: Parent nodes represent CIDR ranges (depth = prefix length)

### Cluster Detection Algorithm

The detector performs depth-first traversal of the trie. A node is reported as a cluster when its two subtrees are *balanced* - evenly loaded children mean the traffic is spread across the subnet rather than coming from one deeper source:

```
For each trie node, descending from the root:
    Prune children with fewer than minSize requests
    If depth == maxDepth and node.Count >= minSize:
        Report node as cluster, stop descending
    If depth >= minDepth and both children carry traffic
       and 2*|left.Count - right.Count| < threshold*(node.Count)
       and node.Count >= minSize:
        Report node as cluster, stop descending
    Otherwise recurse into the populated children
```

**Pseudocode**:

```go
func detectClusters(node *TrieNode, depth int, params ClusterParams) []Cluster {
    if depth == params.MaxDepth {
        if node.Count >= params.MinSize {
            return []Cluster{{CIDR: nodeToCIDR(node, depth), Count: node.Count}}
        }
        return nil
    }

    left, right := node.Children[0], node.Children[1]
    if depth >= params.MinDepth && left != nil && right != nil {
        diff := absDiff(left.Count, right.Count)
        if 2*diff < uint64(params.Threshold*float64(node.Count)) &&
            node.Count >= params.MinSize {
            // Balanced subtree - report and don't recurse into children
            return []Cluster{{CIDR: nodeToCIDR(node, depth), Count: node.Count}}
        }
    }

    // Unbalanced (or too shallow): descend into populated children
    var out []Cluster
    if left != nil && left.Count >= params.MinSize {
        out = append(out, detectClusters(left, depth+1, params)...)
    }
    if right != nil && right.Count >= params.MinSize {
        out = append(out, detectClusters(right, depth+1, params)...)
    }
    return out
}
```

(The real implementation does this recursively with integer-only math; see `trie/trie.go`.)

**Complexity**:
- **Time**: O(N) where N = unique IPs (worst case)
- **Space**: O(D) where D = max depth (recursion stack)
- **Typical**: <1ms for 500k unique IPs

For parameter tuning, see [Clustering]({{< relref "/docs/reference/clustering/" >}}).

### Multi-Trie Processing

Each [cluster arg set]({{< relref "/docs/reference/clustering/" >}}) runs against the same trie independently. Results from multiple sets are combined, and the `useForJail` flag controls which sets contribute to the jail:

- Same CIDR from multiple sets = single jail entry
- Sub-ranges merged when parent range detected
- Repeat offenders escalate through ban tiers

## Jail System

The jail uses a tiered cell system with escalating ban durations:

```go
type Prisoner struct {
    CIDR      string    // e.g., "198.51.100.192/26"
    BanStart  time.Time // When current ban started
    BanActive bool      // Whether ban is currently active
}

type Cell struct {
    ID          int
    Description string
    BanDuration time.Duration
    Prisoners   []Prisoner
}

type Jail struct {
    Cells    []Cell
    AllCIDRs []string  // All ranges currently in jail
}
```

### Default Cells (5 Escalating Tiers)

| Cell | Description | Duration |
|------|-------------|----------|
| 1 | Stage 1 Ban | 10 minutes |
| 2 | Stage 2 Ban | 4 hours |
| 3 | Stage 3 Ban | 7 days |
| 4 | Stage 4 Ban | 30 days |
| 5 | Stage 5 Ban | 180 days |

### Behavior

- **Tiered escalation**: Repeat offenders move to higher cells with longer bans
- **Ban expiry**: Bans expire after the cell's duration
- **Re-detection**: If detected again after ban expires, prisoner moves to next cell
- **Range merging**: If a parent CIDR is detected, sub-ranges are consolidated
- **Sub-range awareness**: Existing jailed ranges that are sub-ranges of a new detection are merged

### Jail File Format

The jail file (`--jailFile`) persists detection state as JSON. It is read on startup and written after each detection cycle.

## Data Flow

### Static Mode

```
1. Read log file
2. For each line:
   a. Parse to Request
   b. Apply time filter (if configured)
   c. Apply User-Agent / endpoint regex filters (if configured)
   d. Apply User-Agent whitelist/blacklist lists (if configured)
   e. If passed all filters, keep for this trie
3. Build trie from filtered requests
4. For each cluster arg set:
   a. Traverse trie
   b. Detect clusters, merge overlapping ranges
5. Jail processing (only when jailFile AND banFile are configured):
   a. Collect merged ranges from sets with useForJail = true
   b. Remove anything covered by the IP whitelist
   c. Update jail, write jail file
   d. Write ban file (active bans + manual blacklist, minus whitelist)
6. Output results (JSON/Plain/TUI)
```

The IP whitelist/blacklist act in the **ban pipeline** (step 5), not on the per-line analysis - whitelisted traffic still appears in the statistics.

### Live Mode

```
1. Start Lumberjack server on [live] port; wait for a shipper to connect
2. Initialize one sliding window per [live.NAME] section
3. Loop:
   a. Read one batch from the ingestor
   b. Classify User-Agents against the UA lists (whitelisted-UA requests
      never enter any window; blacklisted-UA IPs are marked for force-jail)
   c. For each window: apply that window's regex filters, append the
      surviving requests, expire entries beyond the time/size bounds
   d. For each window and each cluster arg set: detect clusters
   e. Merge all jail-eligible detections, remove whitelisted ranges,
      append force-jailed /32s
   f. Update jail, write jail file, write ban file (atomic)
   g. Publish the stats snapshot (if statsListen is set), log one
      iteration summary line
   h. Sleep max(sleepBetweenIterations) across windows; repeat
```

## Sliding Window

Live mode uses sliding windows to bound memory usage:

- **Time-bounded**: Old requests expire based on `slidingWindowMaxTime`
- **Size-bounded**: Capped at `slidingWindowMaxSize` to prevent unbounded growth
- **Lazy cleanup**: Cleanup runs on the detection timer, not per-request

Multiple windows with different parameters are all updated by the single detection loop (which paces itself at the largest `sleepBetweenIterations`). See [Live Protection Guide]({{< relref "/docs/guides/live-protection/" >}}) for configuration.

## Lumberjack Protocol

flokbn implements the Lumberjack protocol (Beats protocol) for receiving logs from Filebeat:

```
Client (Filebeat) → [Lumberjack Protocol] → flokbn Server
```

**Protocol features** (Lumberjack v2): zlib-compressed batches, acknowledgments, windowed flow control, reliable delivery.

## Optimization Techniques

### Memory Pools

Pre-allocated object pools (trie nodes, scratch slices) reduce allocation and GC pressure.

### Regex Compilation and Prefiltering

Regex patterns are compiled once at startup, per trie/window. On top of that, flokbn derives each pattern's *required literals* (e.g. `bot` from `.*bot.*`) and screens every input with fast substring checks before the regex engine runs - see [Filtering]({{< relref "/docs/reference/filtering/" >}}).

### Adaptive Filtering

Static mode switches from sequential to concurrent filtering when the dataset exceeds 50,000 requests *and* filters are active; small or filter-free runs stay sequential (less overhead). Filter-free runs additionally take an IP-only parse path that never materializes full request structs.

### Buffered I/O

File reading uses 256KB buffers and zero-copy chunked reads, reducing syscalls on large files.

See [Performance]({{< relref "/docs/architecture/performance/" >}}) for benchmarks and tuning.

## Package Structure

```
flokbn/src/
├── main.go              # Entry point
├── analysis/            # Analysis orchestration
├── cidr/                # CIDR parsing utilities
├── cli/                 # CLI commands and API entry points
├── config/              # Configuration structs and loading
├── ingestor/            # Static/live mode ingestion, Request struct
├── iputils/             # IP address utilities
├── jail/                # Ban/jail management (tiered cells)
├── logging/             # Leveled slog setup for live mode
├── logparser/           # Log format parsing
├── output/              # Output formatting (JSON, plain text)
├── pools/               # Memory pool management, TrieNode struct
├── sliding/             # Sliding window for live mode
├── trie/                # IP trie building and cluster detection
├── tui/                 # Terminal user interface
└── version/             # Version info
```

## Complexity Summary

### Time

| Operation | Complexity | Notes |
|-----------|------------|-------|
| Parse line | O(N) | N = line length |
| Filter check | O(1) | Whitelist/blacklist |
| Regex match | O(M) | M = pattern complexity |
| Trie insert | O(32) | Fixed IPv4 depth |
| Trie lookup | O(32) | Fixed IPv4 depth |
| Cluster detect | O(U) | U = unique IPs |

### Space

| Component | Complexity | Notes |
|-----------|------------|-------|
| Request storage | O(R) | R = total requests |
| Trie nodes | O(U) | U = unique IPs |
| Jail entries | O(C) | C = detected clusters |
