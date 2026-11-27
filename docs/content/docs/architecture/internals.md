---
title: "Internals"
description: "flokbn internal architecture and design"
summary: "Deep dive into how flokbn works: pipeline, binary trie, cluster detection, jail system, and code organization"
date: 2025-10-09T10:00:00+00:00
lastmod: 2026-11-23T10:00:00+00:00
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
- Continuous operation; the loop starts as soon as the listener is up and does not block until a shipper connects
- Multiple windows with independent filters and bounds, driven by one detection loop (the loop sleeps for the largest `sleepBetweenIterations` across windows)
- Bounded memory (sliding windows)
- Automatic jail updates and atomic ban-file writes, skipped when the content did not change
- An idle heartbeat expires window entries and bans while no traffic arrives
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
}
```

IPs are stored as `uint32` - no string allocation per IP, no `net.IP` overhead. Non-hot-path code derives a `net.IP` from `IPUint32` on demand (`Request.GetIPNet`).

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

- Every set's ranges reach the jail as that set found them, not merged across sets
- Same CIDR from multiple sets = single jail record
- A hot host and the subnet around it are two records, each with its own stage
- The ban file joins nested and neighbouring bans again

## Jail System

The jail is the persistent record of which ranges were banned, at which stage and since when. It is a sorted list of records:

```go
type Record struct {
    IP        uint32 // network address
    PrefixLen uint8
    Stage     uint8 // stage of the last ban, 1-based
    BanStart  int64 // start of the last ban, Unix nanoseconds
}
```

Whether a ban is active is not stored. It is computed from the time of the round: a ban at stage `s` lasts the duration of that stage and has ended afterwards.

### Stages

| Stage | Duration |
|-------|----------|
| 1 | 10 minutes |
| 2 | 4 hours |
| 3 | 7 days |
| 4 | 30 days |
| 5 | 180 days |

The last stage repeats. A record is forgotten 180 days after its ban ended; until then a new detection counts as a repeat.

### Rules

Two ranges count as the same offender when the narrower one fills at least 50% of the addresses of the wider one, which for CIDR ranges means: the same range, or one prefix bit apart.

Every detected range is judged against the jail as it was before the round:

1. **Already banned**: a range whose addresses are all banned is ignored. Blocked requests can still show up in a log and must not escalate anything.
2. **Banned one stage above its history**: otherwise the range is banned at the stage after the highest of
   - its own ended record,
   - an ended record around it of which it fills at least 50%,
   - the highest stage that at least 50% of its addresses have served in ended records inside it.

   Without a history it starts at stage 1.
3. **A wider record is banned again as a whole** when the detected range fills at least 50% of it and its ban has ended.
4. **Records inside the detected range are banned again**, each at its own next stage, when their ban has ended: all their addresses were detected again.

A new or repeated ban always starts at the time of the round. A ban that is still running passes nothing on: a range around an active ban starts its own ladder, and the narrower record keeps its ban.

Examples:

| In the jail | Detected | Result |
|-------------|----------|--------|
| `/24` at stage 2, ended | the same `/24` | `/24` at stage 3 |
| `/24` at stage 2, active | the same `/24`, or anything inside it | nothing |
| `/24` at stage 3, ended | one of its `/25` halves | the whole `/24` and the `/25` at stage 4 |
| `/24` at stage 3, ended | one address in it | the address at stage 1, the `/24` unchanged |
| `/32` at stage 4, ended | the `/16` around it | the `/16` at stage 1, the `/32` at stage 5 |
| `/25` at stage 2, active | the `/24` around it | the `/24` at stage 1, the `/25` keeps its ban |

Records are never merged in the jail: it holds every range that was detected, with its own stage. Nested and neighbouring bans are joined in the ban file only.

### Jail File Format

The jail file (`--jailFile`) holds the records as JSON, one per line, in address order:

```json
{"version":2,"records":[
{"cidr":"10.0.0.0/16","stage":3,"banStart":"2026-11-26T16:45:00Z"},
{"cidr":"10.0.5.5/32","stage":5,"banStart":"2026-11-27T09:12:30Z"}
]}
```

It is read on startup. Static mode writes it at the end of a run that changed a record; live mode writes it after a detection cycle or idle heartbeat whose jail content differs from what is on disk. A ban that merely runs out changes the ban file, not the jail file. A file that flokbn cannot take over completely (unknown or repeated keys, a record without its range, stage or ban start, a range listed twice) is rejected at startup rather than read as a smaller jail. A jail file of an earlier flokbn version (top-level key `Cells`) is not read: flokbn stops with a message that says so, and starts with an empty jail once the file is deleted.

The jail does not go back in time. If the system clock steps back, also across a restart, it keeps working with the latest time it has seen, so bans that have ended do not come back.

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
1. Start the Lumberjack server on [live] listen:port (default 127.0.0.1);
   shippers may connect at any time, the loop does not wait for one
2. Initialize one sliding window per [live.NAME] section
3. Loop:
   a. Read the queued batches from the ingestor. If there are none: poll
      again after one second and, once idle for max(sleepBetweenIterations),
      run a heartbeat (expire window entries and bans, write the files if
      that changed them, publish a stats snapshot)
   b. Classify User-Agents against the UA lists (whitelisted-UA requests
      never enter any window; blacklisted-UA IPs are marked for force-jail)
   c. For each window: apply that window's regex filters, append the
      surviving requests, expire entries beyond the time/size bounds
   d. For each window and each cluster arg set: detect clusters
   e. Merge all jail-eligible detections, remove whitelisted ranges,
      append force-jailed /32s
   f. Update jail; write the jail file and the ban file (atomic) only
      when their content changed
   g. Publish the stats snapshot (if statsListen is set), log one
      iteration summary line
   h. Sleep max(sleepBetweenIterations) across windows; repeat
```

## Sliding Window

Live mode uses sliding windows to bound memory usage:

- **Time-bounded**: Old requests expire based on `slidingWindowMaxTime`
- **Size-bounded**: Capped at `slidingWindowMaxSize` to prevent unbounded growth
- **Lazy cleanup**: Cleanup runs on the detection timer and on the idle heartbeat, not per-request
- **Wall-clock expiry**: an entry expires when its log timestamp is older than `slidingWindowMaxTime` by the clock of the flokbn host; timestamps in the future are clamped to the arrival time so one bad stamp cannot hold back expiry

Multiple windows with different parameters are all updated by the single detection loop (which paces itself at the largest `sleepBetweenIterations`). See [Live Protection Guide]({{< relref "/docs/guides/live-protection/" >}}) for configuration.

## Lumberjack Protocol

flokbn implements the Lumberjack protocol (Beats protocol) for receiving logs from Filebeat:

```
Client (Filebeat) → [Lumberjack Protocol] → flokbn Server
```

**Protocol features** (Lumberjack v2): zlib-compressed batches, acknowledgments, windowed flow control, reliable delivery.

The server side is flokbn's own reader (`ingestor/lumberjack.go`), not a third-party library: every size a peer announces (events per window, event size, compressed and inflated batch size) is checked against a fixed limit before memory is allocated for it, and the number of connections and the bytes waiting for the detection loop are bounded. The listener binds `127.0.0.1` unless `[live] listen` says otherwise and can speak TLS or mutual TLS. A batch is acknowledged once it is queued for the detection loop, not once it has been processed, so batches still queued when the process dies are lost. See [Protocol limits]({{< relref "/docs/guides/live-protection/#protocol-limits" >}}).

## Optimization Techniques

### Memory Pools

Trie nodes come from chunked bump allocators (`pools/`), which reduces allocation and GC pressure.

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
├── accesslog/           # Request struct shared by the parsers (leaf package)
├── analysis/            # Analysis orchestration
├── cidr/                # Numeric CIDRs, interval sets, merge, whitelist filters
├── cli/                 # CLI commands and API entry points
├── config/              # Configuration structs and loading
├── ingestor/            # Live mode ingestion (Lumberjack server)
├── iputils/             # IP address utilities
├── jail/                # The jail: records, rules, jail file and ban file
├── logging/             # Leveled slog setup for live mode
├── logparser/           # Log format parsing
├── output/              # Output formatting (JSON, plain text)
├── pools/               # Trie node allocators, TrieNode struct
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
