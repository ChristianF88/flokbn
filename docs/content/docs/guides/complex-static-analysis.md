---
title: "Complex Static Analysis"
description: "Full-coverage static-mode example: multiple tries, every filter, and jail wiring in one TOML"
summary: "Walkthrough of the committed complex-static.toml example exercising the full static filter surface"
date: 2026-06-12T10:00:00+00:00
lastmod: 2026-06-12T10:00:00+00:00
draft: false
weight: 815
slug: "complex-static-analysis-guide"
toc: true
seo:
  title: "flokbn Complex Static Analysis Guide"
  description: "Learn how to combine multiple tries, filters, and cluster parameter sets in a single flokbn TOML configuration"
  canonical: ""
  noindex: false
---

This guide walks through the complex static-analysis example
(`config_examples/complex-static.toml`), a runnable configuration that
exercises the **entire static-mode filter surface** in a single run — one
command unpacks a self-contained, ready-to-run copy into a directory of your
choice with `flokbn generate static-demo` (see below): global IP and
User-Agent white-/blacklists, per-trie User-Agent/endpoint/time filters,
CIDR-range analysis, three cluster parameter regimes per trie, and mixed jail
wiring. It builds four differently-filtered tries from **one parse pass** over
a 1,000,000-line log and is the best starting point for writing your own
multi-trie configuration.

If you have not used static mode before, start with
[Static Analysis]({{< relref "/docs/guides/static-analysis/" >}}).

## Generating the Demo

`flokbn generate static-demo` writes a complete, runnable example into a
directory of your choice: a fixed 1,000,000-line synthetic access log
(`access.log`), the matching configuration TOML whose cluster thresholds are
calibrated for that log, and the four IP/UA list files it references. Every
path in the generated config is rewritten to an absolute, co-located target,
so the config runs from any working directory:

```bash
flokbn generate static-demo --out ./demo
```

`--out` is a directory and is optional — it defaults to the current directory
(`.`). The synthetic log is deterministic, so the figures below are
reproducible. There is no line-count flag: the demo always generates exactly
1,000,000 lines, and the config's `clusterArgSets` minimum sizes are
calibrated for that scale (hotspot `/16`s carrying ~7.5k–17.8k requests each).

The generated traffic has a known shape: ten weighted `/16` hotspots over a
uniform public-IP background (~13.9% of traffic, heaviest ~2%), Googlebot and
bingbot User-Agents reused across many requests (~10.4%, exact matches for two
entries in the UA whitelist — deliberate, see below), endpoints with
Zipf-distributed popularity, and timestamps ascending over 72 hours from
`2026-02-03T23:56:44Z`. The full 1,000,000-line log is ~185 MB.

**Using your own log instead:** point `logFile` at your access log and
adapt `logFormat` to its layout (see
[Log Formats]({{< relref "/docs/reference/log-formats/" >}})). You will
also need to adapt the per-trie `useragentRegex`/`endpointRegex` patterns,
the `startTime`/`endTime` window, and — most importantly — the
`clusterArgSets` minimum sizes to your traffic volume.

## Running It

```bash
flokbn static --config ./demo/complex-static.toml --plain
```

Add `--tui` instead of `--plain` for the interactive terminal UI. Because
`flokbn generate static-demo` rewrote every path to an absolute, co-located
target, the generated config runs from any working directory — there is no
need to be in a particular directory. Running the analysis writes
`heatmap.html`, `flokbn_jail.json`, and `flokbn_ban.txt` into the same demo
directory. The jail file persists across runs — delete it (together with
`flokbn_ban.txt` and `heatmap.html`) for a clean rerun.

## Global Lists

The `[global]` section wires all four list files:

- `whitelist` / `blacklist` — CIDRs never/always to ban. The examples hold
  private ranges plus public DNS, and TEST-NET-2 respectively; neither
  overlaps the hotspot ranges, so detection is unaffected.
- `userAgentWhitelist` / `userAgentBlacklist` — **exact** User-Agent string
  matches. Not substrings, not regexes: the full User-Agent header must
  equal a line in the file.

A whitelisted User-Agent removes the request from **every** trie and
shields its IP from jailing. A blacklisted User-Agent jails its IP
immediately as a `/32`.

The global lists are reported as **Active Filters** on every trie. With the
demo's list files this shows as `IP whitelist (8 CIDRs), UA whitelist (58
patterns)`, in addition to whatever per-trie filters that trie carries.

The example deliberately demonstrates whitelist precedence:
`ua_whitelist.txt` contains the exact Googlebot and bingbot strings present
in the fake data (~10.4% of all requests). That is why the unfiltered
baseline trie reports ~896k requests instead of 1,000,000 — the whitelisted
requests are gone before any trie sees them, and no per-trie filter can
bring them back.

The config does **not** blacklist the high-volume bot User-Agents (curl,
python-requests). A UA-blacklist hit jails each matching IP as an
individual `/32` — with hundreds of thousands of distinct client IPs using
those agents, the jail would be flooded with `/32` entries. Let clustering
find the dense ranges instead; reserve the UA blacklist for rare,
unambiguous attack tools.

## The Four Tries

Each `[static.NAME]` table builds one independent trie from the same parsed
log. All four use three `clusterArgSets`
(`[minSize, minDepth, maxDepth, threshold]`, see
[Clustering]({{< relref "/docs/reference/clustering/" >}})) spanning three
regimes: a **coarse sweep** (large minSize, shallow depths) that only the
heaviest ranges survive, a **standard sweep** sized to catch the dominant
hotspot ranges, and a **deep sweep** (smaller minSize, minDepth 18) that
slices hotspots into finer subranges.

### t1_baseline — no per-trie filters

All traffic minus UA-whitelisted requests: ~896k requests. Hotspot `/16`s
carry ~7.5k–17.8k requests while a background `/16` carries only ~12, so the
size thresholds separate them cleanly: minSize 10000 yields only the
heaviest hotspot cores, 5000 the dominant hotspot ranges, and 1500 at
depth 18–26 finer slices of each hotspot.
`cidrRanges` additionally reports raw request counts for one broad `/8` and
two narrow `/16`s. Only the conservative coarse set feeds the jail
(`useForJail = [true, false, false]`) — the finer sets are exploratory.

### t2_bots — useragentRegex

`"Googlebot|bingbot|python-requests|curl|Anubis"` names all five bot
User-Agents, but the Googlebot/bingbot requests are already gone — the
exact-match UA whitelist wins over any per-trie filter. What remains is
curl + python-requests + Anubis: ~196k requests, hotspot `/16`s carrying
~1.7k–3.9k. The minSizes scale down accordingly (2000/1000/350). The two
coarser sets feed the jail.

### t3_hot_endpoints — endpointRegex

`"^/fake-endpoint-[1-9]$"` selects the nine hottest endpoints. Endpoint
popularity is Zipf-distributed, so the top nine carry ~60% of traffic and
~545k requests survive, with hotspot `/16`s carrying ~4.5k–10.6k
(minSizes 6000/3000/1000). Only the middle set feeds the jail.

### t4_targeted_window — everything combined

UA regex + endpoint regex + a 24-hour `startTime`/`endTime` window
(RFC3339; the fake log spans `2026-02-03T23:56Z` to `2026-02-06T23:58Z`).
Each filter multiplies: bots × hot endpoints × one third of the time range
leaves ~39k requests, hotspot `/16`s carrying just ~310–760 — hence minSizes
of 300/150/60. Even after triple filtering, the coarse sweep still recovers
the hotspot `/16`s intact. Only the deep sweep feeds the jail
(`useForJail = [false, false, true]`).

Jail contributions compose across tries: every cluster set marked `true`
in any trie adds its detected ranges to the **same** jail, which is then
filtered through the IP whitelist and published to the ban file together
with the IP blacklist entries.

## Why TOML Instead of CLI Flags

- **One parse, N tries.** The log is read and parsed once; all four
  tries are built from the same pass. Reproducing this with CLI flags
  takes four separate runs, i.e. four full parses.
- **Per-trie filters.** A CLI run applies one global filter set; named
  `[static.NAME]` tables each carry their own `useragentRegex`,
  `endpointRegex`, and time window. Combining differently-filtered views
  of the same log is not expressible as flags.
- **User-Agent lists.** `userAgentWhitelist`/`userAgentBlacklist` are
  config-only — basic CLI usage has no equivalent flags.
- **Selective jailing.** `useForJail` chooses per cluster set what feeds
  the jail; CLI cluster arg sets all count toward jailing.
- **Reviewable and reproducible.** The complete analysis — filters,
  thresholds, list files, jail wiring — lives in one version-controlled
  file instead of a shell history entry.

## Expected Output

Abbreviated `--plain` output (full run against the generated demo data).
Because the synthetic generator is deterministic, the per-trie totals and
hotspot `/16` counts are reproducible, though the exact shape of the detected
ranges varies with the cluster regime: the generator spreads hotspot traffic
uniformly within each `/16`, so the coarse/standard sweeps tend to report
whole `/16`s while the deep sweep slices them into `/17`/`/18`/`/19` subranges.

```
📊 ANALYSIS OVERVIEW
────────────────────────────────────────────────────────────
Log File:        /path/to/demo/access.log
Analysis Type:   static

⚡ PARSING PERFORMANCE
────────────────────────────────────────────────────────────
Total Requests:  1,000,000
Parse Time:      360 ms
Parse Rate:      2,773,168 requests/sec

🎯 TRIE: t1_baseline
────────────────────────────────────────────────────────────
Requests After Filtering: 895,978
Excluded (UA whitelist): 104,022
Unique IPs:              884,202
Trie Build Time:         1364 ms
Active Filters:          IP whitelist (8 CIDRs), UA whitelist (58 patterns)

📍 CIDR RANGE ANALYSIS
  23.0.0.0/8                21,316 requests  (  2.38%)
  23.253.0.0/16             17,838 requests  (  1.99%)
  87.26.0.0/16              15,018 requests  (  1.68%)

🔍 CLUSTERING RESULTS (3 sets)
  Set 1: min_size=10000, depth=12-18, threshold=0.20
  Execution Time: 37 μs
  Detected Threat Ranges:
    23.253.0.0/16             17,838 requests  (  1.99%)
    35.217.0.0/16             11,220 requests  (  1.25%)
    50.231.0.0/16             11,938 requests  (  1.33%)
    87.26.0.0/16              15,018 requests  (  1.68%)
    143.173.0.0/16            15,955 requests  (  1.78%)
    166.94.0.0/16             12,563 requests  (  1.40%)
    183.77.0.0/16             15,046 requests  (  1.68%)
    ───────────────────       99,578 requests  ( 11.11%) [TOTAL]
  ...

🎯 TRIE: t2_bots
────────────────────────────────────────────────────────────
Requests After Filtering: 195,509
Active Filters:          User-Agent: Googlebot|bingbot|python-requests|curl|Anubis,
                         IP whitelist (8 CIDRs), UA whitelist (58 patterns)
  ...

🎯 TRIE: t3_hot_endpoints
────────────────────────────────────────────────────────────
Requests After Filtering: 545,070
Active Filters:          Endpoint: ^/fake-endpoint-[1-9]$,
                         IP whitelist (8 CIDRs), UA whitelist (58 patterns)
  ...

🎯 TRIE: t4_targeted_window
────────────────────────────────────────────────────────────
Requests After Filtering: 39,399
Active Filters:          User-Agent: python-requests|curl|Anubis,
                         Endpoint: ^/fake-endpoint-[1-9]$,
                         Time: 2026-02-04 12:00 → 2026-02-05 12:00,
                         IP whitelist (8 CIDRs), UA whitelist (58 patterns)

🔍 CLUSTERING RESULTS (3 sets)
  Set 1: min_size=300, depth=12-16, threshold=0.20
  Execution Time: 49 μs
  Detected Threat Ranges:
    23.253.0.0/16                757 requests  (  1.92%)
    35.217.0.0/16                519 requests  (  1.32%)
    ...
    ───────────────────        5,516 requests  ( 14.00%) [TOTAL]
  ...
```

Every cluster set detects the genuine hotspot `/16`s; the four tries report
~896k / ~196k / ~545k / ~39k requests after filtering. After the run,
`flokbn_ban.txt` contains the jailed ranges plus the IP blacklist entries,
`flokbn_jail.json` holds the persistent jail state, and `heatmap.html` shows
the first-octet/second-octet request distribution.

## Performance

Measured on the generated 1,000,000-line / ~185 MB demo log (single run, plain
output, jail enabled):

| Stage                          | Time        |
|--------------------------------|-------------|
| Parse (1,000,000 requests)     | 360 ms (2,773,168 requests/sec) |
| t1_baseline build (884k unique IPs)   | 1364 ms |
| t2_bots build (195k unique IPs)       | 589 ms  |
| t3_hot_endpoints build (541k unique IPs) | 1093 ms |
| t4_targeted_window build (39k unique IPs) | 78 ms |
| Each clustering set            | 28–153 μs   |
| **Total (four-trie analysis)** | **~2.5 s**  |

Four differently-filtered tries plus twelve clustering passes add little on
top of the parse: clustering itself runs in microseconds per set — the
dominant costs are parsing and trie construction. See
[Performance]({{< relref "/docs/architecture/performance/" >}}) for how the
parser and tries achieve this.

> **Note on the synthetic data:** `flokbn generate static-demo` scatters IPs
> almost uniformly at random, so the vast majority of requests carry a distinct
> address. Real logs reuse client IPs heavily, which builds a far smaller,
> cache-resident trie — so on real traffic of the same volume the build times
> are substantially lower. Read the figures above as a deliberate worst case.
