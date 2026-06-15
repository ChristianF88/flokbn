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
exercises the **entire static-mode filter surface** in a single run — you can
unpack it into a working directory with `flokbn example config` (see below):
global IP and User-Agent white-/blacklists,
per-trie User-Agent/endpoint/time filters, CIDR-range analysis, three
cluster parameter regimes per trie, and mixed jail wiring. It builds four
differently-filtered tries from **one parse pass** over a 10-million-line
log and is the best starting point for writing your own multi-trie
configuration.

If you have not used static mode before, start with
[Static Analysis]({{< relref "/docs/guides/static-analysis/" >}}).

## Scaffolding the Example

`flokbn example config` writes a runnable copy of this configuration — the
TOML plus its four list files — into a directory of your choice. Every path
in the scaffolded config is rewritten to an absolute, co-located target, so
the config runs from any working directory:

```bash
flokbn example config --out ./demo
```

## Generating the Log

The config drives a synthetic log produced by the matching generator. Write
it into the scaffolded directory as `access.log` — the file name the
scaffolded config expects:

```bash
flokbn example logs --out ./demo/access.log --lines 10000000
```

The generator is deterministic for a given `--seed` (default 42) and
produces traffic with a known shape: ten weighted `/16` hotspots over a
uniform public-IP background, ten User-Agents (including exact matches for
two entries in the UA whitelist — deliberate, see below), 100 endpoints with
Zipf-distributed popularity, and timestamps ascending over 72 hours from
`2026-02-03T23:56:44Z`. The full 10-million-line log is ~1.9 GB.

`flokbn example logs` defaults to 1,000,000 lines for a quick taste, but the
`clusterArgSets` minimum sizes in the scaffolded config are calibrated for
the full 10M-line run (hotspot `/16`s carrying 77k–178k requests each). Pass
`--lines 10000000` to reproduce the figures below, or lower the per-trie
minimum sizes to match a smaller log.

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

Because `flokbn example config` rewrote every path to an absolute,
co-located target, the scaffolded config runs from any working directory —
there is no need to be in a particular directory. The jail file
(`flokbn_jail.json`) persists across runs — delete it (together with
`flokbn_ban.txt` and `heatmap.html`, all in the scaffold directory) for a
clean rerun.

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

The example deliberately demonstrates whitelist precedence:
`ua_whitelist.txt` contains the exact Googlebot and bingbot strings present
in the fake data (~10.4% of all requests). That is why the unfiltered
baseline trie reports ~8.95M requests instead of 10M — the whitelisted
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

All traffic minus UA-whitelisted requests: ~8.95M requests. Hotspot `/16`s
carry 77k–178k requests while a background `/16` carries only ~116, so the
size thresholds separate them cleanly: minSize 100000 yields only the
heaviest hotspot cores, 50000 the dominant hotspot ranges, and 15000 at
depth 18–26 finer slices of each hotspot.
`cidrRanges` additionally reports raw request counts for one broad `/8` and
two narrow `/16`s. Only the conservative coarse set feeds the jail
(`useForJail = [true, false, false]`) — the finer sets are exploratory.

### t2_bots — useragentRegex

`"Googlebot|bingbot|python-requests|curl|Anubis"` names all five bot
User-Agents, but the Googlebot/bingbot requests are already gone — the
exact-match UA whitelist wins over any per-trie filter. What remains is
curl + python-requests + Anubis: ~1.96M requests, hotspot `/16`s carrying
~17k–39k. The minSizes scale down accordingly (20000/10000/3500). The two
coarser sets feed the jail.

### t3_hot_endpoints — endpointRegex

`"^/fake-endpoint-[1-9]$"` selects the nine hottest endpoints. Endpoint
popularity is Zipf-distributed: `/fake-endpoint-1` alone is ~23% of
traffic, the top nine ~60%, so ~5.4M requests survive and hotspot `/16`s
carry ~47k–108k (minSizes 60000/30000/10000). Only the middle set feeds
the jail.

### t4_targeted_window — everything combined

UA regex + endpoint regex + a 24-hour `startTime`/`endTime` window
(RFC3339; the fake log spans `2026-02-03T23:56Z` to `2026-02-06T23:58Z`).
Each filter multiplies: bots (~19.5%) × hot endpoints (~60%) × one third of
the time range leaves ~0.4M requests, hotspot `/16`s carrying just
~3.4k–8k — hence minSizes of 3000/1500/600. Even after triple filtering,
the coarse sweep still recovers the hotspot `/16`s intact. Only the deep
sweep feeds the jail (`useForJail = [false, false, true]`).

Jail contributions compose across tries: every cluster set marked `true`
in any trie adds its detected ranges to the **same** jail, which is then
filtered through the IP whitelist and published to the ban file together
with the IP blacklist entries.

## Why TOML Instead of CLI Flags

- **One parse, N tries.** The 1.9 GB log is read and parsed once; all four
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

Abbreviated `--plain` output (full run against the reference fake data).
If you regenerate the data with `flokbn example logs`, the per-trie totals
and hotspot `/16` counts match closely, but the exact shape of the detected
ranges differs: the generator spreads hotspot traffic uniformly within
each `/16`, so the sweeps tend to report whole `/16`s and their `/17`/`/18`
halves rather than the dense cores shown below.

```
📊 ANALYSIS OVERVIEW
────────────────────────────────────────────────────────────
Log File:        /home/you/demo/access.log
Analysis Type:   static

⚡ PARSING PERFORMANCE
────────────────────────────────────────────────────────────
Total Requests:  10,000,000
Parse Time:      1157 ms
Parse Rate:      8,636,353 requests/sec

🎯 TRIE: t1_baseline
────────────────────────────────────────────────────────────
Requests After Filtering: 8,956,933
Unique IPs:              7,329,290
Trie Build Time:         5916 ms

📍 CIDR RANGE ANALYSIS
  23.0.0.0/8               207,786 requests  (  2.32%)
  23.253.0.0/16            177,630 requests  (  1.98%)
  87.26.0.0/16             150,743 requests  (  1.68%)

🔍 CLUSTERING RESULTS (3 sets)
  Set 1: min_size=100000, depth=12-18, threshold=0.20
  Execution Time: 20 μs
  Detected Threat Ranges:
    23.253.128.0/18          104,606 requests  (  1.17%)
    50.231.0.0/18            119,445 requests  (  1.33%)
    87.26.128.0/18           150,664 requests  (  1.68%)
    143.173.192.0/18         160,529 requests  (  1.79%)
    166.94.192.0/18          125,922 requests  (  1.41%)
    183.77.0.0/18            151,619 requests  (  1.69%)
    ───────────────────      812,785 requests  (  9.07%) [TOTAL]
  ...

🎯 TRIE: t2_bots
────────────────────────────────────────────────────────────
Requests After Filtering: 1,951,540
Active Filters:  User-Agent: Googlebot|bingbot|python-requests|curl|Anubis
  ...

🎯 TRIE: t3_hot_endpoints
────────────────────────────────────────────────────────────
Requests After Filtering: 5,444,209
Active Filters:  Endpoint: ^/fake-endpoint-[1-9]$
  ...

🎯 TRIE: t4_targeted_window
────────────────────────────────────────────────────────────
Requests After Filtering: 395,518
Active Filters:  User-Agent: python-requests|curl|Anubis,
                 Endpoint: ^/fake-endpoint-[1-9]$,
                 Time: 2026-02-04 12:00 → 2026-02-05 12:00

🔍 CLUSTERING RESULTS (3 sets)
  Set 1: min_size=3000, depth=12-16, threshold=0.20
  Execution Time: 41 μs
  Detected Threat Ranges:
    23.253.0.0/16              7,921 requests  (  2.00%)
    35.217.0.0/16              5,167 requests  (  1.31%)
    ...
    ───────────────────       62,575 requests  ( 15.82%) [TOTAL]
  ...
```

Every cluster set detects at least one range; the four tries report
~8.95M / ~1.96M / ~5.40M / ~0.39M requests after filtering. After the run,
`flokbn_ban.txt` contains the jailed ranges plus the IP blacklist entries,
`flokbn_jail.json` holds the persistent jail state, and `heatmap.html` shows
the first-octet/second-octet request distribution.

## Performance

Measured on the reference 10M-line / 1.9 GB fake log (single run, plain
output):

| Stage                          | Time        |
|--------------------------------|-------------|
| Parse (10,000,000 requests)    | 1157 ms (8,636,353 requests/sec) |
| t1_baseline build (7.33M unique IPs)  | 5916 ms |
| t2_bots build (1.67M unique IPs)      | 2558 ms |
| t3_hot_endpoints build (4.53M unique IPs) | 4527 ms |
| t4_targeted_window build (0.35M unique IPs) | 415 ms |
| Each clustering set            | 20–99 μs    |
| **Total (four-trie analysis)** | **7145 ms** |

Four differently-filtered tries plus twelve clustering passes add little on
top of the parse: clustering itself runs in microseconds per set — the
dominant costs are parsing and trie construction. See
[Performance]({{< relref "/docs/architecture/performance/" >}}) for how the
parser and tries achieve this.

> **Note on the synthetic data:** `flokbn example logs` scatters IPs almost
> uniformly at random, so ~85 % of requests carry a distinct address. Real logs reuse
> client IPs heavily, which builds a far smaller, cache-resident trie — so on
> real traffic of the same volume the build times are substantially lower.
> Read the figures above as a deliberate worst case.
