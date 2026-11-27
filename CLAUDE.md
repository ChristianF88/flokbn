# CLAUDE.md

Guidance for working in this repository.

## What flokbn is

A Go CLI that clusters the IPs in HTTP access logs into CIDR ranges using a binary
trie, for botnet detection, abuse analysis, and ban-list generation. A 2M-line log
clusters in ~1s on a workstation. Two modes:

- **`flokbn static`** - batch-analyze a log file. Output: JSON / compact JSON / plain text / interactive TUI.
- **`flokbn live`** - continuous monitoring. Ingests over the Lumberjack protocol (Filebeat-compatible), keeps a sliding window, escalates detected ranges through a persistent **jail**, and serves HTTP `/stats`, `/bans`, Prometheus `/metrics`. The ingest listener binds `[live] listen` / `--listen` (default `127.0.0.1`); optional TLS / mutual TLS via `tlsCert`, `tlsKey`, `tlsClientCA` (config file only).

**IPv4 only.** IPv6 is deliberately unsupported and rejected loudly at config load.

## Repo layout

```
flokbn/src/          # THE GO MODULE lives here, not at repo root
  main.go            # entry: cli.App.Run(os.Args)
  cli/               # command defs (urfave/cli v2), api.go entry points, live_loop.go (liveLoop), stats server, plain_output.go, generate, synthlog
  config/            # TOML + flag parsing; regexprefilter/ subpkg
  accesslog/         # the Request record every parser fills, HTTPMethod, Uint32ToIPString (imports only iputils)
  logparser/         # format-string compiler; Parser (files, multi-worker) and LineParser (single lines, live mode)
  ingestor/          # TCPIngestor + own size-limited Lumberjack v2 reader (lumberjack.go); parses with logparser.LineParser
  trie/              # binary trie, CollectCIDRsNumeric clustering walk, CountInCIDR
  cidr/              # NumericCIDR, Parse, IntervalSet, MergeCIDRs, whitelist subtraction (RemoveWhitelisted), UserAgentMatcher
  analysis/          # Static() / StaticWithRequests(): one pipeline (runStatic) parse→filter→trie→cluster→publish; UpdateBans
  sliding/           # time+size bounded window for live mode
  jail/              # the jail: records and rules (jail.go), jail file (file.go), ban file and atomic writes (banfile.go)
  output/            # JSONOutput, plain text, PlotHeatmap (echarts HTML)
  tui/               # tview dashboard
  pools/             # TrieNode allocators (chunked + lock-free bump)
  iputils/ logging/ version/ testutil/
docs/                # Hugo site (published to GitHub Pages)
e2e/                 # bash e2e suites + e2e/Makefile
config_examples/  flokbn.toml.example   # sample configs
docker-compose*.yml  grafana/ prometheus/ nginx-exporter/ proxy/ filebeat/  # demo stack
.github/workflows/   # ci.yml, release.yml, docs.yml
```

**Gotcha:** module path is `github.com/ChristianF88/flokbn` but the module root is
`flokbn/src/`. All `go` commands must run from `flokbn/src/`. The repo-root Makefile
handles this via `GO_DIR := flokbn/src`.

## Build / test / lint

Run from **repo root** (Makefile cd's into `flokbn/src`):

```bash
make              # default = test: fmt-check → vet → staticcheck → go-test → e2e (non-docker)
make fmt          # gofmt -w
make vet
make staticcheck  # needs honnef.co/go/tools/cmd/staticcheck on PATH
make go-test      # go test ./...
make test-race    # go test -race ./...
make bench        # go test -bench=. -benchmem ./...
make test-docker  # docker live e2e (live, live-detection, live-firewall)
make test-all     # test + test-race + test-docker
```

Build the binary, single test, e2e (from `flokbn/src/` unless noted):

```bash
cd flokbn/src && go build -o flokbn .
cd flokbn/src && go test -run TestName ./cidr
cd e2e && bash e2e_static_test.sh        # non-docker e2e scripts
```

Go 1.23. Tests use the standard library `testing` package (no testify or go-cmp).
`github.com/elastic/go-lumber` is in go.mod for tests only: its client drives the
ingestor and live e2e tests, the server side is our own reader. ~169 `_test.go` files including
differential fuzz (`cidr/removewhitelisted_diff_test.go`,
`ingestor/live_parser_diff_test.go`), a reference-model test (`jail/reference_test.go`)
and invariant tests (`analysis/whitelist_invariant_test.go`). Real-world benchmarks
are env-gated (run manually).

CI (`.github/workflows/ci.yml`): prepare (go mod tidy must be clean) → lint → test
(race + coverage → Codecov) → cross-platform build matrix. Release on `v*` tag via
GoReleaser. No golangci-lint config; lint = gofmt + vet + staticcheck only.
Actions are pinned to full commit SHAs (version in a trailing comment), staticcheck to
`v0.6.1` (the last release that builds with Go 1.23) and GoReleaser to an exact
version in `release.yml`. `.goreleaser.yaml` has no before-hooks: the release job
holds a write token, and tests run in the CI job it requires.

## Core concepts

- **Cluster arg set** = `minSize,minDepth,maxDepth,threshold`. minSize = min request
  count; depth = CIDR prefix-length search range; threshold = max imbalance between a
  subtree's halves (0.1 = emit a subtree when traffic spreads across it with ≤10%
  imbalance). Multiple sets run in one pass as detection tiers (tight = hot hosts,
  loose = whole subnets). Static flag `--clusterArgSets`, live flag `--clusterArgSet`;
  each command accepts the other spelling as an alias. One flag = one set (repeat the
  flag). Both surfaces share `validateClusterArgValues` (`config/clusterargs.go`): whole
  minSize >= 1, whole depths with 0 <= minDepth <= maxDepth <= 32, threshold in [0, 2].
- **Trie clustering** (`trie.CollectCIDRsNumeric`): DFS walk emitting a node's prefix
  as a `NumericCIDR{IP uint32, PrefixLen uint8}` when balance/size/depth gates pass;
  early-exits to avoid overlapping ranges. Both pipelines keep the ranges numeric
  after the walk: count with `Trie.CountInCIDR`, merge with `cidr.MergeCIDRs` (in
  place), and build each string once, for the JSON output, the /stats snapshot and
  the jail (`processClustering` in `analysis/static.go`, `liveLoop.clusterWindow`
  in `cli/live_loop.go`). The ranges are merged within a cluster set only: the jail
  gets every set's ranges as that set found them (static: `jailCandidates`, live:
  `liveLoop.iterate`), so a hot host and the subnet around it are two records.
- **CIDR strings to numbers** (`cidr/numeric.go`): `cidr.Parse` is the one parser
  outside config and jail. It accepts exactly what `net.ParseCIDR` accepts with a
  4-byte mask (canonical spelling without allocating, anything else via
  `net.ParseCIDR`; `FuzzParse` holds it to that). `cidr.IntervalSet` is the one
  sorted, merged `[start,end]` form of a CIDR list: the whitelist in
  `RemoveWhitelisted` and the TUI cluster overlay (`tui/cluster_membership.go`) use
  it. The `*net.IPNet` merge the numeric one replaced (`MergeIPNets`) lives on as
  test oracle in `cidr/merge_ref_test.go`.
- **Jail** (`jail/`): the persistent record of banned ranges, used by both modes.
  A record is a range, the stage of its last ban and the start of that ban; whether a
  ban is active is computed from the time handed to each call, nothing is flagged on
  disk. 5 stages: 10m -> 4h -> 7d -> 30d -> 180d, the last one repeats; a record is
  forgotten 180d after its ban ended. Two ranges are the same offender when the
  narrower fills at least `Overlap` percent (50) of the wider. A detected range is
  judged against the jail as it was before the round: (1) all its addresses banned ->
  ignored; (2) banned one stage above its history = max(own ended record, ended
  records around it that it fills >= 50% of, highest stage that >= 50% of its
  addresses served in ended records inside it); (3) an ended record around it that it
  fills >= 50% of is banned again as a whole; (4) ended records inside it are banned
  again, each at its own next stage. An active ban passes no history (a stage cannot
  climb to wider ranges round by round) and is never replaced. Records are NOT merged
  or absorbed: the jail keeps every detected range with its own stage (the wider
  record does not pass its stage down to a range below the threshold, so dropping the
  narrow one would lose history). Nested and neighbouring bans are joined only in
  `Jail.BanList`, which is what the ban file is built from: only running bans, a
  range inside another one listed once, two allocations however long the list. The
  jail's time never goes back (`Jail.at`): it is the latest time an `Update` saw, and
  a jail read from a file starts at the latest ban start in the file, so this holds
  across a restart and the first round counts the bans that ran out meanwhile
  (`Outcome.Ended`). `Decode` is strict (unknown or repeated keys, missing fields, a
  range listed twice are errors). The file format of the jail this one replaced
  (top-level `Cells`) is not read: `Decode` says so and to delete the file. Stages,
  overlap and retention are `jail.DefaultConfig()`; there are no TOML keys for them
  yet. Tests: the rule table (`rules_test.go`), an address-by-address reference model
  that random scripts and `FuzzUpdate` compare against (`reference_test.go`), the
  file formats (`file_test.go`, `banfile_test.go`), benchmarks (`bench_test.go`).
- **Whitelist semantics:** the whitelist (CIDR file + User-Agent-whitelisted IPs as
  /32) is applied at two points with different rules.
  *Before the jail* (`cidr.DropFullyWhitelisted`): a detected CIDR is dropped only if
  **fully covered by a single whitelist entry**; coverage by the union of several
  entries does NOT drop it and partial overlaps are kept whole (deliberate: carving
  around many /32 holes would explode the jail into fragments).
  *At publish* (`cidr.ComposeBanLists` -> `RemoveWhitelisted`): the whitelist is
  subtracted exactly from active bans AND the manual blacklist, so anything covered by
  the union of entries is removed and partial overlaps are carved. This is the choke
  point that guarantees a whitelisted address is never published (see
  `analysis/whitelist_invariant_test.go`). `RemoveWhitelisted` parses the whitelist once
  (O(B+W), not O(B*W); `ComposeBanLists` once for both lists) and is byte-identical
  to the old path for IPv4 (proven by differential fuzz).
  `analysis.UpdateBans(*jail.Jail, BanInput)` runs both points and the jail update
  on an in-memory jail at `BanInput.Now`, without I/O (invariant:
  `analysis/whitelist_invariant_test.go`). Every mode publishes through it:
  static in `analysis/publish.go`, live in `liveLoop.publishBans` (`cli/live_loop.go`).
- **Static pipeline** (`analysis/static.go`): both entrypoints run `runStatic`. The
  parse is IP-only when no trie filters and the caller does not want the requests,
  else full. Tries without filters share one sorted IP list (`parsedLog.sortedIPs`);
  tries with filters go through the single request filter (`filterResult.add` in
  `analysis/filter.go`, concurrent above 50,000 requests). Golden snapshots of the
  observable output live in `analysis/testdata/static_pipeline/` (regenerate only for
  an intended change: `go test ./analysis -run TestStaticPipelineGolden -update`).
- **Trie tables in config** (`config/config.go`): `TrieConfig` (`[static.<name>]`) and
  `SlidingTrieConfig` (`[live.<name>]`) embed one `TrieCommon` by value: regex filters
  with their compiled state, time bounds, cluster-arg sets, `useForJail`. Its fields
  and methods are promoted (`tc.UserAgentRegex`, `tc.ShouldIncludeRequest(req)`), but
  a composite literal must name it:
  `config.TrieConfig{TrieCommon: config.TrieCommon{UserAgentRegex: "bot"}}`.
  Both tables share one parser (`TrieCommon.parse`, `parseCIDRRanges`) and one
  validation loop (`Config.eachTrie`); add a shared key there, not per table.
- **`[global]` list files** (whitelist, blacklist, both User-Agent lists) are read once
  per `Config` (`config/lists.go`): the first `Load...` call reads the file - in a CLI
  run that is `Validate` at the barrier - and every later call returns the kept
  entries or the kept error. The static pipeline, the ban publish and the live loop
  therefore enforce exactly what was validated. An edited list file needs a new
  `Config` (a new run).
- **IPv4-only gate:** discriminator is `len(ipNet.Mask) != 4` (4 bytes = IPv4,
  16 = IPv6 incl. IPv4-mapped `::ffff:`). Rejected at config load; skipped/kept-verbatim
  in hot paths as defense-in-depth (`cidr.Parse` applies the gate for the cidr
  package and the TUI).

## Conventions / gotchas

- Hot paths avoid allocations: `NumericCIDR` over strings, custom `.String()` without
  `fmt.Sprintf` (one octet formatter: `iputils.PutUint8` / `PutIPv4`), memory pools
  for trie nodes, IP-only fast path skips URI/UA parsing when no regex filter is set.
- Log format strings: exactly one `%h`, no duplicate specifiers (except `%^`).
  Static default (`logparser.DefaultLogFormat`) is
  `%^ %^ %^ [%t] "%r" %s %b "%^" "%u" "%h"`: `%h` last, every quoted slot quoted.
  Live mode uses the same compiler through `logparser.LineParser` with its OWN key
  (`[live] logFormat`, `live --logFormat`) and its OWN default
  (`logparser.DefaultLiveLogFormat`, `%h %^ %^ [%t] "%r" %s %b "%^" "%u"`: `%h`
  first, what live mode always read). `[static] logFormat` does not apply to live.
  Both modes reject a filter whose field is missing from their format
  (`config/filter_fields.go`); live additionally requires `%t`.
- Live line parsing (`logparser/line.go`): a line is dropped only for an invalid
  `%h` (`ErrInvalidIP`, incl. IPv6 and 0.0.0.0) or an invalid `%t`
  (`ErrInvalidTimestamp`). A line whose `[%t]` does not parse in place is re-aligned
  on the first bracket holding a valid timestamp (slow path; keeps a space in the
  client-controlled user field from hiding a request). The old hardcoded live
  parser survives only as the test oracle `ingestor/legacy_parser_test.go`; `ingestor/live_parser_diff_test.go` lists every
  divergence from it with the decision taken.
- File parser re-alignment (`logparser/realign.go`, enabled by `NewParser`): the
  literals of the format delimit the fields, so a space in a bare free-text field
  (the user name) does not shift what follows when `[%t]`, a quoted slot or a
  non-space delimiter comes behind it. `compileFormat` alone stays positional (that
  is what `LineParser` uses). The slow path hangs off the bare scan's existing
  "stopped on its delimiter?" test - do not add per-field work to the walkers; the
  differential tests against `logparser/legacy_walk_test.go` and the asm of the
  bare path are the check. Rules and residual cases: docs `reference/log-formats.md`,
  "Spaces in bare fields".
- Flag/TOML surfaces: aliases `--logFile` (= `--logfile`) and `--cidrRanges`
  (= `--rangesCidr`); `startTime`/`endTime` use one parser for flags and TOML
  (`config.ParseTimeBound`: RFC3339 or the short forms); omitted
  `sleepBetweenIterations` = 10 on both (`config.DefaultSleepBetweenIterations`).
- Live loop (`cli/live_loop.go`): `liveLoop` holds the state, `run` reads batches. A
  round is an iteration (`iterate`: a batch arrived) or a heartbeat (`heartbeat`: idle
  for `sleepBetweenIterations`, at least 1s). Both end in `publishBans`; a heartbeat
  hands in no detections, so it only expires bans - a ban is started or escalated by
  an iteration alone. `clusterWindow` is the one clustering loop (iteration, and the
  heartbeat's stats refresh after window expiry).
  `cli/live_ban_characterization_test.go` pins the jail and ban-file outcome of both.
- Live mode writes jail.json and the ban file only when their content changed
  (`jailFileState`, `banFileState` in `cli/live_persist.go`). A ban that runs out
  changes the ban file, not the jail's records.
- Live log lines other code or docs rely on are constants: `liveAcceptingMsg`
  ("accepting Lumberjack connections", the listener is up; nothing waits for a
  shipper), `liveTimestampSkewMsg`, `liveRejectedLinesMsg` (more than half of at
  least 20 incoming lines were parse errors, usually a `[live] logFormat` mismatch;
  at most once per minute).
- Config mode vs flag mode are mutually exclusive per command. With `--config`, only
  output flags are allowed alongside it (static: `--tui/--compact/--plain`; live: `--logLevel`).
- `flokbn generate static-demo` writes a self-contained demo (1M-line synthetic
  access.log + calibrated TOML + white/blacklist files) with absolute paths rewritten
  into the config. Use it to reproduce behavior locally.
- When editing CIDR/jail/whitelist logic, the invariant and differential-fuzz tests
  are the safety net - run `cd flokbn/src && go test ./cidr ./jail ./analysis`
  after changes.
