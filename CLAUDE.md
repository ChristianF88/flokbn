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
  cli/               # command defs (urfave/cli v2), api.go orchestration, stats server, generate, synthlog
  config/            # TOML + flag parsing; regexprefilter/ subpkg
  logparser/         # fast multi-worker log parser, format-string compiler
  ingestor/          # Request type; TCPIngestor + own size-limited Lumberjack v2 reader (lumberjack.go)
  trie/              # binary trie, CollectCIDRsNumeric clustering walk
  cidr/              # CIDR merge/subtract, RemoveWhitelisted, UserAgentMatcher
  analysis/          # Static() / StaticWithRequests(): one pipeline (runStatic) parse→filter→trie→cluster→publish; UpdateBans
  sliding/           # time+size bounded window for live mode
  jail/              # persistent escalating ban state (jail.go, io.go)
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
ingestor and live e2e tests, the server side is our own reader. ~137 `_test.go` files including
differential fuzz (`cidr/removewhitelisted_diff_test.go`) and invariant tests
(`jail/whitelist_invariant_test.go`). Real-world benchmarks are env-gated (run manually).

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
  early-exits to avoid overlapping ranges.
- **Jail** (`jail/`): persistent escalating ban state for live mode. 5 cells with
  durations 10m → 4h → 7d → 30d → 180d. A CIDR escalates to the next cell on
  re-detection after expiry. Parent ranges consolidate contained sub-ranges (prevents
  fragment explosion). Persisted as JSON; bounds cached as uint32 to avoid re-parsing.
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
  `jail/whitelist_invariant_test.go`). `RemoveWhitelisted` parses the whitelist once
  (O(B+W), not O(B*W)) and is byte-identical to the old path for IPv4 (proven by
  differential fuzz).
  `analysis.UpdateBans(*jail.Jail, BanInput)` runs both points plus ban expiry and the
  jail update on an in-memory jail, without I/O; static mode publishes through it
  (`analysis/publish.go`).
- **Static pipeline** (`analysis/static.go`): both entrypoints run `runStatic`. The
  parse is IP-only when no trie filters and the caller does not want the requests,
  else full. Tries without filters share one sorted IP list (`parsedLog.sortedIPs`);
  tries with filters go through the single request filter (`filterResult.add` in
  `analysis/filter.go`, concurrent above 50,000 requests). The `[global]` list files
  are read once per run (`analysis/lists.go`). Golden snapshots of the observable
  output live in `analysis/testdata/static_pipeline/` (regenerate only for an intended
  change: `go test ./analysis -run TestStaticPipelineGolden -update`).
- **IPv4-only gate:** discriminator is `len(ipNet.Mask) != 4` (4 bytes = IPv4,
  16 = IPv6 incl. IPv4-mapped `::ffff:`). Rejected at config load; skipped/kept-verbatim
  in hot paths as defense-in-depth.

## Conventions / gotchas

- Hot paths avoid allocations: `NumericCIDR` over strings, custom `.String()` without
  `fmt.Sprintf`, memory pools for trie nodes, IP-only fast path skips URI/UA parsing
  when no regex filter is set.
- Log format strings: exactly one `%h`, no duplicate specifiers (except `%^`).
  Static default (`logparser.DefaultLogFormat`) is
  `%^ %^ %^ [%t] "%r" %s %b "%^" "%u" "%h"`: `%h` last, every quoted slot quoted.
  Static mode rejects a filter whose field is missing from the format
  (`config/filter_fields.go`). Live mode ignores `logFormat`: its own parser in
  `ingestor/` reads the client IP from the first field.
- Flag/TOML surfaces: aliases `--logFile` (= `--logfile`) and `--cidrRanges`
  (= `--rangesCidr`); `startTime`/`endTime` use one parser for flags and TOML
  (`config.ParseTimeBound`: RFC3339 or the short forms); omitted
  `sleepBetweenIterations` = 10 on both (`config.DefaultSleepBetweenIterations`).
- Live mode writes jail.json and the ban file only when their content changed.
- Config mode vs flag mode are mutually exclusive per command. With `--config`, only
  output flags are allowed alongside it (static: `--tui/--compact/--plain`; live: `--logLevel`).
- `flokbn generate static-demo` writes a self-contained demo (1M-line synthetic
  access.log + calibrated TOML + white/blacklist files) with absolute paths rewritten
  into the config. Use it to reproduce behavior locally.
- When editing CIDR/jail/whitelist logic, the invariant and differential-fuzz tests
  are the safety net - run `cd flokbn/src && go test ./cidr ./jail` after changes.
