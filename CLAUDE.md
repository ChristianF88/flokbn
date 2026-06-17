# CLAUDE.md

Guidance for working in this repository.

## What flokbn is

A Go CLI that clusters the IPs in HTTP access logs into CIDR ranges using a binary
trie, for botnet detection, abuse analysis, and ban-list generation. A 2M-line log
clusters in ~1s on a workstation. Two modes:

- **`flokbn static`** — batch-analyze a log file. Output: JSON / compact JSON / plain text / interactive TUI.
- **`flokbn live`** — continuous monitoring. Ingests over the Lumberjack protocol (Filebeat-compatible), keeps a sliding window, escalates detected ranges through a persistent **jail**, and serves HTTP `/stats`, `/bans`, Prometheus `/metrics`.

**IPv4 only.** IPv6 is deliberately unsupported and rejected loudly at config load.

## Repo layout

```
flokbn/src/          # THE GO MODULE lives here, not at repo root
  main.go            # entry: cli.App.Run(os.Args)
  cli/               # command defs (urfave/cli v2), api.go orchestration, stats server, generate, synthlog
  config/            # TOML + flag parsing; regexprefilter/ subpkg
  logparser/         # fast multi-worker log parser, format-string compiler
  ingestor/          # Request type; TCPIngestor (go-lumber server)
  trie/              # binary trie, CollectCIDRsNumeric clustering walk
  cidr/              # CIDR merge/subtract, RemoveWhitelisted, UserAgentMatcher
  analysis/          # Static() / StaticWithRequests() — wires parse→trie→cluster→filter
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

Go 1.23. Test deps: testify, go-cmp. ~72 `_test.go` files including differential
fuzz (`cidr/removewhitelisted_diff_test.go`) and invariant tests
(`jail/whitelist_invariant_test.go`). Real-world benchmarks are env-gated (run manually).

CI (`.github/workflows/ci.yml`): prepare (go mod tidy must be clean) → lint → test
(race + coverage → Codecov) → cross-platform build matrix. Release on `v*` tag via
GoReleaser. No golangci-lint config; lint = gofmt + vet + staticcheck only.

## Core concepts

- **Cluster arg set** = `minSize,minDepth,maxDepth,threshold`. minSize = min request
  count; depth = CIDR prefix-length search range; threshold = max imbalance between a
  subtree's halves (0.1 = emit a subtree when traffic spreads across it with ≤10%
  imbalance). Multiple sets run in one pass as detection tiers (tight = hot hosts,
  loose = whole subnets). Static flag: `--clusterArgSets`; live flag: `--clusterArgSet`.
- **Trie clustering** (`trie.CollectCIDRsNumeric`): DFS walk emitting a node's prefix
  as a `NumericCIDR{IP uint32, PrefixLen uint8}` when balance/size/depth gates pass;
  early-exits to avoid overlapping ranges.
- **Jail** (`jail/`): persistent escalating ban state for live mode. 5 cells with
  durations 10m → 4h → 7d → 30d → 180d. A CIDR escalates to the next cell on
  re-detection after expiry. Parent ranges consolidate contained sub-ranges (prevents
  fragment explosion). Persisted as JSON; bounds cached as uint32 to avoid re-parsing.
- **Whitelist semantics:** a blacklist CIDR is dropped only if **fully covered by a
  single whitelist entry** — the union of multiple entries does NOT count (deliberate;
  see jail invariant tests). `RemoveWhitelisted` parses the whitelist once
  (O(B+W), not O(B*W)) and is byte-identical to the old path for IPv4 (proven by
  differential fuzz). Whitelist is applied at **publish time** (`ComposeBanLists`),
  not when entering the jail.
- **IPv4-only gate:** discriminator is `len(ipNet.Mask) != 4` (4 bytes = IPv4,
  16 = IPv6 incl. IPv4-mapped `::ffff:`). Rejected at config load; skipped/kept-verbatim
  in hot paths as defense-in-depth.

## Conventions / gotchas

- Hot paths avoid allocations: `NumericCIDR` over strings, custom `.String()` without
  `fmt.Sprintf`, memory pools for trie nodes, IP-only fast path skips URI/UA parsing
  when no regex filter is set.
- Log format strings: exactly one `%h`, no duplicate specifiers (except `%^`).
  Static default format puts `%h` last (`... "%u" "%h"`).
- Config mode vs flag mode are mutually exclusive per command. With `--config`, only
  output flags are allowed alongside it (static: `--tui/--compact/--plain`; live: `--logLevel`).
- `flokbn generate static-demo` writes a self-contained demo (1M-line synthetic
  access.log + calibrated TOML + white/blacklist files) with absolute paths rewritten
  into the config. Use it to reproduce behavior locally.
- When editing CIDR/jail/whitelist logic, the invariant and differential-fuzz tests
  are the safety net — run `cd flokbn/src && go test ./cidr ./jail` after changes.
