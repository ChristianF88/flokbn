---
title: "Developer Guide"
description: "Developer guide for contributing to cidrx"
summary: "Performance requirements, testing, and development workflow for cidrx contributors"
date: 2025-10-09T10:00:00+00:00
lastmod: 2025-11-26T10:00:00+00:00
draft: false
weight: 500
toc: true
seo:
  title: "Contributing to cidrx"
  description: "Developer guide for contributing to the cidrx IP clustering tool"
  canonical: ""
  noindex: false
---

cidrx is open source and welcomes contributions. This guide covers cidrx-specific development requirements.

## Quick Start

### 1. Prerequisites

- **Go 1.21+** (check: `go version`)
- **staticcheck** (install: `go install honnef.co/go/tools/cmd/staticcheck@latest`)

### 2. Clone and Build

```bash
git clone https://github.com/YOUR_USERNAME/cidrx.git
cd cidrx/cidrx/src
go mod download
go build -o cidrx .
```

### 3. Verify Setup

```bash
go test ./...
staticcheck ./...
./cidrx --version
```

## Performance Requirements

**cidrx is performance-critical.** All changes must maintain or improve these benchmarks:

- **Parse Rate**: >=1.3M requests/sec
- **End-to-end Processing**: >=1M requests/sec
- **Cluster Detection**: <5ms for typical workloads
- **Memory**: No unbounded growth

See [Performance]({{< relref "/docs/architecture/performance/" >}}) for benchmarks and profiling.

## Development Workflow

### Making Changes

```bash
cd cidrx/src

# 1. Make your changes

# 2. Run tests
go test ./...

# 3. Run benchmarks (REQUIRED for performance-sensitive code)
go test -bench=. -benchmem ./...

# 4. Run static analysis
staticcheck ./...

# 5. Format code
go fmt ./...
```

### Running Benchmarks

**Critical**: Always benchmark before and after performance-related changes.

```bash
# Before making changes
go test -bench=. -benchmem ./... > bench-before.txt

# Make your changes

# After changes
go test -bench=. -benchmem ./... > bench-after.txt

# Compare results
diff bench-before.txt bench-after.txt
```

### Real-World Performance Test

```bash
cd cidrx/src
time go run . static --logfile /var/log/nginx/access.log \
  --clusterArgSets 1000,24,32,0.1 \
  --clusterArgSets 10000,16,24,0.2 \
  --plain
```

**Expected performance** (1M+ requests):
- Parse Time: ~750ms
- Parse Rate: 1.3M+ requests/sec
- Total Duration: ~1s

## Testing

```bash
go test ./...               # Run all tests
go test -cover ./...        # With coverage
go test ./logparser -v      # Specific package
go test -race ./...         # Race detector
```

### Makefile (Repo Root)

The repo-root `Makefile` is the canonical local gate:

```bash
make test          # gofmt check + vet + staticcheck + go test + non-Docker e2e suites
make test-race     # go test -race ./...
make test-docker   # Docker live e2e suites
make test-all      # Full sweep: test + test-race + test-docker
make bench         # Package benchmarks
make fmt           # gofmt -w .
```

The git pre-commit hook runs the commit-time Go-only subset (gofmt, vet, staticcheck, go test); `make test` is the fuller sweep including e2e.

### E2E Tests

End-to-end tests live in `e2e/` and exercise the full binary against generated or live traffic.

```bash
cd e2e
make all              # Static E2E tests (no Docker required)
make live             # Live mode E2E test (requires Docker)
make live-detection   # Live mode multi-trie detection test (requires Docker)
make everything       # All of the above
```

Individual targets: `static`, `filters`, `whitelist-blacklist`, `live`, `live-detection`.

## Code Quality

Run before every commit:

```bash
go fmt ./... && go vet ./... && staticcheck ./... && go test ./...
```

## Writing Tests

### Conventions

- Place tests in `*_test.go` files
- Use table-driven tests
- Test edge cases and error conditions
- Include benchmarks for performance-critical code

### Example Test

```go
func TestParseIPAddress(t *testing.T) {
    tests := []struct {
        name     string
        input    string
        expected string
        wantErr  bool
    }{
        {"valid IPv4", "192.168.1.1", "192.168.1.1", false},
        {"invalid IP", "not-an-ip", "", true},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result, err := ParseIPAddress(tt.input)
            if (err != nil) != tt.wantErr {
                t.Errorf("expected error=%v, got error=%v", tt.wantErr, err)
            }
            if result != tt.expected {
                t.Errorf("expected %s, got %s", tt.expected, result)
            }
        })
    }
}
```

### Example Benchmark

```go
func BenchmarkParseIPAddress(b *testing.B) {
    input := "192.168.1.1"
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        ParseIPAddress(input)
    }
}
```

## Pull Request Checklist

- [ ] Tests pass: `go test ./...`
- [ ] Benchmarks run (for performance changes)
- [ ] No performance regression
- [ ] Static analysis passes: `staticcheck ./...`
- [ ] Code formatted: `go fmt ./...`
- [ ] Real-world test passes (if applicable)
- [ ] Documentation updated (if needed)

## Repository Structure

```
cidrx/
├── cidrx/src/          # Main Go application
│   ├── analysis/       # Analysis orchestration
│   ├── cidr/           # CIDR parsing utilities
│   ├── cli/            # CLI commands and API
│   ├── config/         # Configuration structs and loading
│   ├── ingestor/       # Static/live mode ingestion
│   ├── iputils/        # IP address utilities
│   ├── jail/           # Ban/jail management
│   ├── logparser/      # Log parsing
│   ├── output/         # Output formatting (JSON, plain, etc.)
│   ├── pools/          # Memory pool management
│   ├── sliding/        # Sliding window for live mode
│   ├── trie/           # IP trie clustering
│   ├── tui/            # Terminal user interface
│   ├── version/        # Version info
│   └── main.go
├── e2e/                # End-to-end test scripts
├── docs/               # Hugo documentation
├── .github/workflows/  # CI/CD
├── .goreleaser.yaml    # Release configuration
└── README.md
```

See [Internals]({{< relref "/docs/architecture/internals/" >}}) for how these packages interact.

## Profiling

### CPU Profiling

```bash
go test -cpuprofile=cpu.prof -bench=. ./logparser
go tool pprof cpu.prof
```

### Memory Profiling

```bash
go test -memprofile=mem.prof -bench=. ./logparser
go tool pprof mem.prof
```

## Debugging

### Race Detector

```bash
go build -race -o cidrx .
./cidrx static --logfile test.log --clusterArgSets 1000,24,32,0.1
```

### Delve Debugger

```bash
go install github.com/go-delve/delve/cmd/dlv@latest
dlv test ./logparser -- -test.run TestParseLogLine
```

## Cleanup

```bash
cd cidrx/src
rm -f cidrx
rm -f *.prof *.out
go clean -cache
```

## Contributing Guidelines

1. **One feature per PR** - Keep changes focused
2. **Maintain performance** - Benchmark everything
3. **Add tests** - All new code needs tests
4. **Document changes** - Update docs when needed
5. **Follow Go conventions** - Use `go fmt` and `staticcheck`

## Common Issues

**Import errors**: `go mod tidy && go mod download`

**Stale test cache**: `go test -count=1 ./...`

**staticcheck not found**: `go install honnef.co/go/tools/cmd/staticcheck@latest` and ensure `$(go env GOPATH)/bin` is in PATH.

## Resources

- [GitHub Repository](https://github.com/ChristianF88/cidrx)
- [Issue Tracker](https://github.com/ChristianF88/cidrx/issues)
- [Discussions](https://github.com/ChristianF88/cidrx/discussions)
