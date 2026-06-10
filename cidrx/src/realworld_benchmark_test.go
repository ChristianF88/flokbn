package main

import (
	"os"
	"testing"

	"github.com/ChristianF88/cidrx/analysis"
	"github.com/ChristianF88/cidrx/config"
)

// BenchmarkRealWorldStaticFromConfig mirrors the real-world command used to
// guard against performance regressions:
//
//	go run main.go static --config $CIDRX_BENCH_CONFIG
//
// It drives the exact same entrypoint the CLI uses
// (analysis.ParallelStaticFromConfigNoRequests, see cli/api.go), so parse +
// IP-extract + sort + trie-build + clustering are all measured end to end
// against a real log file referenced by the config.
//
// No filepath is hardcoded: the benchmark is skipped unless CIDRX_BENCH_CONFIG
// points to a cidrx TOML config. Run it with:
//
//	CIDRX_BENCH_CONFIG=/path/to/your/cidrx.toml \
//	    go test -run '^$' -bench BenchmarkRealWorldStaticFromConfig -benchmem .
//
// Capture a baseline before any change and compare after (e.g. with benchstat)
// to prove no regression.
func BenchmarkRealWorldStaticFromConfig(b *testing.B) {
	cfgPath := os.Getenv("CIDRX_BENCH_CONFIG")
	if cfgPath == "" {
		b.Skip("set CIDRX_BENCH_CONFIG to a cidrx TOML config to run the real-world benchmark")
	}

	cfg, err := config.LoadConfig(cfgPath)
	if err != nil {
		b.Fatalf("load config %q: %v", cfgPath, err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := analysis.ParallelStaticFromConfigNoRequests(cfg); err != nil {
			b.Fatalf("static analysis: %v", err)
		}
	}
}
