package main

import (
	"os"
	"testing"

	"github.com/ChristianF88/flokbn/analysis"
	"github.com/ChristianF88/flokbn/config"
)

// BenchmarkRealWorldStaticFromConfig mirrors the real-world command used to
// guard against performance regressions:
//
//	go run main.go static --config $FLOKBN_BENCH_CONFIG
//
// It drives the exact same entrypoint the CLI uses
// (analysis.Static, see cli/api.go), so parse +
// IP-extract + sort + trie-build + clustering are all measured end to end
// against a real log file referenced by the config.
//
// No filepath is hardcoded: the benchmark is skipped unless FLOKBN_BENCH_CONFIG
// points to a flokbn TOML config. Run it with:
//
//	FLOKBN_BENCH_CONFIG=/path/to/your/flokbn.toml \
//	    go test -run '^$' -bench BenchmarkRealWorldStaticFromConfig -benchmem .
//
// Capture a baseline before any change and compare after (e.g. with benchstat)
// to prove no regression.
func BenchmarkRealWorldStaticFromConfig(b *testing.B) {
	cfgPath := os.Getenv("FLOKBN_BENCH_CONFIG")
	if cfgPath == "" {
		b.Skip("set FLOKBN_BENCH_CONFIG to a flokbn TOML config to run the real-world benchmark")
	}

	cfg, err := config.LoadConfig(cfgPath)
	if err != nil {
		b.Fatalf("load config %q: %v", cfgPath, err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := analysis.Static(cfg); err != nil {
			b.Fatalf("static analysis: %v", err)
		}
	}
}
