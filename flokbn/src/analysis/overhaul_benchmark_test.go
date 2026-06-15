package analysis

import (
	"testing"

	"github.com/ChristianF88/flokbn/config"
)

// benchOverhaulConfig builds an unfiltered static config (the common --plain case)
// pointing at a freshly generated clustered log file.
func benchOverhaulConfig(b *testing.B) *config.Config {
	b.Helper()
	logFile := generateBenchmarkLogFileImpl(b.TempDir())
	return &config.Config{
		Global: &config.GlobalConfig{},
		Static: &config.StaticConfig{
			LogFile:   logFile,
			LogFormat: integrationLogFormat,
		},
		StaticTries: map[string]*config.TrieConfig{
			"bench_trie": {
				CIDRRanges: []string{"14.160.0.0/12", "77.88.0.0/16"},
				ClusterArgSets: []config.ClusterArgSet{
					{MinClusterSize: 1000, MinDepth: 24, MaxDepth: 32, MeanSubnetDifference: 0.1},
					{MinClusterSize: 2000, MinDepth: 16, MaxDepth: 24, MeanSubnetDifference: 0.2},
				},
			},
		},
	}
}

// BenchmarkStaticOverhaul compares the full []Request pipeline against the new
// IP-only ([]uint32 + seq-trie) fast path used by `static --plain`.
func BenchmarkStaticOverhaul(b *testing.B) {
	b.Run("Full_WithRequests", func(b *testing.B) {
		cfg := benchOverhaulConfig(b)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, _, err := StaticWithRequests(cfg); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("Fast_NoRequests", func(b *testing.B) {
		cfg := benchOverhaulConfig(b)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := Static(cfg); err != nil {
				b.Fatal(err)
			}
		}
	})
}
