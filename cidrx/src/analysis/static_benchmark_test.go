package analysis

import (
	"testing"

	"github.com/ChristianF88/cidrx/config"
)

func BenchmarkStaticPipeline(b *testing.B) {
	// Generate deterministic log file once (outside timing)
	t := &testing.T{}
	tmpDir := b.TempDir()

	// Use a smaller inline generator to avoid t.Helper dependency
	logFile := func() string {
		return generateBenchmarkLogFile(b, tmpDir)
	}()

	cfg := &config.Config{
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
	_ = t

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ParallelStaticFromConfigNoRequests(cfg)
		if err != nil {
			b.Fatalf("StaticFromConfig failed: %v", err)
		}
	}
}

func BenchmarkStaticPipeline_ParseOnly(b *testing.B) {
	tmpDir := b.TempDir()
	logFile := generateBenchmarkLogFile(b, tmpDir)

	cfg := &config.Config{
		Global: &config.GlobalConfig{},
		Static: &config.StaticConfig{
			LogFile:   logFile,
			LogFormat: integrationLogFormat,
		},
		StaticTries: map[string]*config.TrieConfig{},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ParallelStaticFromConfigNoRequests(cfg)
		if err != nil {
			b.Fatalf("StaticFromConfig failed: %v", err)
		}
	}
}

// generateBenchmarkLogFile creates a log file using the same distribution
// as the integration test but callable from benchmarks.
func generateBenchmarkLogFile(b *testing.B, tmpDir string) string {
	b.Helper()
	return generateBenchmarkLogFileImpl(tmpDir)
}
