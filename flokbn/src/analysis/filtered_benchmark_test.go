package analysis

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ChristianF88/flokbn/config"
)

// benchFilteredConfig builds a static config whose tries all filter requests:
// one only through the global User-Agent lists, one with a User-Agent regex,
// one with an endpoint regex and a time window. With 100k log lines every trie
// takes the concurrent filter.
func benchFilteredConfig(b *testing.B) *config.Config {
	b.Helper()
	dir := b.TempDir()
	logFile := generateBenchmarkLogFileImpl(dir)

	write := func(name, content string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			b.Fatal(err)
		}
		return path
	}

	clusterSets := []config.ClusterArgSet{
		{MinClusterSize: 1000, MinDepth: 24, MaxDepth: 32, MeanSubnetDifference: 0.1},
		{MinClusterSize: 2000, MinDepth: 16, MaxDepth: 24, MeanSubnetDifference: 0.2},
	}
	tries := map[string]*config.TrieConfig{
		"ua_lists_only": {TrieCommon: config.TrieCommon{ClusterArgSets: clusterSets}},
		"bots":          {TrieCommon: config.TrieCommon{UserAgentRegex: "Googlebot|python-requests", ClusterArgSets: clusterSets}},
		"api":           {TrieCommon: config.TrieCommon{EndpointRegex: "^/api/", ClusterArgSets: clusterSets}},
	}
	for name, tc := range tries {
		if err := compileRegex(&tc.TrieCommon); err != nil {
			b.Fatalf("CompileRegex(%q): %v", name, err)
		}
	}

	return &config.Config{
		Global: &config.GlobalConfig{
			// 20% of the requests carry the whitelisted User-Agent, 15% the
			// blacklisted one.
			UserAgentWhitelist: write("ua_whitelist.txt", "curl/7.68.0\n"),
			UserAgentBlacklist: write("ua_blacklist.txt", "python-requests/2.28\n"),
		},
		Static:      &config.StaticConfig{LogFile: logFile, LogFormat: integrationLogFormat},
		StaticTries: tries,
	}
}

// BenchmarkStaticFiltered measures the full-parse pipeline with request
// filters on every trie, through both entrypoints.
func BenchmarkStaticFiltered(b *testing.B) {
	b.Run("Static", func(b *testing.B) {
		cfg := benchFilteredConfig(b)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := Static(cfg); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("StaticWithRequests", func(b *testing.B) {
		cfg := benchFilteredConfig(b)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, _, err := StaticWithRequests(cfg); err != nil {
				b.Fatal(err)
			}
		}
	})
}
