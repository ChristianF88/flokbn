package analysis

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ChristianF88/cidrx/config"
)

// ============================================================================
// Static Pipeline E2E Tests
// ============================================================================

// TestStaticPipeline_ClusterDetection verifies that clusters are correctly
// detected from a known IP distribution. We generate a log where all IPs
// fall in 10.20.0.0/16, which should form a detectable cluster.
func TestStaticPipeline_ClusterDetection(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "cluster.log")

	// Generate 5000 IPs in 10.20.0.0/16 — enough to form a cluster
	var b strings.Builder
	for i := 0; i < 5000; i++ {
		v := i + 1
		ip := fmt.Sprintf("10.20.%d.%d", v/256, v%256)
		fmt.Fprintf(&b, "%s - - [01/Feb/2025:00:00:00 +0000] \"GET / HTTP/1.1\" 200 100 \"-\" \"test\"\n", ip)
	}
	if err := os.WriteFile(logFile, []byte(b.String()), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		Global: &config.GlobalConfig{},
		Static: &config.StaticConfig{
			LogFile:   logFile,
			LogFormat: "%h %^ %^ [%t] \"%r\" %s %b \"%^\" \"%u\"",
		},
		StaticTries: map[string]*config.TrieConfig{
			"detect": {
				ClusterArgSets: []config.ClusterArgSet{
					{MinClusterSize: 1000, MinDepth: 16, MaxDepth: 24, MeanSubnetDifference: 0.2},
				},
			},
		},
	}

	result, err := Static(cfg)
	if err != nil {
		t.Fatalf("StaticFromConfig failed: %v", err)
	}

	if len(result.Tries) != 1 {
		t.Fatalf("Expected 1 trie, got %d", len(result.Tries))
	}

	tr := result.Tries[0]
	if len(tr.Data) != 1 {
		t.Fatalf("Expected 1 cluster result set, got %d", len(tr.Data))
	}

	if len(tr.Data[0].DetectedRanges) == 0 {
		t.Error("Expected at least one detected cluster in 10.20.0.0/16 range")
	}

	// Verify the detected cluster is within the expected range
	foundCluster := false
	for _, dr := range tr.Data[0].DetectedRanges {
		if strings.HasPrefix(dr.CIDR, "10.20.") {
			foundCluster = true
			if dr.Requests < 1000 {
				t.Errorf("Expected cluster to have >= 1000 requests, got %d", dr.Requests)
			}
		}
	}
	if !foundCluster {
		t.Error("Expected a detected cluster in the 10.20.x.x range")
	}
}

// TestStaticPipeline_CIDRRangeAnalysis verifies CIDR range request counting.
func TestStaticPipeline_CIDRRangeAnalysis(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "cidr.log")

	var b strings.Builder
	// 1000 IPs in 10.0.0.0/8 (use sequential IPs starting at 10.0.0.1)
	for i := 0; i < 1000; i++ {
		v := i + 1 // skip .0 by starting at 1
		fmt.Fprintf(&b, "10.%d.%d.%d - - [01/Feb/2025:00:00:00 +0000] \"GET / HTTP/1.1\" 200 100 \"-\" \"test\"\n",
			(v>>16)&0xFF, (v>>8)&0xFF, v&0xFF)
	}
	// 500 IPs in 192.168.0.0/16 (use sequential IPs starting at 192.168.0.1)
	for i := 0; i < 500; i++ {
		v := i + 1
		fmt.Fprintf(&b, "192.168.%d.%d - - [01/Feb/2025:00:00:00 +0000] \"GET / HTTP/1.1\" 200 100 \"-\" \"test\"\n",
			(v>>8)&0xFF, v&0xFF)
	}
	if err := os.WriteFile(logFile, []byte(b.String()), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		Global: &config.GlobalConfig{},
		Static: &config.StaticConfig{
			LogFile:   logFile,
			LogFormat: "%h %^ %^ [%t] \"%r\" %s %b \"%^\" \"%u\"",
		},
		StaticTries: map[string]*config.TrieConfig{
			"ranges": {
				CIDRRanges: []string{"10.0.0.0/8", "192.168.0.0/16"},
				ClusterArgSets: []config.ClusterArgSet{
					{MinClusterSize: 100, MinDepth: 24, MaxDepth: 32, MeanSubnetDifference: 0.2},
				},
			},
		},
	}

	result, err := Static(cfg)
	if err != nil {
		t.Fatalf("StaticFromConfig failed: %v", err)
	}

	tr := result.Tries[0]
	if len(tr.Stats.CIDRAnalysis) != 2 {
		t.Fatalf("Expected 2 CIDR range results, got %d", len(tr.Stats.CIDRAnalysis))
	}

	for _, ca := range tr.Stats.CIDRAnalysis {
		switch ca.CIDR {
		case "10.0.0.0/8":
			if ca.Requests != 1000 {
				t.Errorf("10.0.0.0/8: expected 1000 requests, got %d", ca.Requests)
			}
		case "192.168.0.0/16":
			if ca.Requests != 500 {
				t.Errorf("192.168.0.0/16: expected 500 requests, got %d", ca.Requests)
			}
		default:
			t.Errorf("Unexpected CIDR range: %s", ca.CIDR)
		}
	}
}

// TestStaticPipeline_DeterministicResults runs analysis twice on the same
// input and verifies identical outputs.
func TestStaticPipeline_DeterministicResults(t *testing.T) {
	logFile := generateIntegrationLogFile(t)

	buildCfg := func() *config.Config {
		return &config.Config{
			Global: &config.GlobalConfig{},
			Static: &config.StaticConfig{
				LogFile:   logFile,
				LogFormat: integrationLogFormat,
			},
			StaticTries: map[string]*config.TrieConfig{
				"trie_1": {
					ClusterArgSets: []config.ClusterArgSet{
						{MinClusterSize: 1000, MinDepth: 24, MaxDepth: 32, MeanSubnetDifference: 0.1},
						{MinClusterSize: 2000, MinDepth: 16, MaxDepth: 24, MeanSubnetDifference: 0.2},
					},
					CIDRRanges: []string{"14.160.0.0/12", "77.88.0.0/16"},
				},
			},
		}
	}

	result1, _, err := StaticWithRequests(buildCfg())
	if err != nil {
		t.Fatalf("First run failed: %v", err)
	}
	result2, _, err := StaticWithRequests(buildCfg())
	if err != nil {
		t.Fatalf("Second run failed: %v", err)
	}

	// Compare all non-timing fields
	compareJSONOutputs(t, result1, result2)
}

// TestStaticPipeline_MalformedLines verifies graceful handling of mixed
// valid and malformed log lines.
func TestStaticPipeline_MalformedLines(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "malformed.log")

	var b strings.Builder
	// 100 valid lines
	for i := 0; i < 100; i++ {
		fmt.Fprintf(&b, "10.0.0.%d - - [01/Feb/2025:00:00:00 +0000] \"GET / HTTP/1.1\" 200 100 \"-\" \"test\"\n", i+1)
	}
	// Intersperse malformed lines
	b.WriteString("this is not a log line\n")
	b.WriteString("\n")
	b.WriteString("     \n")
	b.WriteString("incomplete [01/Feb/2025:00:00:00 +0000]\n")
	b.WriteString("--- --- --- --- --- --- ---\n")

	if err := os.WriteFile(logFile, []byte(b.String()), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		Global: &config.GlobalConfig{},
		Static: &config.StaticConfig{
			LogFile:   logFile,
			LogFormat: "%h %^ %^ [%t] \"%r\" %s %b \"%^\" \"%u\"",
		},
		StaticTries: map[string]*config.TrieConfig{
			"test": {
				ClusterArgSets: []config.ClusterArgSet{
					{MinClusterSize: 10, MinDepth: 24, MaxDepth: 32, MeanSubnetDifference: 0.2},
				},
			},
		},
	}

	result, err := Static(cfg)
	if err != nil {
		t.Fatalf("StaticFromConfig failed: %v", err)
	}

	// Should have parsed at least the 100 valid lines
	if result.General.TotalRequests < 100 {
		t.Errorf("Expected at least 100 parsed requests, got %d", result.General.TotalRequests)
	}
}

// TestStaticPipeline_NilConfig verifies nil config returns error without panic.
func TestStaticPipeline_NilConfig(t *testing.T) {
	result, err := Static(nil)
	if err == nil {
		t.Error("Expected error for nil config")
	}
	if result == nil {
		t.Error("Expected non-nil result even for nil config")
	}
}

// TestStaticPipeline_NilStaticSection verifies missing static section returns error.
func TestStaticPipeline_NilStaticSection(t *testing.T) {
	cfg := &config.Config{
		Global: &config.GlobalConfig{},
	}
	result, err := Static(cfg)
	if err == nil {
		t.Error("Expected error for nil static section")
	}
	if result == nil {
		t.Error("Expected non-nil result even for nil static section")
	}
}

// TestStaticPipeline_UniqueIPsCountsDistinct verifies that Stats.UniqueIPs
// reports the number of DISTINCT IPs, not the number of insertions. Regression
// test for UniqueIPs being set from trie CountAll(), which counts duplicate
// IPs and therefore equalled requests-after-filtering.
func TestStaticPipeline_UniqueIPsCountsDistinct(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "dups.log")

	// 300 requests from only 3 distinct IPs.
	ips := []string{"10.1.1.1", "10.1.1.2", "10.1.1.3"}
	var b strings.Builder
	for i := 0; i < 300; i++ {
		fmt.Fprintf(&b, "%s - - [01/Feb/2025:00:00:00 +0000] \"GET / HTTP/1.1\" 200 100 \"-\" \"test\"\n", ips[i%3])
	}
	if err := os.WriteFile(logFile, []byte(b.String()), 0644); err != nil {
		t.Fatal(err)
	}

	logFormat := "%h %^ %^ [%t] \"%r\" %s %b \"%^\" \"%u\""

	cases := []struct {
		name string
		trie *config.TrieConfig
	}{
		// Unfiltered: exercises the IP-only fast path (processTrieFromSortedIPs).
		{"unfiltered fast path", &config.TrieConfig{}},
		// Filtered: a User-Agent regex forces the full path (processTrie).
		{"filtered full path", &config.TrieConfig{UserAgentRegex: "test"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.trie.CompileRegex(); err != nil {
				t.Fatal(err)
			}
			cfg := &config.Config{
				Global: &config.GlobalConfig{},
				Static: &config.StaticConfig{
					LogFile:   logFile,
					LogFormat: logFormat,
				},
				StaticTries: map[string]*config.TrieConfig{"t": tc.trie},
			}

			result, err := Static(cfg)
			if err != nil {
				t.Fatalf("static analysis failed: %v", err)
			}
			if len(result.Tries) != 1 {
				t.Fatalf("expected 1 trie, got %d", len(result.Tries))
			}
			stats := result.Tries[0].Stats
			if stats.TotalRequestsAfterFiltering != 300 {
				t.Errorf("TotalRequestsAfterFiltering = %d, want 300", stats.TotalRequestsAfterFiltering)
			}
			if stats.UniqueIPs != 3 {
				t.Errorf("UniqueIPs = %d, want 3 (must count distinct IPs, not insertions)", stats.UniqueIPs)
			}
			if result.General.UniqueIPs != 3 {
				t.Errorf("General.UniqueIPs = %d, want 3", result.General.UniqueIPs)
			}
		})
	}
}
