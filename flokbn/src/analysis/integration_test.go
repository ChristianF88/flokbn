package analysis

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ChristianF88/flokbn/config"
	"github.com/ChristianF88/flokbn/output"
)

// ============================================================================
// Integration Test: CLI-built Config vs TOML-loaded Config Equivalence
//
// Generates ~100k log entries with deterministic IP distributions that produce
// detectable clusters. Builds two equivalent configs (one from TOML, one
// programmatically as the CLI handler would) and verifies both produce
// identical analysis results.
// ============================================================================

const (
	integrationLogFormat = `%h %^ %^ [%t] "%r" %s %b "%^" "%u"`

	// IP distribution constants
	clusterACount   = 20000 // 10.20.0.0/16
	clusterBCount   = 15000 // 192.168.0.0/18
	clusterCCount   = 4000  // 172.16.0.0/20
	cidrTest1Count  = 4000  // 14.160.0.0/12
	cidrTest2Count  = 5000  // 77.88.0.0/16
	noiseCount      = 52000 // scattered across many /8s
	totalEntryCount = clusterACount + clusterBCount + clusterCCount + cidrTest1Count + cidrTest2Count + noiseCount
)

// userAgentInfo maps a user agent type to its string and endpoint.
type userAgentInfo struct {
	ua       string
	endpoint string
}

var userAgents = []userAgentInfo{
	{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", "/page/%d"},
	{"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", "/api/data"},
	{"curl/7.68.0", "/api/health"},
	{"python-requests/2.28", "/admin/login"},
}

// uaDistribution controls how user agents are assigned (out of 20 slots).
// 0-7 = Mozilla (40%), 8-12 = Googlebot (25%), 13-16 = curl (20%), 17-19 = python (15%)
func uaForIndex(i int) userAgentInfo {
	slot := i % 20
	switch {
	case slot < 8:
		return userAgents[0]
	case slot < 13:
		return userAgents[1]
	case slot < 17:
		return userAgents[2]
	default:
		return userAgents[3]
	}
}

var months = []string{"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"}

func timestampForIndex(i int) string {
	// Spread across Feb 1-7, 2025
	day := 1 + (i % 7)
	hour := (i / 7) % 24
	minute := (i / 168) % 60
	second := (i / 10080) % 60
	return fmt.Sprintf("[%02d/%s/2025:%02d:%02d:%02d +0000]", day, months[1], hour, minute, second)
}

// generateIntegrationLogFile creates a temp log file with ~100k entries
// having deterministic IP distributions for clustering tests.
func generateIntegrationLogFile(t *testing.T) string {
	t.Helper()
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "integration.log")

	var b strings.Builder
	b.Grow(totalEntryCount * 150) // estimate ~150 bytes per line

	entryIdx := 0

	writeEntry := func(ip string) {
		ua := uaForIndex(entryIdx)
		ts := timestampForIndex(entryIdx)
		endpoint := ua.endpoint
		if strings.Contains(endpoint, "%d") {
			endpoint = fmt.Sprintf(endpoint, entryIdx%100)
		}
		fmt.Fprintf(&b, "%s - - %s \"GET %s HTTP/1.1\" 200 1024 \"-\" \"%s\"\n",
			ip, ts, endpoint, ua.ua)
		entryIdx++
	}

	// Cluster A: 20k IPs in 10.20.0.0/16 (sequential fill)
	for i := 0; i < clusterACount; i++ {
		v := i + 1 // skip .0.0
		writeEntry(fmt.Sprintf("10.20.%d.%d", v/256, v%256))
	}

	// Cluster B: 15k IPs in 192.168.0.0/18 (192.168.0.0 - 192.168.63.255)
	for i := 0; i < clusterBCount; i++ {
		v := i + 1
		writeEntry(fmt.Sprintf("192.168.%d.%d", v/256, v%256))
	}

	// Cluster C: 4k IPs in 172.16.0.0/20 (172.16.0.0 - 172.16.15.255)
	for i := 0; i < clusterCCount; i++ {
		v := i + 1
		writeEntry(fmt.Sprintf("172.16.%d.%d", v/256, v%256))
	}

	// CIDR range test 1: 4k IPs in 14.160.0.0/12 (14.160.0.0 - 14.175.255.255)
	for i := 0; i < cidrTest1Count; i++ {
		v := i + 1
		writeEntry(fmt.Sprintf("14.160.%d.%d", v/256, v%256))
	}

	// CIDR range test 2: 5k IPs in 77.88.0.0/16
	for i := 0; i < cidrTest2Count; i++ {
		v := i + 1
		writeEntry(fmt.Sprintf("77.88.%d.%d", v/256, v%256))
	}

	// Noise: 52k IPs scattered across many /8 ranges (no clustering)
	// Each of 52 first octets (40-91) gets 1000 IPs, spread across 250 /24s with 4 IPs each.
	for i := 0; i < noiseCount; i++ {
		o1 := 40 + (i / 1000)     // 40..91
		o2 := (i % 1000) / 4      // 0..249
		o3 := (i % 4)             // 0..3
		o4 := 1 + ((i * 7) % 254) // 1..254, varied
		writeEntry(fmt.Sprintf("%d.%d.%d.%d", o1, o2, o3, o4))
	}

	if err := os.WriteFile(logFile, []byte(b.String()), 0644); err != nil {
		t.Fatalf("Failed to write integration log file: %v", err)
	}

	return logFile
}

// buildTOMLConfig writes a TOML config file matching the integration test
// parameters, loads it via LoadConfig, and returns the resulting Config.
func buildTOMLConfig(t *testing.T, logFile string) *config.Config {
	t.Helper()
	tmpDir := t.TempDir()

	tomlContent := fmt.Sprintf(`
[global]

[static]
logFile = %q
logFormat = '%s'

[static.trie_1]
cidrRanges = ["14.160.0.0/12", "77.88.0.0/16"]
clusterArgSets = [[1000, 24, 32, 0.1], [2000, 16, 24, 0.2]]
useForJail = [true, true]

[static.trie_2]
useragentRegex = ".*Googlebot.*"
clusterArgSets = [[500, 24, 32, 0.2]]
useForJail = [true]

[static.trie_3]
endpointRegex = "/api/.*"
clusterArgSets = [[1000, 16, 24, 0.2]]
useForJail = [true]

[static.trie_4]
startTime = "2025-02-03T00:00:00Z"
endTime = "2025-02-05T23:59:59Z"
clusterArgSets = [[1000, 16, 24, 0.2]]
useForJail = [true]
`, logFile, integrationLogFormat)

	configPath := filepath.Join(tmpDir, "integration.toml")
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("Failed to write TOML config: %v", err)
	}

	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	return cfg
}

// buildCLIConfig constructs a Config programmatically, exactly as
// handleStaticFlagsMode would from CLI flags.
func buildCLIConfig(t *testing.T, logFile string) *config.Config {
	t.Helper()

	startTime := time.Date(2025, 2, 3, 0, 0, 0, 0, time.UTC)
	endTime := time.Date(2025, 2, 5, 23, 59, 59, 0, time.UTC)

	cfg := &config.Config{
		Global: &config.GlobalConfig{},
		Static: &config.StaticConfig{
			LogFile:   logFile,
			LogFormat: integrationLogFormat,
		},
		StaticTries: map[string]*config.TrieConfig{
			"trie_1": {
				CIDRRanges: []string{"14.160.0.0/12", "77.88.0.0/16"},
				ClusterArgSets: []config.ClusterArgSet{
					{MinClusterSize: 1000, MinDepth: 24, MaxDepth: 32, MeanSubnetDifference: 0.1},
					{MinClusterSize: 2000, MinDepth: 16, MaxDepth: 24, MeanSubnetDifference: 0.2},
				},
				UseForJail: []bool{true, true},
			},
			"trie_2": {
				UserAgentRegex: ".*Googlebot.*",
				ClusterArgSets: []config.ClusterArgSet{
					{MinClusterSize: 500, MinDepth: 24, MaxDepth: 32, MeanSubnetDifference: 0.2},
				},
				UseForJail: []bool{true},
			},
			"trie_3": {
				EndpointRegex: "/api/.*",
				ClusterArgSets: []config.ClusterArgSet{
					{MinClusterSize: 1000, MinDepth: 16, MaxDepth: 24, MeanSubnetDifference: 0.2},
				},
				UseForJail: []bool{true},
			},
			"trie_4": {
				StartTime: &startTime,
				EndTime:   &endTime,
				ClusterArgSets: []config.ClusterArgSet{
					{MinClusterSize: 1000, MinDepth: 16, MaxDepth: 24, MeanSubnetDifference: 0.2},
				},
				UseForJail: []bool{true},
			},
		},
	}

	// CLI path must explicitly compile regex (as handleStaticFlagsMode does)
	for name, tc := range cfg.StaticTries {
		if err := tc.CompileRegex(); err != nil {
			t.Fatalf("CompileRegex failed for trie %q: %v", name, err)
		}
	}

	return cfg
}

// ============================================================================
// Result comparison helpers
// ============================================================================

// compareJSONOutputs compares two JSONOutput structs, ignoring timing fields.
func compareJSONOutputs(t *testing.T, toml, cli *output.JSONOutput) {
	t.Helper()

	// General stats
	if toml.General.TotalRequests != cli.General.TotalRequests {
		t.Errorf("TotalRequests mismatch: toml=%d, cli=%d",
			toml.General.TotalRequests, cli.General.TotalRequests)
	}
	if toml.General.UniqueIPs != cli.General.UniqueIPs {
		t.Errorf("UniqueIPs mismatch: toml=%d, cli=%d",
			toml.General.UniqueIPs, cli.General.UniqueIPs)
	}

	// Number of tries
	if len(toml.Tries) != len(cli.Tries) {
		t.Fatalf("Tries count mismatch: toml=%d, cli=%d", len(toml.Tries), len(cli.Tries))
	}

	// Both should be sorted by name already (analysis sorts them)
	for i := range toml.Tries {
		compareTrieResults(t, toml.Tries[i], cli.Tries[i])
	}
}

func compareTrieResults(t *testing.T, toml, cli output.TrieResult) {
	t.Helper()
	prefix := fmt.Sprintf("Trie %q", toml.Name)

	if toml.Name != cli.Name {
		t.Errorf("%s: name mismatch: toml=%q, cli=%q", prefix, toml.Name, cli.Name)
		return
	}

	// Stats
	if toml.Stats.TotalRequestsAfterFiltering != cli.Stats.TotalRequestsAfterFiltering {
		t.Errorf("%s: TotalRequestsAfterFiltering mismatch: toml=%d, cli=%d",
			prefix, toml.Stats.TotalRequestsAfterFiltering, cli.Stats.TotalRequestsAfterFiltering)
	}
	if toml.Stats.UniqueIPs != cli.Stats.UniqueIPs {
		t.Errorf("%s: UniqueIPs mismatch: toml=%d, cli=%d",
			prefix, toml.Stats.UniqueIPs, cli.Stats.UniqueIPs)
	}

	// Parameters: regex
	comparePtrStr(t, prefix+".UserAgentRegex", toml.Parameters.UserAgentRegex, cli.Parameters.UserAgentRegex)
	comparePtrStr(t, prefix+".EndpointRegex", toml.Parameters.EndpointRegex, cli.Parameters.EndpointRegex)

	// Parameters: CIDR ranges
	compareStringSlices(t, prefix+".CIDRRanges", toml.Parameters.CIDRRanges, cli.Parameters.CIDRRanges)

	// Parameters: UseForJail
	compareBoolSlices(t, prefix+".UseForJail", toml.Parameters.UseForJail, cli.Parameters.UseForJail)

	// Parameters: time range
	compareTimeRanges(t, prefix, toml.Parameters.TimeRange, cli.Parameters.TimeRange)

	// CIDR analysis (range counts)
	compareCIDRAnalysis(t, prefix, toml.Stats.CIDRAnalysis, cli.Stats.CIDRAnalysis)

	// Cluster results
	if len(toml.Data) != len(cli.Data) {
		t.Errorf("%s: cluster result count mismatch: toml=%d, cli=%d",
			prefix, len(toml.Data), len(cli.Data))
		return
	}
	for j := range toml.Data {
		compareClusterResults(t, fmt.Sprintf("%s.Cluster[%d]", prefix, j), toml.Data[j], cli.Data[j])
	}
}

func compareClusterResults(t *testing.T, prefix string, toml, cli output.ClusterResult) {
	t.Helper()

	// Parameters must match exactly
	if toml.Parameters != cli.Parameters {
		t.Errorf("%s: parameters mismatch: toml=%+v, cli=%+v",
			prefix, toml.Parameters, cli.Parameters)
	}

	// Detected ranges (sort by CIDR for stable comparison)
	compareCIDRRangeSlices(t, prefix+".DetectedRanges", toml.DetectedRanges, cli.DetectedRanges)
	compareCIDRRangeSlices(t, prefix+".MergedRanges", toml.MergedRanges, cli.MergedRanges)
}

func compareCIDRRangeSlices(t *testing.T, prefix string, a, b []output.CIDRRange) {
	t.Helper()
	if len(a) != len(b) {
		t.Errorf("%s: length mismatch: %d vs %d", prefix, len(a), len(b))
		// Log details for debugging
		t.Logf("  toml: %v", cidrRangeNames(a))
		t.Logf("  cli:  %v", cidrRangeNames(b))
		return
	}

	// Sort both by CIDR string for stable comparison
	sortedA := make([]output.CIDRRange, len(a))
	sortedB := make([]output.CIDRRange, len(b))
	copy(sortedA, a)
	copy(sortedB, b)
	sort.Slice(sortedA, func(i, j int) bool { return sortedA[i].CIDR < sortedA[j].CIDR })
	sort.Slice(sortedB, func(i, j int) bool { return sortedB[i].CIDR < sortedB[j].CIDR })

	for i := range sortedA {
		if sortedA[i].CIDR != sortedB[i].CIDR {
			t.Errorf("%s[%d]: CIDR mismatch: %q vs %q", prefix, i, sortedA[i].CIDR, sortedB[i].CIDR)
		}
		if sortedA[i].Requests != sortedB[i].Requests {
			t.Errorf("%s[%d] %s: Requests mismatch: %d vs %d",
				prefix, i, sortedA[i].CIDR, sortedA[i].Requests, sortedB[i].Requests)
		}
	}
}

func cidrRangeNames(ranges []output.CIDRRange) []string {
	names := make([]string, len(ranges))
	for i, r := range ranges {
		names[i] = fmt.Sprintf("%s(%d)", r.CIDR, r.Requests)
	}
	return names
}

func comparePtrStr(t *testing.T, field string, a, b *string) {
	t.Helper()
	if (a == nil) != (b == nil) {
		t.Errorf("%s: nil mismatch: toml=%v, cli=%v", field, a, b)
		return
	}
	if a != nil && *a != *b {
		t.Errorf("%s: value mismatch: toml=%q, cli=%q", field, *a, *b)
	}
}

func compareStringSlices(t *testing.T, field string, a, b []string) {
	t.Helper()
	if len(a) != len(b) {
		t.Errorf("%s: length mismatch: %d vs %d", field, len(a), len(b))
		return
	}
	for i := range a {
		if a[i] != b[i] {
			t.Errorf("%s[%d]: mismatch: %q vs %q", field, i, a[i], b[i])
		}
	}
}

func compareBoolSlices(t *testing.T, field string, a, b []bool) {
	t.Helper()
	if len(a) != len(b) {
		t.Errorf("%s: length mismatch: %d vs %d", field, len(a), len(b))
		return
	}
	for i := range a {
		if a[i] != b[i] {
			t.Errorf("%s[%d]: mismatch: %v vs %v", field, i, a[i], b[i])
		}
	}
}

func compareTimeRanges(t *testing.T, prefix string, a, b *output.TimeRange) {
	t.Helper()
	if (a == nil) != (b == nil) {
		t.Errorf("%s.TimeRange: nil mismatch: toml=%v, cli=%v", prefix, a, b)
		return
	}
	if a != nil {
		if !a.Start.Equal(b.Start) {
			t.Errorf("%s.TimeRange.Start: mismatch: toml=%v, cli=%v", prefix, a.Start, b.Start)
		}
		if !a.End.Equal(b.End) {
			t.Errorf("%s.TimeRange.End: mismatch: toml=%v, cli=%v", prefix, a.End, b.End)
		}
	}
}

func compareCIDRAnalysis(t *testing.T, prefix string, a, b []output.CIDRRange) {
	t.Helper()
	if len(a) != len(b) {
		t.Errorf("%s.CIDRAnalysis: length mismatch: %d vs %d", prefix, len(a), len(b))
		return
	}
	for i := range a {
		if a[i].CIDR != b[i].CIDR {
			t.Errorf("%s.CIDRAnalysis[%d]: CIDR mismatch: %q vs %q", prefix, i, a[i].CIDR, b[i].CIDR)
		}
		if a[i].Requests != b[i].Requests {
			t.Errorf("%s.CIDRAnalysis[%d] %s: Requests mismatch: %d vs %d",
				prefix, i, a[i].CIDR, a[i].Requests, b[i].Requests)
		}
	}
}

// ============================================================================
// Main Integration Test
// ============================================================================

func TestCLIConfigEquivalence(t *testing.T) {
	// 1. Generate deterministic log file with ~100k entries
	logFile := generateIntegrationLogFile(t)
	t.Logf("Generated log file: %s (%d entries)", logFile, totalEntryCount)

	// 2. Build equivalent configs via both paths
	tomlCfg := buildTOMLConfig(t, logFile)
	cliCfg := buildCLIConfig(t, logFile)

	// 3. Run analysis on both
	tomlResult, tomlRequests, err := StaticWithRequests(tomlCfg)
	if err != nil {
		t.Fatalf("TOML analysis failed: %v", err)
	}
	cliResult, cliRequests, err := StaticWithRequests(cliCfg)
	if err != nil {
		t.Fatalf("CLI analysis failed: %v", err)
	}

	// 4. Both must parse the same number of requests
	if len(tomlRequests) != len(cliRequests) {
		t.Fatalf("Parsed request count mismatch: toml=%d, cli=%d",
			len(tomlRequests), len(cliRequests))
	}
	t.Logf("Both parsed %d requests", len(tomlRequests))

	// 5. Compare all non-timing fields
	compareJSONOutputs(t, tomlResult, cliResult)

	// 6. Sanity checks: verify the data is non-trivial
	if tomlResult.General.TotalRequests < 90000 {
		t.Errorf("Expected at least 90k parsed requests, got %d", tomlResult.General.TotalRequests)
	}

	if len(tomlResult.Tries) != 4 {
		t.Fatalf("Expected 4 tries, got %d", len(tomlResult.Tries))
	}

	// Verify trie_1 (unfiltered) has all requests
	for _, tr := range tomlResult.Tries {
		switch tr.Name {
		case "trie_1":
			// Unfiltered: should have all valid requests
			if tr.Stats.TotalRequestsAfterFiltering < 90000 {
				t.Errorf("trie_1: expected >90k requests after filtering, got %d",
					tr.Stats.TotalRequestsAfterFiltering)
			}
			// CIDR analysis should have non-zero counts for our test ranges
			for _, ca := range tr.Stats.CIDRAnalysis {
				if ca.CIDR == "14.160.0.0/12" && ca.Requests == 0 {
					t.Error("trie_1: expected non-zero requests for 14.160.0.0/12")
				}
				if ca.CIDR == "77.88.0.0/16" && ca.Requests == 0 {
					t.Error("trie_1: expected non-zero requests for 77.88.0.0/16")
				}
			}
			// The broader cluster set (minDepth=16) should detect clusters
			for _, cluster := range tr.Data {
				if cluster.Parameters.MinDepth <= 16 && len(cluster.DetectedRanges) == 0 {
					t.Errorf("trie_1: expected detected clusters for broad params %+v", cluster.Parameters)
				}
			}

		case "trie_2":
			// Bot filter: ~25% of requests
			expected := totalEntryCount / 4 // 25% Googlebot
			tolerance := expected / 5       // 20% tolerance
			if intAbs(tr.Stats.TotalRequestsAfterFiltering-expected) > tolerance {
				t.Errorf("trie_2 (bot filter): expected ~%d requests, got %d",
					expected, tr.Stats.TotalRequestsAfterFiltering)
			}

		case "trie_3":
			// Endpoint filter (/api/*): ~45% (Googlebot + curl)
			expected := totalEntryCount * 45 / 100
			tolerance := expected / 5
			if intAbs(tr.Stats.TotalRequestsAfterFiltering-expected) > tolerance {
				t.Errorf("trie_3 (endpoint filter): expected ~%d requests, got %d",
					expected, tr.Stats.TotalRequestsAfterFiltering)
			}

		case "trie_4":
			// Time filter (Feb 3-5): ~3/7 of requests
			expected := totalEntryCount * 3 / 7
			tolerance := expected / 5
			if intAbs(tr.Stats.TotalRequestsAfterFiltering-expected) > tolerance {
				t.Errorf("trie_4 (time filter): expected ~%d requests, got %d",
					expected, tr.Stats.TotalRequestsAfterFiltering)
			}
		}
	}

	t.Logf("TOML duration: %dms, CLI duration: %dms",
		tomlResult.Metadata.DurationMS, cliResult.Metadata.DurationMS)
}

func intAbs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// generateBenchmarkLogFileImpl creates a log file for benchmarks using the
// same distribution as generateIntegrationLogFile but without *testing.T.
func generateBenchmarkLogFileImpl(tmpDir string) string {
	logFile := filepath.Join(tmpDir, "benchmark.log")
	var b strings.Builder
	b.Grow(totalEntryCount * 150)
	entryIdx := 0

	writeEntry := func(ip string) {
		ua := uaForIndex(entryIdx)
		ts := timestampForIndex(entryIdx)
		endpoint := ua.endpoint
		if strings.Contains(endpoint, "%d") {
			endpoint = fmt.Sprintf(endpoint, entryIdx%100)
		}
		fmt.Fprintf(&b, "%s - - %s \"GET %s HTTP/1.1\" 200 1024 \"-\" \"%s\"\n",
			ip, ts, endpoint, ua.ua)
		entryIdx++
	}

	for i := 0; i < clusterACount; i++ {
		v := i + 1
		writeEntry(fmt.Sprintf("10.20.%d.%d", v/256, v%256))
	}
	for i := 0; i < clusterBCount; i++ {
		v := i + 1
		writeEntry(fmt.Sprintf("192.168.%d.%d", v/256, v%256))
	}
	for i := 0; i < clusterCCount; i++ {
		v := i + 1
		writeEntry(fmt.Sprintf("172.16.%d.%d", v/256, v%256))
	}
	for i := 0; i < cidrTest1Count; i++ {
		v := i + 1
		writeEntry(fmt.Sprintf("14.160.%d.%d", v/256, v%256))
	}
	for i := 0; i < cidrTest2Count; i++ {
		v := i + 1
		writeEntry(fmt.Sprintf("77.88.%d.%d", v/256, v%256))
	}
	for i := 0; i < noiseCount; i++ {
		o1 := 40 + (i / 1000)
		o2 := (i % 1000) / 4
		o3 := (i % 4)
		o4 := 1 + ((i * 7) % 254)
		writeEntry(fmt.Sprintf("%d.%d.%d.%d", o1, o2, o3, o4))
	}

	if err := os.WriteFile(logFile, []byte(b.String()), 0644); err != nil {
		panic(fmt.Sprintf("Failed to write benchmark log file: %v", err))
	}
	return logFile
}

// ============================================================================
// Invalid Input Error Parity Tests
// ============================================================================

func TestInvalidRegexParity(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")
	if err := os.WriteFile(logFile, []byte("1.2.3.4 - - [01/Feb/2025:00:00:00 +0000] \"GET / HTTP/1.1\" 200 0 \"-\" \"test\"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// TOML path: invalid regex causes LoadConfig to fail
	tomlContent := fmt.Sprintf(`
[static]
logFile = %q
logFormat = '%s'

[static.trie_1]
useragentRegex = "[invalid regex"
clusterArgSets = [[100, 24, 32, 0.1]]
`, logFile, integrationLogFormat)

	configPath := filepath.Join(tmpDir, "bad_regex.toml")
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatal(err)
	}

	// CFG-02: the TOML path is now collect-all — LoadConfig succeeds and the
	// invalid regex surfaces through Validate(StaticMode).Report(). MSG preserved.
	cfg, tomlErr := config.LoadConfig(configPath)
	if tomlErr != nil {
		t.Fatalf("LoadConfig should succeed (regex surfaces via Validate now): %v", tomlErr)
	}
	tomlReport := cfg.Validate(config.StaticMode).Report()

	// CLI path: invalid regex causes CompileRegex to fail (error channel preserved)
	cliTrie := &config.TrieConfig{
		UserAgentRegex: "[invalid regex",
		ClusterArgSets: []config.ClusterArgSet{
			{MinClusterSize: 100, MinDepth: 24, MaxDepth: 32, MeanSubnetDifference: 0.1},
		},
	}
	cliErr := cliTrie.CompileRegex()
	if cliErr == nil {
		t.Fatal("Expected CLI CompileRegex to fail for invalid regex")
	}

	// Both should carry the same MSG-02 prefix (one via report, one via error).
	if !strings.Contains(tomlReport, "invalid useragentRegex pattern") {
		t.Errorf("TOML report missing expected prefix:\n%s", tomlReport)
	}
	if !strings.Contains(cliErr.Error(), "invalid useragentRegex pattern") {
		t.Errorf("CLI error missing expected prefix: %v", cliErr)
	}
}

func TestInvalidEndpointRegexParity(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")
	if err := os.WriteFile(logFile, []byte("1.2.3.4 - - [01/Feb/2025:00:00:00 +0000] \"GET / HTTP/1.1\" 200 0 \"-\" \"test\"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// TOML path
	tomlContent := fmt.Sprintf(`
[static]
logFile = %q
logFormat = '%s'

[static.trie_1]
endpointRegex = "*invalid"
clusterArgSets = [[100, 24, 32, 0.1]]
`, logFile, integrationLogFormat)

	configPath := filepath.Join(tmpDir, "bad_ep_regex.toml")
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatal(err)
	}

	// CFG-02: collect-all — surfaces via Validate(StaticMode).Report().
	cfg, tomlErr := config.LoadConfig(configPath)
	if tomlErr != nil {
		t.Fatalf("LoadConfig should succeed (regex surfaces via Validate now): %v", tomlErr)
	}
	tomlReport := cfg.Validate(config.StaticMode).Report()

	// CLI path
	cliTrie := &config.TrieConfig{
		EndpointRegex: "*invalid",
	}
	cliErr := cliTrie.CompileRegex()
	if cliErr == nil {
		t.Fatal("Expected CLI CompileRegex to fail for invalid endpoint regex")
	}

	if !strings.Contains(tomlReport, "invalid endpointRegex pattern") {
		t.Errorf("TOML report missing expected prefix:\n%s", tomlReport)
	}
	if !strings.Contains(cliErr.Error(), "invalid endpointRegex pattern") {
		t.Errorf("CLI error missing expected prefix: %v", cliErr)
	}
}

func TestInvalidLogFileParity(t *testing.T) {
	nonexistent := "/nonexistent/path/to/file.log"

	// Both paths create config pointing to nonexistent file, then run analysis
	cfgA := &config.Config{
		Global: &config.GlobalConfig{},
		Static: &config.StaticConfig{
			LogFile:   nonexistent,
			LogFormat: integrationLogFormat,
		},
		StaticTries: map[string]*config.TrieConfig{
			"test": {
				ClusterArgSets: []config.ClusterArgSet{
					{MinClusterSize: 100, MinDepth: 24, MaxDepth: 32, MeanSubnetDifference: 0.2},
				},
			},
		},
	}

	cfgB := &config.Config{
		Global: &config.GlobalConfig{},
		Static: &config.StaticConfig{
			LogFile:   nonexistent,
			LogFormat: integrationLogFormat,
		},
		StaticTries: map[string]*config.TrieConfig{
			"test": {
				ClusterArgSets: []config.ClusterArgSet{
					{MinClusterSize: 100, MinDepth: 24, MaxDepth: 32, MeanSubnetDifference: 0.2},
				},
			},
		},
	}

	resultA, _, errA := StaticWithRequests(cfgA)
	resultB, _, errB := StaticWithRequests(cfgB)

	// Both should fail
	if errA == nil {
		t.Error("Expected error for config A with nonexistent file")
	}
	if errB == nil {
		t.Error("Expected error for config B with nonexistent file")
	}

	// Both should still return result with error info
	if resultA == nil || resultB == nil {
		t.Fatal("Expected non-nil results even on error")
	}
	if len(resultA.Errors) == 0 || len(resultB.Errors) == 0 {
		t.Error("Expected error entries in results")
	}
}

func TestInvalidClusterArgsParity(t *testing.T) {
	// Test via ParseClusterArgSetsFromStrings (CLI path)
	tests := []struct {
		name string
		args []string
	}{
		{"not multiple of 4", []string{"1000", "24", "32"}},
		{"non-numeric value", []string{"abc", "24", "32", "0.1"}},
		{"minDepth > maxDepth", []string{"1000", "32", "24", "0.1"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := config.ParseClusterArgSetsFromStrings(tt.args)
			if err == nil {
				t.Errorf("Expected error for %s, got nil", tt.name)
			}
		})
	}

	// Test minDepth > maxDepth through the analysis pipeline
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")
	if err := os.WriteFile(logFile, []byte("1.2.3.4 - - [01/Feb/2025:00:00:00 +0000] \"GET / HTTP/1.1\" 200 0 \"-\" \"test\"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		Global: &config.GlobalConfig{},
		Static: &config.StaticConfig{
			LogFile:   logFile,
			LogFormat: integrationLogFormat,
		},
		StaticTries: map[string]*config.TrieConfig{
			"bad_depth": {
				ClusterArgSets: []config.ClusterArgSet{
					{MinClusterSize: 100, MinDepth: 32, MaxDepth: 24, MeanSubnetDifference: 0.2},
				},
			},
		},
	}

	result, _, err := StaticWithRequests(cfg)
	if err != nil {
		t.Fatalf("Expected analysis to succeed (error goes into result.Errors): %v", err)
	}

	// Should have error about invalid depth parameters
	found := false
	for _, e := range result.Errors {
		if e.Type == "invalid_depth_params" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected 'invalid_depth_params' error in result")
	}
}

func TestEmptyLogFileParity(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "empty.log")
	if err := os.WriteFile(logFile, []byte(""), 0644); err != nil {
		t.Fatal(err)
	}

	// TOML-loaded config
	tomlContent := fmt.Sprintf(`
[static]
logFile = %q
logFormat = '%s'

[static.trie_1]
clusterArgSets = [[100, 24, 32, 0.1]]
`, logFile, integrationLogFormat)

	configPath := filepath.Join(tmpDir, "empty_log.toml")
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatal(err)
	}

	tomlCfg, err := config.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	// CLI-built config
	cliCfg := &config.Config{
		Global: &config.GlobalConfig{},
		Static: &config.StaticConfig{
			LogFile:   logFile,
			LogFormat: integrationLogFormat,
		},
		StaticTries: map[string]*config.TrieConfig{
			"trie_1": {
				ClusterArgSets: []config.ClusterArgSet{
					{MinClusterSize: 100, MinDepth: 24, MaxDepth: 32, MeanSubnetDifference: 0.1},
				},
			},
		},
	}

	tomlResult, _, _ := StaticWithRequests(tomlCfg)
	cliResult, _, _ := StaticWithRequests(cliCfg)

	// Both should have 0 requests
	if tomlResult.General.TotalRequests != 0 {
		t.Errorf("TOML: expected 0 requests, got %d", tomlResult.General.TotalRequests)
	}
	if cliResult.General.TotalRequests != 0 {
		t.Errorf("CLI: expected 0 requests, got %d", cliResult.General.TotalRequests)
	}

	// Both should have empty_logfile warning
	tomlHasWarning := false
	cliHasWarning := false
	for _, w := range tomlResult.Warnings {
		if w.Type == "empty_logfile" {
			tomlHasWarning = true
		}
	}
	for _, w := range cliResult.Warnings {
		if w.Type == "empty_logfile" {
			cliHasWarning = true
		}
	}
	if !tomlHasWarning {
		t.Error("TOML result missing 'empty_logfile' warning")
	}
	if !cliHasWarning {
		t.Error("CLI result missing 'empty_logfile' warning")
	}
}
