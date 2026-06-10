package analysis

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ChristianF88/cidrx/config"
)

// getTestLogFile returns the path to the test log file
func getTestLogFile() string {
	return filepath.Join("..", "testdata", "sample.log")
}

func TestStaticFromConfigBasic(t *testing.T) {
	// Create a basic config with one trie
	cfg := &config.Config{
		Static: &config.StaticConfig{
			LogFile:   getTestLogFile(),
			LogFormat: "%^ %^ %^ [%t] \"%r\" %s %b \"%^\" \"%u\" \"%h\"",
		},
		StaticTries: map[string]*config.TrieConfig{
			"basic": {
				ClusterArgSets: []config.ClusterArgSet{
					{MinClusterSize: 1000, MinDepth: 30, MaxDepth: 32, MeanSubnetDifference: 0.2},
				},
				CIDRRanges: []string{"192.168.0.0/16"},
			},
		},
	}

	result, err := ParallelStaticFromConfigNoRequests(cfg)
	if err != nil {
		t.Fatalf("StaticFromConfig failed: %v", err)
	}

	// Verify basic structure
	if result == nil {
		t.Fatal("Result is nil")
	}

	if len(result.Tries) != 1 {
		t.Errorf("Expected 1 trie, got %d", len(result.Tries))
	}

	if result.Tries[0].Name != "basic" {
		t.Errorf("Expected trie name 'basic', got '%s'", result.Tries[0].Name)
	}

	// Verify parameters are set correctly
	trieResult := result.Tries[0]
	if len(trieResult.Parameters.CIDRRanges) != 1 {
		t.Errorf("Expected 1 CIDR range, got %d", len(trieResult.Parameters.CIDRRanges))
	}

	if trieResult.Parameters.CIDRRanges[0] != "192.168.0.0/16" {
		t.Errorf("Expected CIDR range '192.168.0.0/16', got '%s'", trieResult.Parameters.CIDRRanges[0])
	}

	// Verify clustering was performed
	if len(trieResult.Data) != 1 {
		t.Errorf("Expected 1 cluster result, got %d", len(trieResult.Data))
	}

	clusterResult := trieResult.Data[0]
	if clusterResult.Parameters.MinClusterSize != 1000 {
		t.Errorf("Expected MinClusterSize 1000, got %d", clusterResult.Parameters.MinClusterSize)
	}
}

func TestStaticFromConfigMultipleTries(t *testing.T) {
	// Create config with multiple tries with different filters
	cfg := &config.Config{
		Static: &config.StaticConfig{
			LogFile:   getTestLogFile(),
			LogFormat: "%^ %^ %^ [%t] \"%r\" %s %b \"%^\" \"%u\" \"%h\"",
		},
		StaticTries: map[string]*config.TrieConfig{
			"all_traffic": {
				ClusterArgSets: []config.ClusterArgSet{
					{MinClusterSize: 50, MinDepth: 24, MaxDepth: 30, MeanSubnetDifference: 0.3},
				},
			},
			"filtered_endpoints": {
				EndpointRegex: ".*\\.php$",
				ClusterArgSets: []config.ClusterArgSet{
					{MinClusterSize: 10, MinDepth: 20, MaxDepth: 28, MeanSubnetDifference: 0.4},
				},
			},
			"bot_traffic": {
				UserAgentRegex: ".*[Bb]ot.*",
				ClusterArgSets: []config.ClusterArgSet{
					{MinClusterSize: 5, MinDepth: 16, MaxDepth: 24, MeanSubnetDifference: 0.5},
				},
			},
		},
	}

	result, err := ParallelStaticFromConfigNoRequests(cfg)
	if err != nil {
		t.Fatalf("StaticFromConfig failed: %v", err)
	}

	// Verify we have all three tries
	if len(result.Tries) != 3 {
		t.Errorf("Expected 3 tries, got %d", len(result.Tries))
	}

	// Create a map for easier verification
	trieMap := make(map[string]*config.TrieConfig)
	for name, trieConfig := range cfg.StaticTries {
		trieMap[name] = trieConfig
	}

	for _, trieResult := range result.Tries {
		expectedConfig := trieMap[trieResult.Name]
		if expectedConfig == nil {
			t.Errorf("Unexpected trie name: %s", trieResult.Name)
			continue
		}

		// Verify regex parameters
		if expectedConfig.EndpointRegex != "" {
			if trieResult.Parameters.EndpointRegex == nil {
				t.Errorf("Expected endpoint regex for trie %s, got nil", trieResult.Name)
			} else if *trieResult.Parameters.EndpointRegex != expectedConfig.EndpointRegex {
				t.Errorf("Expected endpoint regex '%s', got '%s'", expectedConfig.EndpointRegex, *trieResult.Parameters.EndpointRegex)
			}
		}

		if expectedConfig.UserAgentRegex != "" {
			if trieResult.Parameters.UserAgentRegex == nil {
				t.Errorf("Expected useragent regex for trie %s, got nil", trieResult.Name)
			} else if *trieResult.Parameters.UserAgentRegex != expectedConfig.UserAgentRegex {
				t.Errorf("Expected useragent regex '%s', got '%s'", expectedConfig.UserAgentRegex, *trieResult.Parameters.UserAgentRegex)
			}
		}

		// Verify clustering was performed
		if len(trieResult.Data) != 1 {
			t.Errorf("Expected 1 cluster result for trie %s, got %d", trieResult.Name, len(trieResult.Data))
		}
	}
}

func TestStaticFromConfigWithTimeRange(t *testing.T) {
	startTime := time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)
	endTime := time.Date(2023, 12, 31, 23, 59, 59, 0, time.UTC)

	cfg := &config.Config{
		Static: &config.StaticConfig{
			LogFile:   getTestLogFile(),
			LogFormat: "%^ %^ %^ [%t] \"%r\" %s %b \"%^\" \"%u\" \"%h\"",
		},
		StaticTries: map[string]*config.TrieConfig{
			"time_filtered": {
				StartTime: &startTime,
				EndTime:   &endTime,
				ClusterArgSets: []config.ClusterArgSet{
					{MinClusterSize: 100, MinDepth: 24, MaxDepth: 32, MeanSubnetDifference: 0.2},
				},
			},
		},
	}

	result, err := ParallelStaticFromConfigNoRequests(cfg)
	if err != nil {
		t.Fatalf("StaticFromConfig failed: %v", err)
	}

	// Verify time range parameters
	trieResult := result.Tries[0]
	if trieResult.Parameters.TimeRange == nil {
		t.Fatal("Expected time range parameters, got nil")
	}

	if !trieResult.Parameters.TimeRange.Start.Equal(startTime) {
		t.Errorf("Expected start time %v, got %v", startTime, trieResult.Parameters.TimeRange.Start)
	}

	if !trieResult.Parameters.TimeRange.End.Equal(endTime) {
		t.Errorf("Expected end time %v, got %v", endTime, trieResult.Parameters.TimeRange.End)
	}
}

func TestStaticFromConfigInvalidLogFile(t *testing.T) {
	cfg := &config.Config{
		Static: &config.StaticConfig{
			LogFile:   "/nonexistent/file.log",
			LogFormat: "%^ %^ %^ [%t] \"%r\" %s %b \"%^\" \"%u\" \"%h\"",
		},
		StaticTries: map[string]*config.TrieConfig{
			"test": {
				ClusterArgSets: []config.ClusterArgSet{
					{MinClusterSize: 100, MinDepth: 24, MaxDepth: 32, MeanSubnetDifference: 0.2},
				},
			},
		},
	}

	result, err := ParallelStaticFromConfigNoRequests(cfg)
	if err == nil {
		t.Error("Expected error for nonexistent log file, got nil")
	}

	// Should still return a result with error information
	if result == nil {
		t.Error("Expected result with error information, got nil")
		return
	}

	if len(result.Errors) == 0 {
		t.Error("Expected error information in result")
	}
}

func TestStaticFromConfigInvalidClusterParams(t *testing.T) {
	cfg := &config.Config{
		Static: &config.StaticConfig{
			LogFile:   getTestLogFile(),
			LogFormat: "%^ %^ %^ [%t] \"%r\" %s %b \"%^\" \"%u\" \"%h\"",
		},
		StaticTries: map[string]*config.TrieConfig{
			"invalid_params": {
				ClusterArgSets: []config.ClusterArgSet{
					{MinClusterSize: 100, MinDepth: 32, MaxDepth: 24, MeanSubnetDifference: 0.2}, // Invalid: minDepth > maxDepth
				},
			},
		},
	}

	result, err := ParallelStaticFromConfigNoRequests(cfg)
	// Should not fail completely, but should have warnings
	if err != nil && result == nil {
		t.Fatalf("Unexpected complete failure: %v", err)
	}

	// Should have error about invalid depth parameters
	foundError := false
	for _, err := range result.Errors {
		if err.Type == "invalid_depth_params" {
			foundError = true
			break
		}
	}

	if !foundError {
		t.Error("Expected error about invalid depth parameters")
	}
}

func TestStaticFromConfigTiming(t *testing.T) {
	cfg := &config.Config{
		Static: &config.StaticConfig{
			LogFile:   getTestLogFile(),
			LogFormat: "%^ %^ %^ [%t] \"%r\" %s %b \"%^\" \"%u\" \"%h\"",
		},
		StaticTries: map[string]*config.TrieConfig{
			"timing_test": {
				EndpointRegex: ".*\\.html$",
				ClusterArgSets: []config.ClusterArgSet{
					{MinClusterSize: 5, MinDepth: 20, MaxDepth: 28, MeanSubnetDifference: 0.3},
				},
			},
		},
	}

	result, err := ParallelStaticFromConfigNoRequests(cfg)
	if err != nil {
		t.Fatalf("StaticFromConfig failed: %v", err)
	}

	// Verify timing information is present (allow 0 for very fast operations)
	if result.Metadata.DurationMS < 0 {
		t.Error("Expected non-negative analysis duration")
	}

	if result.General.Parsing.DurationMS < 0 {
		t.Error("Expected non-negative parsing duration")
	}

	if result.General.Parsing.RatePerSecond <= 0 {
		t.Error("Expected positive parsing rate")
	}

	// Verify trie-specific timing
	trieResult := result.Tries[0]
	if trieResult.Stats.InsertTimeMS < 0 {
		t.Error("Expected non-negative insert time")
	}

	// Verify cluster execution timing
	if len(trieResult.Data) > 0 {
		clusterResult := trieResult.Data[0]
		if clusterResult.ExecutionTimeUS < 0 {
			t.Error("Expected non-negative cluster execution time")
		}
	}
}

func TestStaticFromConfigEmptyTries(t *testing.T) {
	cfg := &config.Config{
		Static: &config.StaticConfig{
			LogFile:   getTestLogFile(),
			LogFormat: "%^ %^ %^ [%t] \"%r\" %s %b \"%^\" \"%u\" \"%h\"",
		},
		StaticTries: map[string]*config.TrieConfig{},
	}

	result, err := ParallelStaticFromConfigNoRequests(cfg)
	if err != nil {
		t.Fatalf("StaticFromConfig failed: %v", err)
	}

	// Should handle empty tries gracefully
	if len(result.Tries) != 0 {
		t.Errorf("Expected 0 tries, got %d", len(result.Tries))
	}

	// Basic metadata should still be populated
	expectedLogFile := getTestLogFile()
	if result.General.LogFile != expectedLogFile {
		t.Errorf("Expected log file '%s', got '%s'", expectedLogFile, result.General.LogFile)
	}
}

// ============================================================================
// USER AGENT INTEGRATION TESTS (from static_useragent_integration_test.go)
// ============================================================================

func TestUserAgentWhitelistIntegration(t *testing.T) {
	// Create temporary files
	tempDir := t.TempDir()
	logFile := filepath.Join(tempDir, "test.log")
	uaWhitelistFile := filepath.Join(tempDir, "ua_whitelist.txt")
	jailFile := filepath.Join(tempDir, "jail.json")
	banFile := filepath.Join(tempDir, "ban.txt")

	// Create test log file with exact User-Agent strings
	logContent := `192.168.1.100 - - [01/Jan/2023:12:00:00 +0000] "GET / HTTP/1.1" 200 1234 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
192.168.1.101 - - [01/Jan/2023:12:00:01 +0000] "GET /page1 HTTP/1.1" 200 1234 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
192.168.1.102 - - [01/Jan/2023:12:00:02 +0000] "GET /page2 HTTP/1.1" 200 1234 "-" "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
192.168.1.103 - - [01/Jan/2023:12:00:03 +0000] "GET /page3 HTTP/1.1" 200 1234 "-" "BadBot/1.0"
192.168.1.104 - - [01/Jan/2023:12:00:04 +0000] "GET /page4 HTTP/1.1" 200 1234 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
`
	err := os.WriteFile(logFile, []byte(logContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test log file: %v", err)
	}

	// Create User-Agent whitelist file with exact matches
	uaWhitelistContent := `# Whitelist legitimate search engine bots (exact match)
Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
`
	err = os.WriteFile(uaWhitelistFile, []byte(uaWhitelistContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create User-Agent whitelist file: %v", err)
	}

	// Create test configuration
	cfg := &config.Config{
		Global: &config.GlobalConfig{
			JailFile:           jailFile,
			BanFile:            banFile,
			UserAgentWhitelist: uaWhitelistFile,
		},
		Static: &config.StaticConfig{
			LogFile:   logFile,
			LogFormat: "%h %^ %^ [%t] \"%r\" %s %b \"%^\" \"%u\"",
		},
		StaticTries: map[string]*config.TrieConfig{
			"test_trie": {
				ClusterArgSets: []config.ClusterArgSet{{MinClusterSize: 2, MinDepth: 24, MaxDepth: 24, MeanSubnetDifference: 0.5}},
				UseForJail:     []bool{true},
			},
		},
	}

	// Run static analysis
	result, err := ParallelStaticFromConfigNoRequests(cfg)
	if err != nil {
		t.Fatalf("StaticFromConfig failed: %v", err)
	}

	// Verify User-Agent whitelist IPs were extracted (3 IPs with whitelisted User-Agent)
	expectedWhitelistIPs := []string{"192.168.1.100", "192.168.1.101", "192.168.1.102"}
	if len(result.UserAgentWhitelistIPs) != len(expectedWhitelistIPs) {
		t.Errorf("Expected %d whitelisted IPs, got %d", len(expectedWhitelistIPs), len(result.UserAgentWhitelistIPs))
	}

	// Verify specific IPs are in the whitelist
	if len(result.UserAgentWhitelistIPs) > 0 {
		whitelistMap := make(map[string]bool)
		for _, ip := range result.UserAgentWhitelistIPs {
			whitelistMap[ip] = true
		}

		for _, expectedIP := range expectedWhitelistIPs {
			if !whitelistMap[expectedIP] {
				t.Errorf("Expected IP %s to be in User-Agent whitelist", expectedIP)
			}
		}
	}

	// Verify trie contains only non-whitelisted IPs (should exclude whitelisted ones)
	expectedUniqueIPs := 2 // Only 192.168.1.103 and 192.168.1.104 should be in trie
	if result.Tries[0].Stats.UniqueIPs != expectedUniqueIPs {
		t.Errorf("Expected %d unique IPs in trie, got %d", expectedUniqueIPs, result.Tries[0].Stats.UniqueIPs)
	}
}

func TestUserAgentBlacklistIntegration(t *testing.T) {
	// Create temporary files
	tempDir := t.TempDir()
	logFile := filepath.Join(tempDir, "test.log")
	uaBlacklistFile := filepath.Join(tempDir, "ua_blacklist.txt")
	jailFile := filepath.Join(tempDir, "jail.json")
	banFile := filepath.Join(tempDir, "ban.txt")

	// Create test log file
	logContent := `192.168.1.100 - - [01/Jan/2023:12:00:00 +0000] "GET / HTTP/1.1" 200 1234 "-" "BadBot/1.0"
192.168.1.101 - - [01/Jan/2023:12:00:01 +0000] "GET /page1 HTTP/1.1" 200 1234 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
192.168.1.102 - - [01/Jan/2023:12:00:02 +0000] "GET /page2 HTTP/1.1" 200 1234 "-" "EvilScraper/2.0"
192.168.1.103 - - [01/Jan/2023:12:00:03 +0000] "GET /page3 HTTP/1.1" 200 1234 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
`
	err := os.WriteFile(logFile, []byte(logContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test log file: %v", err)
	}

	// Create User-Agent blacklist file with exact matches
	uaBlacklistContent := `# Blacklist known bad bots (exact match)
BadBot/1.0
EvilScraper/2.0
`
	err = os.WriteFile(uaBlacklistFile, []byte(uaBlacklistContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create User-Agent blacklist file: %v", err)
	}

	// Create test configuration
	cfg := &config.Config{
		Global: &config.GlobalConfig{
			JailFile:           jailFile,
			BanFile:            banFile,
			UserAgentBlacklist: uaBlacklistFile,
		},
		Static: &config.StaticConfig{
			LogFile:   logFile,
			LogFormat: "%h %^ %^ [%t] \"%r\" %s %b \"%^\" \"%u\"",
		},
		StaticTries: map[string]*config.TrieConfig{
			"test_trie": {
				ClusterArgSets: []config.ClusterArgSet{{MinClusterSize: 2, MinDepth: 24, MaxDepth: 24, MeanSubnetDifference: 0.5}},
				UseForJail:     []bool{true},
			},
		},
	}

	// Run static analysis
	result, err := ParallelStaticFromConfigNoRequests(cfg)
	if err != nil {
		t.Fatalf("StaticFromConfig failed: %v", err)
	}

	// Verify User-Agent blacklist IPs were extracted
	expectedBlacklistIPs := []string{"192.168.1.100", "192.168.1.102"}
	if len(result.UserAgentBlacklistIPs) != len(expectedBlacklistIPs) {
		t.Errorf("Expected %d blacklisted IPs, got %d", len(expectedBlacklistIPs), len(result.UserAgentBlacklistIPs))
	}

	// Verify specific IPs are in the blacklist
	if len(result.UserAgentBlacklistIPs) > 0 {
		blacklistMap := make(map[string]bool)
		for _, ip := range result.UserAgentBlacklistIPs {
			blacklistMap[ip] = true
		}

		for _, expectedIP := range expectedBlacklistIPs {
			if !blacklistMap[expectedIP] {
				t.Errorf("Expected IP %s to be in User-Agent blacklist", expectedIP)
			}
		}
	}
}

func TestUserAgentFilteringWithTimeRange(t *testing.T) {
	// Create temporary files
	tempDir := t.TempDir()
	logFile := filepath.Join(tempDir, "test.log")
	uaWhitelistFile := filepath.Join(tempDir, "ua_whitelist.txt")
	jailFile := filepath.Join(tempDir, "jail.json")
	banFile := filepath.Join(tempDir, "ban.txt")

	// Create test log file with timestamps
	logContent := `192.168.1.100 - - [01/Jan/2023:10:00:00 +0000] "GET / HTTP/1.1" 200 1234 "-" "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
192.168.1.101 - - [01/Jan/2023:12:00:01 +0000] "GET /page1 HTTP/1.1" 200 1234 "-" "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
192.168.1.102 - - [01/Jan/2023:14:00:02 +0000] "GET /page2 HTTP/1.1" 200 1234 "-" "BadBot/1.0"
`
	err := os.WriteFile(logFile, []byte(logContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test log file: %v", err)
	}

	// Create User-Agent whitelist file with exact match
	uaWhitelistContent := `# Whitelist legitimate search engine bots (exact match)
Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)
`
	err = os.WriteFile(uaWhitelistFile, []byte(uaWhitelistContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create User-Agent whitelist file: %v", err)
	}

	// Set time range to include only the middle entry
	startTime := time.Date(2023, 1, 1, 11, 0, 0, 0, time.UTC)
	endTime := time.Date(2023, 1, 1, 13, 0, 0, 0, time.UTC)

	// Create test configuration
	cfg := &config.Config{
		Global: &config.GlobalConfig{
			JailFile:           jailFile,
			BanFile:            banFile,
			UserAgentWhitelist: uaWhitelistFile,
		},
		Static: &config.StaticConfig{
			LogFile:   logFile,
			LogFormat: "%h %^ %^ [%t] \"%r\" %s %b \"%^\" \"%u\"",
		},
		StaticTries: map[string]*config.TrieConfig{
			"test_trie": {
				StartTime:      &startTime,
				EndTime:        &endTime,
				ClusterArgSets: []config.ClusterArgSet{{MinClusterSize: 2, MinDepth: 24, MaxDepth: 24, MeanSubnetDifference: 0.5}},
				UseForJail:     []bool{true},
			},
		},
	}

	// Run static analysis
	result, err := ParallelStaticFromConfigNoRequests(cfg)
	if err != nil {
		t.Fatalf("StaticFromConfig failed: %v", err)
	}

	// Verify User-Agent whitelist IPs were extracted within time range (only 192.168.1.101)
	expectedWhitelistIPs := 1
	if len(result.UserAgentWhitelistIPs) != expectedWhitelistIPs {
		t.Errorf("Expected %d whitelisted IPs with time filtering, got %d", expectedWhitelistIPs, len(result.UserAgentWhitelistIPs))
	}

	// Verify correct IP is whitelisted
	if len(result.UserAgentWhitelistIPs) > 0 && result.UserAgentWhitelistIPs[0] != "192.168.1.101" {
		t.Errorf("Expected IP 192.168.1.101 to be whitelisted with time filtering, got %s", result.UserAgentWhitelistIPs[0])
	}
}

func TestUserAgentFilteringPerformance(t *testing.T) {
	// Create temporary files
	tempDir := t.TempDir()
	logFile := filepath.Join(tempDir, "test.log")
	uaWhitelistFile := filepath.Join(tempDir, "ua_whitelist.txt")
	uaBlacklistFile := filepath.Join(tempDir, "ua_blacklist.txt")
	jailFile := filepath.Join(tempDir, "jail.json")
	banFile := filepath.Join(tempDir, "ban.txt")

	// Create large test log file
	numRequests := 10000
	logContent := ""
	for i := 0; i < numRequests; i++ {
		var userAgent string
		ip := 100 + (i % 100) // IPs from 192.168.1.100 to 192.168.1.199

		switch i % 4 {
		case 0:
			userAgent = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" // Whitelisted
		case 1:
			userAgent = "BadBot/1.0" // Blacklisted
		case 2:
			userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" // Regular
		case 3:
			userAgent = "EvilScraper/2.0" // Blacklisted
		}

		logContent += fmt.Sprintf("192.168.1.%d - - [01/Jan/2023:12:00:%02d +0000] \"GET /page%d HTTP/1.1\" 200 1234 \"-\" \"%s\"\n",
			ip, i%60, i, userAgent)
	}

	err := os.WriteFile(logFile, []byte(logContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test log file: %v", err)
	}

	// Create User-Agent whitelist file
	uaWhitelistContent := `# Whitelist legitimate search engine bots (exact match)
Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)
`
	err = os.WriteFile(uaWhitelistFile, []byte(uaWhitelistContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create User-Agent whitelist file: %v", err)
	}

	// Create User-Agent blacklist file
	uaBlacklistContent := `# Blacklist known bad bots (exact match)
BadBot/1.0
EvilScraper/2.0
`
	err = os.WriteFile(uaBlacklistFile, []byte(uaBlacklistContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create User-Agent blacklist file: %v", err)
	}

	// Create test configuration
	cfg := &config.Config{
		Global: &config.GlobalConfig{
			JailFile:           jailFile,
			BanFile:            banFile,
			UserAgentWhitelist: uaWhitelistFile,
			UserAgentBlacklist: uaBlacklistFile,
		},
		Static: &config.StaticConfig{
			LogFile:   logFile,
			LogFormat: "%h %^ %^ [%t] \"%r\" %s %b \"%^\" \"%u\"",
		},
		StaticTries: map[string]*config.TrieConfig{
			"test_trie": {
				ClusterArgSets: []config.ClusterArgSet{{MinClusterSize: 2, MinDepth: 24, MaxDepth: 24, MeanSubnetDifference: 0.5}},
				UseForJail:     []bool{true},
			},
		},
	}

	// Measure performance
	start := time.Now()
	result, err := ParallelStaticFromConfigNoRequests(cfg)
	duration := time.Since(start)

	if err != nil {
		t.Fatalf("StaticFromConfig failed: %v", err)
	}

	// Expected: Due to IP deduplication (IPs 100-199), we have 100 unique IPs
	// Pattern distribution: 25% whitelisted, 50% blacklisted, 25% regular
	// But due to deduplication, each IP appears multiple times with different user agents
	// The final count depends on the last user agent seen for each IP
	expectedWhitelisted := 25 // 25% of 100 unique IPs
	expectedBlacklisted := 50 // 50% of 100 unique IPs

	whitelistedCount := len(result.UserAgentWhitelistIPs)
	blacklistedCount := len(result.UserAgentBlacklistIPs)

	// Allow some tolerance for the exact distribution due to the pattern cycling
	tolerance := 5
	if abs(whitelistedCount-expectedWhitelisted) > tolerance {
		t.Errorf("Expected ~%d whitelisted IPs, got %d", expectedWhitelisted, whitelistedCount)
	}

	if abs(blacklistedCount-expectedBlacklisted) > tolerance {
		t.Errorf("Expected ~%d blacklisted IPs, got %d", expectedBlacklisted, blacklistedCount)
	}

	t.Logf("Processed %d requests in %v (whitelisted: %d, blacklisted: %d)",
		numRequests, duration, whitelistedCount, blacklistedCount)
}

// Helper function for absolute value
func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
