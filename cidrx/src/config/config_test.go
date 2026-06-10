package config

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ChristianF88/cidrx/ingestor"
)

func TestLoadConfig(t *testing.T) {
	testConfigContent := `
[global]
logFile = "/var/log/cidrx.log"
logLevel = "info"
logFileSizeMax = "100MB"
jailFile = "/etc/cidrx/jail.json"
banFile = "/etc/cidrx/ban.txt"

[static]
logFormat = "nginx"

[static.trie_1]
useragentRegex = ".*bot.*"
endpointRegex = "/api/.*"
startTime = "2023-01-01T00:00:00Z"
endTime = "2023-12-31T23:59:59Z"
cidrRanges = ["192.168.1.0/24", "10.0.0.0/8"]
clusterArgSets = [[1000, 24, 32, 0.1], [100, 32, 32, 0.1]]
useForJail = [true, false]

[static.trie_2]
useragentRegex = ".*crawler.*"
endpointRegex = "/test/.*"
cidrRanges = ["172.16.0.0/16"]
clusterArgSets = [[500, 28, 32, 0.05]]
useForJail = [true]

[live]

[live.sliding_trie_1]
useragentRegex = ".*scanner.*"
endpointRegex = "/admin/.*"
slidingWindowMaxTime = "1h"
slidingWindowMaxSize = 10000
sleepBetweenIterations = 30
clusterArgSets = [[200, 30, 32, 0.2]]
useForJail = [true]

[live.sliding_trie_2]
useragentRegex = ".*spider.*"
endpointRegex = "/private/.*"
slidingWindowMaxTime = "2h"
slidingWindowMaxSize = 20000
sleepBetweenIterations = 60
clusterArgSets = [[300, 28, 32, 0.15], [150, 32, 32, 0.1]]
useForJail = [true, false]
`

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test_config.toml")

	err := os.WriteFile(configPath, []byte(testConfigContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write test config file: %v", err)
	}

	config, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if config.Global.JailFile != "/etc/cidrx/jail.json" {
		t.Errorf("Expected JailFile to be '/etc/cidrx/jail.json', got '%s'", config.Global.JailFile)
	}

	if config.Global.BanFile != "/etc/cidrx/ban.txt" {
		t.Errorf("Expected BanFile to be '/etc/cidrx/ban.txt', got '%s'", config.Global.BanFile)
	}

	if config.Static.LogFormat != "nginx" {
		t.Errorf("Expected LogFormat to be 'nginx', got '%s'", config.Static.LogFormat)
	}

	if len(config.StaticTries) != 2 {
		t.Errorf("Expected 2 static tries, got %d", len(config.StaticTries))
	}

	trie1, exists := config.StaticTries["trie_1"]
	if !exists {
		t.Error("Expected trie_1 to exist in static tries")
	} else {
		if trie1.UserAgentRegex != ".*bot.*" {
			t.Errorf("Expected UserAgentRegex to be '.*bot.*', got '%s'", trie1.UserAgentRegex)
		}
		if trie1.EndpointRegex != "/api/.*" {
			t.Errorf("Expected EndpointRegex to be '/api/.*', got '%s'", trie1.EndpointRegex)
		}
		if len(trie1.CIDRRanges) != 2 {
			t.Errorf("Expected 2 CIDR ranges, got %d", len(trie1.CIDRRanges))
		}
		if len(trie1.ClusterArgSets) != 2 {
			t.Errorf("Expected 2 cluster arg sets, got %d", len(trie1.ClusterArgSets))
		}
		if len(trie1.UseForJail) != 2 {
			t.Errorf("Expected 2 useForJail values, got %d", len(trie1.UseForJail))
		}
	}

	if len(config.LiveTries) != 2 {
		t.Errorf("Expected 2 sliding tries, got %d", len(config.LiveTries))
	}

	slidingTrie1, exists := config.LiveTries["sliding_trie_1"]
	if !exists {
		t.Error("Expected sliding_trie_1 to exist in live sliding tries")
	} else {
		if slidingTrie1.UserAgentRegex != ".*scanner.*" {
			t.Errorf("Expected UserAgentRegex to be '.*scanner.*', got '%s'", slidingTrie1.UserAgentRegex)
		}
		if slidingTrie1.SlidingWindowMaxTime != 1*time.Hour {
			t.Errorf("Expected SlidingWindowMaxTime to be 1h, got %v", slidingTrie1.SlidingWindowMaxTime)
		}
		if slidingTrie1.SlidingWindowMaxSize != 10000 {
			t.Errorf("Expected SlidingWindowMaxSize to be 10000, got %d", slidingTrie1.SlidingWindowMaxSize)
		}
		if slidingTrie1.SleepBetweenIterations != 30 {
			t.Errorf("Expected SleepBetweenIterations to be 30, got %d", slidingTrie1.SleepBetweenIterations)
		}
	}
}

func TestLoadConfigWithMissingFile(t *testing.T) {
	_, err := LoadConfig("nonexistent_config.toml")
	if err == nil {
		t.Error("Expected error when loading non-existent config file")
	}
}

func TestLoadConfigWithInvalidTOML(t *testing.T) {
	invalidConfigContent := `
[global
logFile = "/var/log/cidrx.log"
`

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "invalid_config.toml")

	err := os.WriteFile(configPath, []byte(invalidConfigContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write invalid config file: %v", err)
	}

	_, err = LoadConfig(configPath)
	if err == nil {
		t.Error("Expected error when loading invalid TOML config")
	}
}

func TestLoadConfigWithEmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "empty_config.toml")

	err := os.WriteFile(configPath, []byte(""), 0644)
	if err != nil {
		t.Fatalf("Failed to write empty config file: %v", err)
	}

	config, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load empty config: %v", err)
	}

	if config.Global == nil {
		t.Error("Expected Global config to be initialized")
	}
	if config.Static == nil {
		t.Error("Expected Static config to be initialized")
	}
	if config.Live == nil {
		t.Error("Expected Live config to be initialized")
	}
}

func TestGetJailFile(t *testing.T) {
	config := &Config{
		Global: &GlobalConfig{
			JailFile: "/custom/jail.json",
		},
	}

	jailFile := config.GetJailFile()
	if jailFile != "/custom/jail.json" {
		t.Errorf("Expected custom jail file '/custom/jail.json', got '%s'", jailFile)
	}

	config.Global.JailFile = ""
	jailFile = config.GetJailFile()
	if jailFile != JailFile {
		t.Errorf("Expected default jail file '%s', got '%s'", JailFile, jailFile)
	}

	config.Global = nil
	jailFile = config.GetJailFile()
	if jailFile != JailFile {
		t.Errorf("Expected default jail file '%s', got '%s'", JailFile, jailFile)
	}
}

func TestGetBanFile(t *testing.T) {
	config := &Config{
		Global: &GlobalConfig{
			BanFile: "/custom/ban.txt",
		},
	}

	banFile := config.GetBanFile()
	if banFile != "/custom/ban.txt" {
		t.Errorf("Expected custom ban file '/custom/ban.txt', got '%s'", banFile)
	}

	config.Global.BanFile = ""
	banFile = config.GetBanFile()
	if banFile != BanFile {
		t.Errorf("Expected default ban file '%s', got '%s'", BanFile, banFile)
	}

	config.Global = nil
	banFile = config.GetBanFile()
	if banFile != BanFile {
		t.Errorf("Expected default ban file '%s', got '%s'", BanFile, banFile)
	}
}

func TestConfigWithTimeFields(t *testing.T) {
	testConfigContent := `
[static.trie_1]
startTime = "2023-01-01T00:00:00Z"
endTime = "2023-12-31T23:59:59Z"
cidrRanges = ["192.168.1.0/24"]
clusterArgSets = [[100, 24, 32, 0.1]]
useForJail = [true]
`

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "time_config.toml")

	err := os.WriteFile(configPath, []byte(testConfigContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write time config file: %v", err)
	}

	config, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load time config: %v", err)
	}

	trie1, exists := config.StaticTries["trie_1"]
	if !exists {
		t.Error("Expected trie_1 to exist")
	} else {
		expectedStartTime := time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)
		if trie1.StartTime == nil {
			t.Error("Expected StartTime to be set, got nil")
		} else if !trie1.StartTime.Equal(expectedStartTime) {
			t.Errorf("Expected StartTime to be %v, got %v", expectedStartTime, *trie1.StartTime)
		}

		expectedEndTime := time.Date(2023, 12, 31, 23, 59, 59, 0, time.UTC)
		if trie1.EndTime == nil {
			t.Error("Expected EndTime to be set, got nil")
		} else if !trie1.EndTime.Equal(expectedEndTime) {
			t.Errorf("Expected EndTime to be %v, got %v", expectedEndTime, *trie1.EndTime)
		}
	}
}

func TestLiveConfigValidation(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name        string
		config      *Config
		expectError bool
	}{
		{
			name: "valid live config",
			config: &Config{
				Global: &GlobalConfig{
					JailFile: filepath.Join(tmpDir, "jail.json"),
					BanFile:  filepath.Join(tmpDir, "ban.txt"),
				},
				Live: &LiveConfig{
					Port: "8080",
				},
				LiveTries: map[string]*SlidingTrieConfig{
					"default": {
						SlidingWindowMaxTime:   2 * time.Hour,
						SlidingWindowMaxSize:   100000,
						SleepBetweenIterations: 10,
					},
				},
			},
			expectError: false,
		},
		{
			name: "missing LiveTries",
			config: &Config{
				Global: &GlobalConfig{
					JailFile: filepath.Join(tmpDir, "jail.json"),
					BanFile:  filepath.Join(tmpDir, "ban.txt"),
				},
				Live: &LiveConfig{
					Port: "8080",
				},
				LiveTries: map[string]*SlidingTrieConfig{},
			},
			expectError: true,
		},
		{
			name: "missing live section",
			config: &Config{
				Live: nil,
			},
			expectError: true,
		},
		{
			name: "missing port",
			config: &Config{
				Live: &LiveConfig{},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.ValidateLive()
			if tt.expectError && err == nil {
				t.Error("Expected validation error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no validation error but got: %v", err)
			}
		})
	}
}

func TestEnhancedStaticConfigParsing(t *testing.T) {
	tmpDir := t.TempDir()
	plotPath := filepath.Join(tmpDir, "heatmap.html")

	testConfigContent := `
[static]
logFile = "/var/log/access.log"
logFormat = "%^ %^ %^ [%t] \"%r\" %s %b %^ \"%u\" \"%h\""
plotPath = "` + plotPath + `"
`

	configPath := filepath.Join(tmpDir, "static_config.toml")

	err := os.WriteFile(configPath, []byte(testConfigContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	config, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if config.Static.LogFile != "/var/log/access.log" {
		t.Errorf("Expected LogFile to be '/var/log/access.log', got '%s'", config.Static.LogFile)
	}
	if config.Static.LogFormat != "%^ %^ %^ [%t] \"%r\" %s %b %^ \"%u\" \"%h\"" {
		t.Errorf("Expected LogFormat to be '%s', got '%s'", "%^ %^ %^ [%t] \"%r\" %s %b %^ \"%u\" \"%h\"", config.Static.LogFormat)
	}
	if config.Static.PlotPath != plotPath {
		t.Errorf("Expected PlotPath to be '%s', got '%s'", plotPath, config.Static.PlotPath)
	}
}

func TestEnhancedLiveConfigParsing(t *testing.T) {
	testConfigContent := `
[live]
port = "9090"
`

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "live_config.toml")

	err := os.WriteFile(configPath, []byte(testConfigContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	config, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if config.Live.Port != "9090" {
		t.Errorf("Expected Port to be '9090', got '%s'", config.Live.Port)
	}
}

func TestOptionalFieldsHandling(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a test log file
	testLogFile := filepath.Join(tmpDir, "test.log")
	err := os.WriteFile(testLogFile, []byte("test log content"), 0644)
	if err != nil {
		t.Fatalf("Failed to create test log file: %v", err)
	}

	// Test config with minimal required fields only
	testConfigContent := `
[global]
jailFile = "` + filepath.Join(tmpDir, "jail.json") + `"
banFile = "` + filepath.Join(tmpDir, "ban.txt") + `"

[static]
logFile = "` + testLogFile + `"
logFormat = "%h %^ %^ [%t] \"%r\" %s %b"

[live]
port = "8080"

[static.trie_1]
# No optional fields specified - should work fine

[live.sliding_trie_1]  
# No optional fields specified - should work fine
`

	configPath := filepath.Join(tmpDir, "minimal_config.toml")
	err = os.WriteFile(configPath, []byte(testConfigContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	config, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Test live validation with minimal fields
	err = config.ValidateLive()
	if err != nil {
		t.Errorf("Expected live validation to pass with minimal required fields, got: %v", err)
	}

	// Verify static config has required fields
	if config.Static.LogFile != testLogFile {
		t.Errorf("Expected LogFile to be '%s', got '%s'", testLogFile, config.Static.LogFile)
	}
	if config.Static.LogFormat != "%h %^ %^ [%t] \"%r\" %s %b" {
		t.Errorf("Expected LogFormat to be set, got '%s'", config.Static.LogFormat)
	}
	// PlotPath should be empty (optional)
	if config.Static.PlotPath != "" {
		t.Errorf("Expected PlotPath to be empty, got '%s'", config.Static.PlotPath)
	}

	// Verify live config has required fields
	if config.Live.Port != "8080" {
		t.Errorf("Expected Port to be '8080', got '%s'", config.Live.Port)
	}

	// Verify trie configs exist but have optional fields as nil/empty
	if len(config.StaticTries) != 1 {
		t.Errorf("Expected 1 static trie, got %d", len(config.StaticTries))
	}

	trie1, exists := config.StaticTries["trie_1"]
	if !exists {
		t.Error("Expected trie_1 to exist")
	} else {
		// Optional time fields should be nil
		if trie1.StartTime != nil {
			t.Errorf("Expected StartTime to be nil, got %v", trie1.StartTime)
		}
		if trie1.EndTime != nil {
			t.Errorf("Expected EndTime to be nil, got %v", trie1.EndTime)
		}
		// Optional slice fields should be empty
		if len(trie1.CIDRRanges) != 0 {
			t.Errorf("Expected CIDRRanges to be empty, got %v", trie1.CIDRRanges)
		}
		if len(trie1.ClusterArgSets) != 0 {
			t.Errorf("Expected ClusterArgSets to be empty, got %v", trie1.ClusterArgSets)
		}
	}
}

func TestRegexFilteringTrieConfig(t *testing.T) {
	testConfigContent := `
[static.trie_1]
useragentRegex = ".*bot.*"
endpointRegex = "/api/.*"

[static.trie_2]
useragentRegex = ".*crawler.*"
endpointRegex = "/admin/.*"

[static.trie_3]
# No regex filters - should accept all requests
`

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "regex_config.toml")

	err := os.WriteFile(configPath, []byte(testConfigContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	config, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Test trie_1 - should filter for bot user agents and /api/ endpoints
	trie1, exists := config.StaticTries["trie_1"]
	if !exists {
		t.Fatal("Expected trie_1 to exist")
	}

	// Test cases for trie_1
	testCases := []struct {
		name     string
		request  ingestor.Request
		expected bool
	}{
		{
			name: "bot user agent and api endpoint - should include",
			request: ingestor.Request{
				UserAgent: "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
				URI:       "/api/users",
				IP:        net.ParseIP("1.2.3.4"),
			},
			expected: true,
		},
		{
			name: "bot user agent but non-api endpoint - should exclude",
			request: ingestor.Request{
				UserAgent: "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
				URI:       "/home",
				IP:        net.ParseIP("1.2.3.4"),
			},
			expected: false,
		},
		{
			name: "non-bot user agent but api endpoint - should exclude",
			request: ingestor.Request{
				UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
				URI:       "/api/users",
				IP:        net.ParseIP("1.2.3.4"),
			},
			expected: false,
		},
		{
			name: "non-bot user agent and non-api endpoint - should exclude",
			request: ingestor.Request{
				UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
				URI:       "/home",
				IP:        net.ParseIP("1.2.3.4"),
			},
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := trie1.ShouldIncludeRequest(tc.request)
			if result != tc.expected {
				t.Errorf("Expected %v, got %v for %s", tc.expected, result, tc.name)
			}
		})
	}

	// Test trie_3 - no regex filters, should accept all requests
	trie3, exists := config.StaticTries["trie_3"]
	if !exists {
		t.Fatal("Expected trie_3 to exist")
	}

	testRequest := ingestor.Request{
		UserAgent: "Any user agent",
		URI:       "/any/endpoint",
		IP:        net.ParseIP("1.2.3.4"),
	}

	if !trie3.ShouldIncludeRequest(testRequest) {
		t.Error("Expected trie_3 to accept all requests when no regex filters are specified")
	}
}

func TestRegexFilteringSlidingTrieConfig(t *testing.T) {
	testConfigContent := `
[live.sliding_trie_1]
useragentRegex = ".*scanner.*"
endpointRegex = "/admin/.*"

[live.sliding_trie_2]
# No regex filters - should accept all requests
`

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "sliding_regex_config.toml")

	err := os.WriteFile(configPath, []byte(testConfigContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	config, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Test sliding_trie_1 - should filter for scanner user agents and /admin/ endpoints
	slidingTrie1, exists := config.LiveTries["sliding_trie_1"]
	if !exists {
		t.Fatal("Expected sliding_trie_1 to exist")
	}

	testCases := []struct {
		name     string
		request  ingestor.Request
		expected bool
	}{
		{
			name: "scanner user agent and admin endpoint - should include",
			request: ingestor.Request{
				UserAgent: "nmap security scanner v7.80",
				URI:       "/admin/dashboard",
				IP:        net.ParseIP("1.2.3.4"),
			},
			expected: true,
		},
		{
			name: "scanner user agent but non-admin endpoint - should exclude",
			request: ingestor.Request{
				UserAgent: "nmap security scanner v7.80",
				URI:       "/public/info",
				IP:        net.ParseIP("1.2.3.4"),
			},
			expected: false,
		},
		{
			name: "non-scanner user agent but admin endpoint - should exclude",
			request: ingestor.Request{
				UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
				URI:       "/admin/dashboard",
				IP:        net.ParseIP("1.2.3.4"),
			},
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := slidingTrie1.ShouldIncludeRequest(tc.request)
			if result != tc.expected {
				t.Errorf("Expected %v, got %v for %s", tc.expected, result, tc.name)
			}
		})
	}

	// Test sliding_trie_2 - no regex filters, should accept all requests
	slidingTrie2, exists := config.LiveTries["sliding_trie_2"]
	if !exists {
		t.Fatal("Expected sliding_trie_2 to exist")
	}

	testRequest := ingestor.Request{
		UserAgent: "Any user agent",
		URI:       "/any/endpoint",
		IP:        net.ParseIP("1.2.3.4"),
	}

	if !slidingTrie2.ShouldIncludeRequest(testRequest) {
		t.Error("Expected sliding_trie_2 to accept all requests when no regex filters are specified")
	}
}

func TestInvalidRegexHandling(t *testing.T) {
	// Test that invalid useragent regex causes LoadConfig to return an error
	testConfigContent1 := `
[static.trie_1]
useragentRegex = "[invalid regex"
endpointRegex = "/api/.*"
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "invalid_ua_regex_config.toml")
	err := os.WriteFile(configPath, []byte(testConfigContent1), 0644)
	if err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	_, err = LoadConfig(configPath)
	if err == nil {
		t.Fatal("Expected LoadConfig to return error for invalid useragentRegex")
	}

	// Test that invalid endpoint regex causes LoadConfig to return an error
	testConfigContent2 := `
[static.trie_2]
useragentRegex = ".*valid.*"
endpointRegex = "*invalid regex"
`
	configPath2 := filepath.Join(tmpDir, "invalid_ep_regex_config.toml")
	err = os.WriteFile(configPath2, []byte(testConfigContent2), 0644)
	if err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	_, err = LoadConfig(configPath2)
	if err == nil {
		t.Fatal("Expected LoadConfig to return error for invalid endpointRegex")
	}

	// Test that valid regex still works fine
	testConfigContentValid := `
[static.trie_valid]
useragentRegex = ".*bot.*"
endpointRegex = "/api/.*"
`
	configPathValid := filepath.Join(tmpDir, "valid_regex_config.toml")
	err = os.WriteFile(configPathValid, []byte(testConfigContentValid), 0644)
	if err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	cfg, err := LoadConfig(configPathValid)
	if err != nil {
		t.Fatalf("Expected LoadConfig to succeed for valid regex, got: %v", err)
	}

	trieValid, exists := cfg.StaticTries["trie_valid"]
	if !exists {
		t.Fatal("Expected trie_valid to exist")
	}

	if trieValid.userAgentRegexCompiled == nil {
		t.Error("Expected valid useragent regex to be compiled")
	}
	if trieValid.endpointRegexCompiled == nil {
		t.Error("Expected valid endpoint regex to be compiled")
	}
}

func TestInvalidTimeFormatStoresRawValue(t *testing.T) {
	testConfigContent := `
[static.trie_1]
startTime = "2025-01-01T00:00:00"
endTime = "2025-12-31"
cidrRanges = ["192.168.1.0/24"]
clusterArgSets = [[100, 24, 32, 0.1]]
useForJail = [true]
`

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "invalid_time_config.toml")

	err := os.WriteFile(configPath, []byte(testConfigContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	config, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	trie1, exists := config.StaticTries["trie_1"]
	if !exists {
		t.Fatal("Expected trie_1 to exist")
	}

	// StartTime should be nil (parse failed) but StartTimeRaw should be set
	if trie1.StartTime != nil {
		t.Errorf("Expected StartTime to be nil for invalid format, got %v", trie1.StartTime)
	}
	if trie1.StartTimeRaw != "2025-01-01T00:00:00" {
		t.Errorf("Expected StartTimeRaw to be '2025-01-01T00:00:00', got '%s'", trie1.StartTimeRaw)
	}

	// EndTime should be nil (parse failed) but EndTimeRaw should be set
	if trie1.EndTime != nil {
		t.Errorf("Expected EndTime to be nil for invalid format, got %v", trie1.EndTime)
	}
	if trie1.EndTimeRaw != "2025-12-31" {
		t.Errorf("Expected EndTimeRaw to be '2025-12-31', got '%s'", trie1.EndTimeRaw)
	}
}

func TestValidTimeFormatDoesNotStoreRawValue(t *testing.T) {
	testConfigContent := `
[static.trie_1]
startTime = "2025-01-01T00:00:00Z"
endTime = "2025-12-31T23:59:59Z"
cidrRanges = ["192.168.1.0/24"]
clusterArgSets = [[100, 24, 32, 0.1]]
useForJail = [true]
`

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "valid_time_config.toml")

	err := os.WriteFile(configPath, []byte(testConfigContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	config, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	trie1, exists := config.StaticTries["trie_1"]
	if !exists {
		t.Fatal("Expected trie_1 to exist")
	}

	// StartTime should be set (parse succeeded) and StartTimeRaw should be empty
	if trie1.StartTime == nil {
		t.Error("Expected StartTime to be set for valid format, got nil")
	}
	if trie1.StartTimeRaw != "" {
		t.Errorf("Expected StartTimeRaw to be empty for valid format, got '%s'", trie1.StartTimeRaw)
	}

	// EndTime should be set (parse succeeded) and EndTimeRaw should be empty
	if trie1.EndTime == nil {
		t.Error("Expected EndTime to be set for valid format, got nil")
	}
	if trie1.EndTimeRaw != "" {
		t.Errorf("Expected EndTimeRaw to be empty for valid format, got '%s'", trie1.EndTimeRaw)
	}
}

func TestEmptyRegexHandling(t *testing.T) {
	testConfigContent := `
[static.trie_1]
useragentRegex = ""
endpointRegex = ""
`

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "empty_regex_config.toml")

	err := os.WriteFile(configPath, []byte(testConfigContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	config, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	trie1, exists := config.StaticTries["trie_1"]
	if !exists {
		t.Fatal("Expected trie_1 to exist")
	}

	// Empty regex strings should not be compiled
	if trie1.userAgentRegexCompiled != nil {
		t.Error("Expected empty useragent regex to not be compiled")
	}

	if trie1.endpointRegexCompiled != nil {
		t.Error("Expected empty endpoint regex to not be compiled")
	}

	// Should accept all requests when no regex filters are compiled
	testRequest := ingestor.Request{
		UserAgent: "Any user agent",
		URI:       "/any/endpoint",
		IP:        net.ParseIP("1.2.3.4"),
	}

	if !trie1.ShouldIncludeRequest(testRequest) {
		t.Error("Expected trie_1 to accept all requests when regex filters are empty")
	}
}

func TestCompileRegex(t *testing.T) {
	t.Run("valid regex compiles", func(t *testing.T) {
		tc := &TrieConfig{
			UserAgentRegex: ".*bot.*",
			EndpointRegex:  "/api/.*",
		}
		if err := tc.CompileRegex(); err != nil {
			t.Fatalf("CompileRegex failed: %v", err)
		}
		req := ingestor.Request{UserAgent: "Googlebot", URI: "/api/users", IP: net.ParseIP("1.2.3.4")}
		if !tc.ShouldIncludeRequest(req) {
			t.Error("Expected matching request to be included")
		}
		req2 := ingestor.Request{UserAgent: "Mozilla", URI: "/home", IP: net.ParseIP("1.2.3.4")}
		if tc.ShouldIncludeRequest(req2) {
			t.Error("Expected non-matching request to be excluded")
		}
	})

	t.Run("invalid regex returns error", func(t *testing.T) {
		tc := &TrieConfig{UserAgentRegex: "[invalid"}
		if err := tc.CompileRegex(); err == nil {
			t.Error("Expected error for invalid regex")
		}
	})

	t.Run("empty regex is no-op", func(t *testing.T) {
		tc := &TrieConfig{}
		if err := tc.CompileRegex(); err != nil {
			t.Fatalf("CompileRegex failed on empty: %v", err)
		}
		req := ingestor.Request{UserAgent: "anything", URI: "/any", IP: net.ParseIP("1.2.3.4")}
		if !tc.ShouldIncludeRequest(req) {
			t.Error("Expected all requests accepted with no regex")
		}
	})

	t.Run("sliding trie config compiles", func(t *testing.T) {
		stc := &SlidingTrieConfig{
			UserAgentRegex: ".*scanner.*",
			EndpointRegex:  "/admin/.*",
		}
		if err := stc.CompileRegex(); err != nil {
			t.Fatalf("CompileRegex failed: %v", err)
		}
		req := ingestor.Request{UserAgent: "nmap scanner", URI: "/admin/panel", IP: net.ParseIP("1.2.3.4")}
		if !stc.ShouldIncludeRequest(req) {
			t.Error("Expected matching request to be included")
		}
	})
}

func TestParseClusterArgSetsFromStrings(t *testing.T) {
	t.Run("valid single set", func(t *testing.T) {
		sets, err := ParseClusterArgSetsFromStrings([]string{"1000", "24", "32", "0.1"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(sets) != 1 {
			t.Fatalf("expected 1 set, got %d", len(sets))
		}
		if sets[0].MinClusterSize != 1000 || sets[0].MinDepth != 24 || sets[0].MaxDepth != 32 {
			t.Errorf("unexpected values: %+v", sets[0])
		}
	})

	t.Run("valid multiple sets", func(t *testing.T) {
		sets, err := ParseClusterArgSetsFromStrings([]string{
			"1000", "24", "32", "0.1",
			"500", "16", "24", "0.2",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(sets) != 2 {
			t.Fatalf("expected 2 sets, got %d", len(sets))
		}
	})

	t.Run("empty returns nil", func(t *testing.T) {
		sets, err := ParseClusterArgSetsFromStrings(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if sets != nil {
			t.Errorf("expected nil, got %v", sets)
		}
	})

	t.Run("not multiple of 4 fails", func(t *testing.T) {
		_, err := ParseClusterArgSetsFromStrings([]string{"1000", "24", "32"})
		if err == nil {
			t.Error("expected error for incomplete set")
		}
	})

	t.Run("invalid number fails", func(t *testing.T) {
		_, err := ParseClusterArgSetsFromStrings([]string{"abc", "24", "32", "0.1"})
		if err == nil {
			t.Error("expected error for non-numeric value")
		}
	})

	t.Run("minDepth > maxDepth fails", func(t *testing.T) {
		_, err := ParseClusterArgSetsFromStrings([]string{"1000", "32", "24", "0.1"})
		if err == nil {
			t.Error("expected error when minDepth > maxDepth")
		}
	})

	t.Run("minDepth equals maxDepth succeeds", func(t *testing.T) {
		sets, err := ParseClusterArgSetsFromStrings([]string{"1000", "24", "24", "0.1"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(sets) != 1 {
			t.Fatalf("expected 1 set, got %d", len(sets))
		}
		if sets[0].MinDepth != 24 || sets[0].MaxDepth != 24 {
			t.Errorf("expected min=max=24, got min=%d max=%d", sets[0].MinDepth, sets[0].MaxDepth)
		}
	})

	t.Run("invalid minDepth fails", func(t *testing.T) {
		_, err := ParseClusterArgSetsFromStrings([]string{"1000", "xyz", "32", "0.1"})
		if err == nil {
			t.Error("expected error for non-numeric minDepth")
		}
	})

	t.Run("invalid maxDepth fails", func(t *testing.T) {
		_, err := ParseClusterArgSetsFromStrings([]string{"1000", "24", "xyz", "0.1"})
		if err == nil {
			t.Error("expected error for non-numeric maxDepth")
		}
	})

	t.Run("invalid meanSubnetDiff fails", func(t *testing.T) {
		_, err := ParseClusterArgSetsFromStrings([]string{"1000", "24", "32", "notanumber"})
		if err == nil {
			t.Error("expected error for non-numeric meanSubnetDifference")
		}
	})
}

func TestConfig_WhitelistBlacklistPaths(t *testing.T) {
	testConfigContent := `
[global]
whitelist = "/path/to/whitelist.txt"
blacklist = "/path/to/blacklist.txt"
userAgentWhitelist = "/path/to/ua_whitelist.txt"
userAgentBlacklist = "/path/to/ua_blacklist.txt"
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "wl_bl_config.toml")
	if err := os.WriteFile(configPath, []byte(testConfigContent), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if cfg.Global.Whitelist != "/path/to/whitelist.txt" {
		t.Errorf("Expected Whitelist '/path/to/whitelist.txt', got %q", cfg.Global.Whitelist)
	}
	if cfg.Global.Blacklist != "/path/to/blacklist.txt" {
		t.Errorf("Expected Blacklist '/path/to/blacklist.txt', got %q", cfg.Global.Blacklist)
	}
	if cfg.Global.UserAgentWhitelist != "/path/to/ua_whitelist.txt" {
		t.Errorf("Expected UserAgentWhitelist '/path/to/ua_whitelist.txt', got %q", cfg.Global.UserAgentWhitelist)
	}
	if cfg.Global.UserAgentBlacklist != "/path/to/ua_blacklist.txt" {
		t.Errorf("Expected UserAgentBlacklist '/path/to/ua_blacklist.txt', got %q", cfg.Global.UserAgentBlacklist)
	}
}

func TestConfig_LoadWhitelistEmptyPaths(t *testing.T) {
	cfg := &Config{Global: &GlobalConfig{}}

	cidrs, err := cfg.LoadWhitelistCIDRs()
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
	if cidrs != nil {
		t.Errorf("Expected nil, got %v", cidrs)
	}

	cidrs, err = cfg.LoadBlacklistCIDRs()
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
	if cidrs != nil {
		t.Errorf("Expected nil, got %v", cidrs)
	}

	patterns, err := cfg.LoadUserAgentWhitelistPatterns()
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
	if patterns != nil {
		t.Errorf("Expected nil, got %v", patterns)
	}

	patterns, err = cfg.LoadUserAgentBlacklistPatterns()
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
	if patterns != nil {
		t.Errorf("Expected nil, got %v", patterns)
	}
}

func TestConfig_LoadWhitelistNilGlobal(t *testing.T) {
	cfg := &Config{Global: nil}

	cidrs, err := cfg.LoadWhitelistCIDRs()
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
	if cidrs != nil {
		t.Errorf("Expected nil, got %v", cidrs)
	}

	cidrs, err = cfg.LoadBlacklistCIDRs()
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
	if cidrs != nil {
		t.Errorf("Expected nil, got %v", cidrs)
	}
}

func TestConfig_LoadCIDRFileWithComments(t *testing.T) {
	tmpDir := t.TempDir()
	cidrFile := filepath.Join(tmpDir, "cidrs.txt")

	content := "# Comment line\n\n192.168.1.0/24\n  # Another comment  \n10.0.0.0/8\n\n172.16.0.0/12\n"
	if err := os.WriteFile(cidrFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{Global: &GlobalConfig{Whitelist: cidrFile}}
	cidrs, err := cfg.LoadWhitelistCIDRs()
	if err != nil {
		t.Fatalf("LoadWhitelistCIDRs failed: %v", err)
	}

	expected := []string{"192.168.1.0/24", "10.0.0.0/8", "172.16.0.0/12"}
	if len(cidrs) != len(expected) {
		t.Fatalf("Expected %d CIDRs, got %d", len(expected), len(cidrs))
	}
	for i, cidr := range cidrs {
		if cidr != expected[i] {
			t.Errorf("CIDR[%d] = %q, want %q", i, cidr, expected[i])
		}
	}
}

func TestConfig_LoadCIDRFileInvalidCIDR(t *testing.T) {
	tmpDir := t.TempDir()
	cidrFile := filepath.Join(tmpDir, "bad_cidrs.txt")

	content := "192.168.1.0/24\nnot-a-cidr\n10.0.0.0/8\n"
	if err := os.WriteFile(cidrFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{Global: &GlobalConfig{Whitelist: cidrFile}}
	_, err := cfg.LoadWhitelistCIDRs()
	if err == nil {
		t.Error("Expected error for invalid CIDR, got nil")
	}
}

func TestConfig_LoadWhitelistNonexistentFile(t *testing.T) {
	cfg := &Config{Global: &GlobalConfig{Whitelist: "/nonexistent/file.txt"}}
	_, err := cfg.LoadWhitelistCIDRs()
	if err == nil {
		t.Error("Expected error for nonexistent file, got nil")
	}
}

func writeTestConfig(t *testing.T, content string) string {
	t.Helper()
	configPath := filepath.Join(t.TempDir(), "test_config.toml")
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to write test config file: %v", err)
	}
	return configPath
}

func TestLoadConfig_LiveReadTimeout(t *testing.T) {
	configPath := writeTestConfig(t, `
[live]
port = "8080"
readTimeout = "250ms"

[live.window_1]
slidingWindowMaxTime = "1h"
slidingWindowMaxSize = 100
sleepBetweenIterations = 1
clusterArgSets = [[100, 24, 32, 0.5]]
useForJail = [true]
`)

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}
	if cfg.Live.ReadTimeout != 250*time.Millisecond {
		t.Errorf("Expected Live.ReadTimeout 250ms, got %v", cfg.Live.ReadTimeout)
	}
	if got := cfg.GetReadTimeout(); got != 250*time.Millisecond {
		t.Errorf("Expected GetReadTimeout() 250ms, got %v", got)
	}
	// readTimeout must be treated as a live config key, not a trie section.
	if len(cfg.LiveTries) != 1 {
		t.Errorf("Expected 1 live trie, got %d", len(cfg.LiveTries))
	}
}

func TestGetReadTimeout_DefaultWhenUnset(t *testing.T) {
	configPath := writeTestConfig(t, `
[live]
port = "8080"
`)

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}
	if got := cfg.GetReadTimeout(); got != DefaultLiveReadTimeout {
		t.Errorf("Expected default read timeout %v, got %v", DefaultLiveReadTimeout, got)
	}

	// Nil Live section also falls back to the default.
	empty := &Config{}
	if got := empty.GetReadTimeout(); got != DefaultLiveReadTimeout {
		t.Errorf("Expected default read timeout %v for nil Live, got %v", DefaultLiveReadTimeout, got)
	}
}

func TestLoadConfig_InvalidReadTimeout(t *testing.T) {
	configPath := writeTestConfig(t, `
[live]
port = "8080"
readTimeout = "bogus"
`)

	_, err := LoadConfig(configPath)
	if err == nil {
		t.Fatal("Expected error for invalid readTimeout, got nil")
	}
	if !strings.Contains(err.Error(), "readTimeout") {
		t.Errorf("Expected error mentioning readTimeout, got: %v", err)
	}
}
