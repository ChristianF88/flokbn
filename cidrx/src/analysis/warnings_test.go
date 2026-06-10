package analysis

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ChristianF88/cidrx/config"
)

func TestInvalidTimeFormatGeneratesWarning(t *testing.T) {
	// Create a temp directory for test files
	tmpDir := t.TempDir()

	// Create a minimal log file
	logFile := filepath.Join(tmpDir, "test.log")
	logContent := `192.168.1.1 - - [01/Jan/2025:00:00:00 +0000] "GET /test HTTP/1.1" 200 100 "-" "Mozilla/5.0" "192.168.1.1"
192.168.1.2 - - [01/Jan/2025:00:00:01 +0000] "GET /test HTTP/1.1" 200 100 "-" "Mozilla/5.0" "192.168.1.2"
`
	err := os.WriteFile(logFile, []byte(logContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create log file: %v", err)
	}

	// Create jail and ban files
	jailFile := filepath.Join(tmpDir, "jail.json")
	banFile := filepath.Join(tmpDir, "ban.txt")
	err = os.WriteFile(jailFile, []byte("{}"), 0644)
	if err != nil {
		t.Fatalf("Failed to create jail file: %v", err)
	}
	err = os.WriteFile(banFile, []byte(""), 0644)
	if err != nil {
		t.Fatalf("Failed to create ban file: %v", err)
	}

	// Create config with invalid time format (missing Z)
	cfg := &config.Config{
		Global: &config.GlobalConfig{
			JailFile: jailFile,
			BanFile:  banFile,
		},
		Static: &config.StaticConfig{
			LogFile:   logFile,
			LogFormat: "%h %^ %^ [%t] \"%r\" %s %b %^ \"%u\" \"%^\"",
		},
		StaticTries: map[string]*config.TrieConfig{
			"test_trie": {
				StartTimeRaw: "2025-01-01T00:00:00", // Invalid - missing Z
				// StartTime is nil because parsing failed
			},
		},
	}

	// Run analysis
	result, err := ParallelStaticFromConfigNoRequests(cfg)
	if err != nil {
		t.Fatalf("Analysis failed: %v", err)
	}

	// Check for warning
	foundWarning := false
	for _, warning := range result.Warnings {
		if warning.Type == "invalid_time_format" {
			foundWarning = true
			t.Logf("Found expected warning: %s", warning.Message)
			break
		}
	}

	if !foundWarning {
		t.Errorf("Expected warning for invalid time format, but none found. Warnings: %+v", result.Warnings)
	}
}

func TestEndTimeBeforeStartTimeGeneratesWarning(t *testing.T) {
	// Create a temp directory for test files
	tmpDir := t.TempDir()

	// Create a minimal log file
	logFile := filepath.Join(tmpDir, "test.log")
	logContent := `192.168.1.1 - - [01/Jan/2025:00:00:00 +0000] "GET /test HTTP/1.1" 200 100 "-" "Mozilla/5.0" "192.168.1.1"
`
	err := os.WriteFile(logFile, []byte(logContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create log file: %v", err)
	}

	// Create jail and ban files
	jailFile := filepath.Join(tmpDir, "jail.json")
	banFile := filepath.Join(tmpDir, "ban.txt")
	err = os.WriteFile(jailFile, []byte("{}"), 0644)
	if err != nil {
		t.Fatalf("Failed to create jail file: %v", err)
	}
	err = os.WriteFile(banFile, []byte(""), 0644)
	if err != nil {
		t.Fatalf("Failed to create ban file: %v", err)
	}

	// Load config with endTime BEFORE startTime (invalid)
	configContent := `
[global]
jailFile = "` + jailFile + `"
banFile = "` + banFile + `"

[static]
logFile = "` + logFile + `"
logFormat = "%h %^ %^ [%t] \"%r\" %s %b %^ \"%u\" \"%^\""

[static.test_trie]
startTime = "2025-01-15T00:00:00Z"
endTime = "2025-01-01T00:00:00Z"
`
	configFile := filepath.Join(tmpDir, "config.toml")
	err = os.WriteFile(configFile, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create config file: %v", err)
	}

	cfg, err := config.LoadConfig(configFile)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Run analysis
	result, err := ParallelStaticFromConfigNoRequests(cfg)
	if err != nil {
		t.Fatalf("Analysis failed: %v", err)
	}

	// Check for warning about invalid time range
	foundWarning := false
	for _, warning := range result.Warnings {
		if warning.Type == "invalid_time_range" {
			foundWarning = true
			t.Logf("Found expected warning: %s", warning.Message)
			break
		}
	}

	if !foundWarning {
		t.Errorf("Expected warning for endTime before startTime, but none found. Warnings: %+v", result.Warnings)
	}
}

func TestNonOverlappingTimeRangeGeneratesWarning(t *testing.T) {
	// Create a temp directory for test files
	tmpDir := t.TempDir()

	// Create a log file with data from January 2025
	logFile := filepath.Join(tmpDir, "test.log")
	logContent := `192.168.1.1 - - [01/Jan/2025:00:00:00 +0000] "GET /test HTTP/1.1" 200 100 "-" "Mozilla/5.0" "192.168.1.1"
192.168.1.2 - - [01/Jan/2025:00:00:01 +0000] "GET /test HTTP/1.1" 200 100 "-" "Mozilla/5.0" "192.168.1.2"
`
	err := os.WriteFile(logFile, []byte(logContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create log file: %v", err)
	}

	// Create jail and ban files
	jailFile := filepath.Join(tmpDir, "jail.json")
	banFile := filepath.Join(tmpDir, "ban.txt")
	err = os.WriteFile(jailFile, []byte("{}"), 0644)
	if err != nil {
		t.Fatalf("Failed to create jail file: %v", err)
	}
	err = os.WriteFile(banFile, []byte(""), 0644)
	if err != nil {
		t.Fatalf("Failed to create ban file: %v", err)
	}

	// Load config with time filter that doesn't overlap with log data (November 2025)
	configContent := `
[global]
jailFile = "` + jailFile + `"
banFile = "` + banFile + `"

[static]
logFile = "` + logFile + `"
logFormat = "%h %^ %^ [%t] \"%r\" %s %b %^ \"%u\" \"%^\""

[static.test_trie]
startTime = "2025-11-13T00:00:00Z"
endTime = "2025-11-13T06:00:00Z"
`
	configFile := filepath.Join(tmpDir, "config.toml")
	err = os.WriteFile(configFile, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create config file: %v", err)
	}

	cfg, err := config.LoadConfig(configFile)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Run analysis
	result, err := ParallelStaticFromConfigNoRequests(cfg)
	if err != nil {
		t.Fatalf("Analysis failed: %v", err)
	}

	// Check for warning about non-overlapping time range
	foundWarning := false
	for _, warning := range result.Warnings {
		if warning.Type == "time_filter_no_results" {
			foundWarning = true
			t.Logf("Found expected warning: %s", warning.Message)
			break
		}
	}

	if !foundWarning {
		t.Errorf("Expected warning for non-overlapping time range, but none found. Warnings: %+v", result.Warnings)
	}
}

// malformedFieldTestEnv writes a log fixture (2 bad-status "2XX" lines, 1
// bad-bytes "garbage" line, 2 clean lines) plus jail/ban files and returns a
// config-builder for it. CIDRX-039.
func malformedFieldTestEnv(t *testing.T) (logFile, jailFile, banFile string) {
	t.Helper()
	tmpDir := t.TempDir()

	logFile = filepath.Join(tmpDir, "test.log")
	logContent := `192.168.1.1 - - [01/Jan/2025:00:00:00 +0000] "GET /a HTTP/1.1" 200 100 "-" "Mozilla/5.0" "192.168.1.1"
192.168.1.2 - - [01/Jan/2025:00:00:01 +0000] "GET /b HTTP/1.1" 2XX 100 "-" "Mozilla/5.0" "192.168.1.2"
192.168.1.3 - - [01/Jan/2025:00:00:02 +0000] "GET /c HTTP/1.1" 2XX 100 "-" "Mozilla/5.0" "192.168.1.3"
192.168.1.4 - - [01/Jan/2025:00:00:03 +0000] "GET /d HTTP/1.1" 200 12ab "-" "Mozilla/5.0" "192.168.1.4"
192.168.1.5 - - [01/Jan/2025:00:00:04 +0000] "GET /e HTTP/1.1" 200 100 "-" "Mozilla/5.0" "192.168.1.5"
`
	if err := os.WriteFile(logFile, []byte(logContent), 0644); err != nil {
		t.Fatalf("Failed to create log file: %v", err)
	}

	jailFile = filepath.Join(tmpDir, "jail.json")
	banFile = filepath.Join(tmpDir, "ban.txt")
	if err := os.WriteFile(jailFile, []byte("{}"), 0644); err != nil {
		t.Fatalf("Failed to create jail file: %v", err)
	}
	if err := os.WriteFile(banFile, []byte(""), 0644); err != nil {
		t.Fatalf("Failed to create ban file: %v", err)
	}
	return logFile, jailFile, banFile
}

func loadMalformedFieldConfig(t *testing.T, logFile, jailFile, banFile string, withTimeFilter bool) *config.Config {
	t.Helper()
	timeFilter := ""
	if withTimeFilter {
		// A StartTime filter forces needsNonIPFields=true, so status/bytes are
		// actually parsed and malformed fields get counted.
		timeFilter = `startTime = "2025-01-01T00:00:00Z"`
	}
	configContent := `
[global]
jailFile = "` + jailFile + `"
banFile = "` + banFile + `"

[static]
logFile = "` + logFile + `"
logFormat = "%h %^ %^ [%t] \"%r\" %s %b %^ \"%u\" \"%^\""

[static.test_trie]
` + timeFilter + `
`
	configFile := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(configFile, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to create config file: %v", err)
	}
	cfg, err := config.LoadConfig(configFile)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}
	return cfg
}

// TestMalformedFieldGeneratesWarning asserts that with a time filter (which
// enables non-IP field parsing) malformed status/bytes fields surface as
// aggregated `malformed_field` warnings, and that the pure IP-only path
// (no filters) structurally produces NO such warning.
func TestMalformedFieldGeneratesWarning(t *testing.T) {
	logFile, jailFile, banFile := malformedFieldTestEnv(t)

	// With time filter: status/bytes parsed -> warnings expected.
	cfg := loadMalformedFieldConfig(t, logFile, jailFile, banFile, true)
	result, err := ParallelStaticFromConfigNoRequests(cfg)
	if err != nil {
		t.Fatalf("Analysis failed: %v", err)
	}

	var statusWarning, bytesWarning bool
	for _, warning := range result.Warnings {
		if warning.Type != "malformed_field" {
			continue
		}
		if strings.Contains(warning.Message, "status field") {
			statusWarning = true
			if !strings.Contains(warning.Message, "2 requests") {
				t.Errorf("status warning should report 2 requests, got: %s", warning.Message)
			}
		}
		if strings.Contains(warning.Message, "bytes field") {
			bytesWarning = true
			if !strings.Contains(warning.Message, "1 requests") {
				t.Errorf("bytes warning should report 1 request, got: %s", warning.Message)
			}
		}
	}
	if !statusWarning {
		t.Errorf("Expected malformed_field warning for status, none found. Warnings: %+v", result.Warnings)
	}
	if !bytesWarning {
		t.Errorf("Expected malformed_field warning for bytes, none found. Warnings: %+v", result.Warnings)
	}

	jsonBytes, err := result.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON failed: %v", err)
	}
	if !strings.Contains(string(jsonBytes), "malformed_field") {
		t.Errorf("JSON output should contain malformed_field warning")
	}

	// Without any filter: IP-only fast path never scans status/bytes, so the
	// warning must NOT appear (counters are structurally zero).
	cfgNoFilter := loadMalformedFieldConfig(t, logFile, jailFile, banFile, false)
	resultNoFilter, err := ParallelStaticFromConfigNoRequests(cfgNoFilter)
	if err != nil {
		t.Fatalf("Analysis (no filter) failed: %v", err)
	}
	for _, warning := range resultNoFilter.Warnings {
		if warning.Type == "malformed_field" {
			t.Errorf("IP-only path must not emit malformed_field warning, got: %s", warning.Message)
		}
	}
}

// TestCleanLogNoMalformedFieldWarning asserts a clean log produces no
// malformed_field warning even when non-IP fields are parsed.
func TestCleanLogNoMalformedFieldWarning(t *testing.T) {
	tmpDir := t.TempDir()

	logFile := filepath.Join(tmpDir, "test.log")
	logContent := `192.168.1.1 - - [01/Jan/2025:00:00:00 +0000] "GET /a HTTP/1.1" 200 100 "-" "Mozilla/5.0" "192.168.1.1"
192.168.1.2 - - [01/Jan/2025:00:00:01 +0000] "GET /b HTTP/1.1" 404 - "-" "Mozilla/5.0" "192.168.1.2"
`
	if err := os.WriteFile(logFile, []byte(logContent), 0644); err != nil {
		t.Fatalf("Failed to create log file: %v", err)
	}
	jailFile := filepath.Join(tmpDir, "jail.json")
	banFile := filepath.Join(tmpDir, "ban.txt")
	if err := os.WriteFile(jailFile, []byte("{}"), 0644); err != nil {
		t.Fatalf("Failed to create jail file: %v", err)
	}
	if err := os.WriteFile(banFile, []byte(""), 0644); err != nil {
		t.Fatalf("Failed to create ban file: %v", err)
	}

	cfg := loadMalformedFieldConfig(t, logFile, jailFile, banFile, true)
	result, err := ParallelStaticFromConfigNoRequests(cfg)
	if err != nil {
		t.Fatalf("Analysis failed: %v", err)
	}
	for _, warning := range result.Warnings {
		if warning.Type == "malformed_field" {
			t.Errorf("Clean log must not emit malformed_field warning, got: %s", warning.Message)
		}
	}
}

func TestValidTimeFormatNoWarning(t *testing.T) {
	// Create a temp directory for test files
	tmpDir := t.TempDir()

	// Create a minimal log file
	logFile := filepath.Join(tmpDir, "test.log")
	logContent := `192.168.1.1 - - [01/Jan/2025:00:00:00 +0000] "GET /test HTTP/1.1" 200 100 "-" "Mozilla/5.0" "192.168.1.1"
`
	err := os.WriteFile(logFile, []byte(logContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create log file: %v", err)
	}

	// Create jail and ban files
	jailFile := filepath.Join(tmpDir, "jail.json")
	banFile := filepath.Join(tmpDir, "ban.txt")
	err = os.WriteFile(jailFile, []byte("{}"), 0644)
	if err != nil {
		t.Fatalf("Failed to create jail file: %v", err)
	}
	err = os.WriteFile(banFile, []byte(""), 0644)
	if err != nil {
		t.Fatalf("Failed to create ban file: %v", err)
	}

	// Load config with VALID time format
	configContent := `
[global]
jailFile = "` + jailFile + `"
banFile = "` + banFile + `"

[static]
logFile = "` + logFile + `"
logFormat = "%h %^ %^ [%t] \"%r\" %s %b %^ \"%u\" \"%^\""

[static.test_trie]
startTime = "2025-01-01T00:00:00Z"
`
	configFile := filepath.Join(tmpDir, "config.toml")
	err = os.WriteFile(configFile, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create config file: %v", err)
	}

	cfg, err := config.LoadConfig(configFile)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Run analysis
	result, err := ParallelStaticFromConfigNoRequests(cfg)
	if err != nil {
		t.Fatalf("Analysis failed: %v", err)
	}

	// Check that there's NO invalid_time_format warning
	for _, warning := range result.Warnings {
		if warning.Type == "invalid_time_format" {
			t.Errorf("Unexpected warning for valid time format: %s", warning.Message)
		}
	}
}
