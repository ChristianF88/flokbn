package analysis

import (
	"os"
	"path/filepath"
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
