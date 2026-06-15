package cli

import (
	"bytes"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ChristianF88/flokbn/iputils"
)

func TestParseFlexibleTime(t *testing.T) {
	tests := []struct {
		input   string
		want    time.Time
		wantErr bool
	}{
		{
			input:   "2024-06-01 13:45",
			want:    time.Date(2024, 6, 1, 13, 45, 0, 0, time.UTC),
			wantErr: false,
		},
		{
			input:   "2024-06-01 13",
			want:    time.Date(2024, 6, 1, 13, 0, 0, 0, time.UTC),
			wantErr: false,
		},
		{
			input:   "2024-06-01",
			want:    time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC),
			wantErr: false,
		},
		{
			input:   "2024/06/01",
			wantErr: true,
		},
		{
			input:   "2024-06-01 13:45:00",
			wantErr: true,
		},
		{
			input:   "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		got, err := parseFlexibleTime(tt.input)
		if tt.wantErr {
			if err == nil {
				t.Errorf("parseFlexibleTime(%q) expected error, got nil", tt.input)
			}
		} else {
			if err != nil {
				t.Errorf("parseFlexibleTime(%q) unexpected error: %v", tt.input, err)
			} else {
				// Compare time in UTC for consistency
				got = got.UTC()
				if !got.Equal(tt.want) {
					t.Errorf("parseFlexibleTime(%q) = %v, want %v", tt.input, got, tt.want)
				}
			}
		}
	}
}

func TestCIDRValidation(t *testing.T) {
	tests := []struct {
		name     string
		cidrs    []string
		expected bool
	}{
		{
			name:     "Valid IPv4 CIDR",
			cidrs:    []string{"192.168.1.0/24"},
			expected: true,
		},
		{
			name:     "Valid IPv6 CIDR",
			cidrs:    []string{"2001:db8::/32"},
			expected: true,
		},
		{
			name:     "Multiple valid CIDRs",
			cidrs:    []string{"192.168.1.0/24", "10.0.0.0/8", "172.16.0.0/12"},
			expected: true,
		},
		{
			name:     "Invalid CIDR format",
			cidrs:    []string{"192.168.1.0/33"},
			expected: false,
		},
		{
			name:     "Invalid IP address",
			cidrs:    []string{"256.256.256.256/24"},
			expected: false,
		},
		{
			name:     "Missing subnet mask",
			cidrs:    []string{"192.168.1.0"},
			expected: true, // IsValidCidrOrIp accepts individual IPs
		},
		{
			name:     "Mixed valid and invalid",
			cidrs:    []string{"192.168.1.0/24", "invalid-cidr"},
			expected: false,
		},
		{
			name:     "Empty string",
			cidrs:    []string{""},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allValid := true
			for _, cidr := range tt.cidrs {
				if !iputils.IsValidCidrOrIP(cidr) {
					allValid = false
					break
				}
			}
			if allValid != tt.expected {
				t.Errorf("CIDR validation for %v = %v, want %v", tt.cidrs, allValid, tt.expected)
			}
		})
	}
}

func TestStaticCommandValidation(t *testing.T) {
	// Create a temporary test log file
	tmpFile, err := os.CreateTemp("", "test_log_*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	// Write some test data
	tmpFile.WriteString("2024-01-01 12:00:00 192.168.1.1\n")
	tmpFile.Close()

	tests := []struct {
		name        string
		args        []string
		expectError bool
		errorMatch  string
	}{
		{
			name: "Valid static command with CIDR",
			args: []string{"flokbn", "static",
				"--logfile", tmpFile.Name(),
				"--clusterArgSets", "1000,24,32,0.2",
				"--rangesCidr", "192.168.1.0/24"},
			expectError: false,
		},
		{
			name: "Multiple valid CIDRs",
			args: []string{"flokbn", "static",
				"--logfile", tmpFile.Name(),
				"--clusterArgSets", "1000,24,32,0.2",
				"--rangesCidr", "192.168.1.0/24",
				"--rangesCidr", "10.0.0.0/8"},
			expectError: false,
		},
		{
			name: "Invalid CIDR range",
			args: []string{"flokbn", "static",
				"--logfile", tmpFile.Name(),
				"--clusterArgSets", "1000,24,32,0.2",
				"--rangesCidr", "192.168.1.0/33"},
			expectError: true,
			errorMatch:  "invalid CIDR range",
		},
		{
			name: "Missing log file",
			args: []string{"flokbn", "static",
				"--logfile", "/nonexistent/file.log",
				"--clusterArgSets", "1000,24,32,0.2"},
			expectError: true,
			errorMatch:  "does not exist",
		},
		{
			name: "Invalid cluster argument sets",
			args: []string{"flokbn", "static",
				"--logfile", tmpFile.Name(),
				"--clusterArgSets", "1000,24,32"},
			expectError: true,
			errorMatch:  "invalid cluster argument sets",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Capture output
			oldStdout := os.Stdout
			oldStderr := os.Stderr
			r, w, _ := os.Pipe()
			os.Stdout = w
			os.Stderr = w

			// Note: We should not reset flag.CommandLine as it interferes with benchmark tests
			// Instead, we'll work with the existing command line state

			var capturedOutput bytes.Buffer
			done := make(chan bool)
			go func() {
				buf := make([]byte, 1024)
				for {
					n, err := r.Read(buf)
					if err != nil {
						break
					}
					capturedOutput.Write(buf[:n])
				}
				done <- true
			}()

			// Run the CLI command
			err := App.Run(tt.args)

			// Restore output
			w.Close()
			os.Stdout = oldStdout
			os.Stderr = oldStderr
			<-done

			output := capturedOutput.String()

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none. Output: %s", output)
				} else if tt.errorMatch != "" && !strings.Contains(err.Error(), tt.errorMatch) && !strings.Contains(output, tt.errorMatch) {
					t.Errorf("Expected error to contain '%s', got: %v. Output: %s", tt.errorMatch, err, output)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v. Output: %s", err, output)
				}
			}
		})
	}
}

func TestCLIFlags(t *testing.T) {
	// Test that all expected flags are present
	staticCmd := App.Commands[1] // static command is second

	expectedFlags := []string{"logfile", "logFormat", "startTime", "endTime", "useragentRegex",
		"endpointRegex", "clusterArgSets", "rangesCidr"}

	for _, expectedFlag := range expectedFlags {
		found := false
		for _, flag := range staticCmd.Flags {
			if flag.Names()[0] == expectedFlag {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected flag '%s' not found in static command", expectedFlag)
		}
	}
}

// TestEnhancedCLIArguments tests the new CLI arguments for feature parity with config mode
func TestEnhancedCLIArguments(t *testing.T) {
	// Create a temporary log file for testing
	tmpFile, err := os.CreateTemp("", "test_log_*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	// Write sample log data
	sampleLog := `127.0.0.1 - - [01/Jan/2024:12:00:00 +0000] "GET /api/test HTTP/1.1" 200 1024 "-" "Mozilla/5.0 (compatible; bot)"
192.168.1.100 - - [01/Jan/2024:12:01:00 +0000] "POST /admin/login HTTP/1.1" 200 512 "-" "curl/7.68.0"`
	tmpFile.WriteString(sampleLog)
	tmpFile.Close()

	tests := []struct {
		name        string
		args        []string
		expectError bool
		errorMatch  string
	}{
		{
			name: "User agent regex filter",
			args: []string{"flokbn", "static",
				"--logfile", tmpFile.Name(),
				"--useragentRegex", ".*bot.*",
				"--clusterArgSets", "1,1,32,0.1"},
			expectError: false,
		},
		{
			name: "Endpoint regex filter",
			args: []string{"flokbn", "static",
				"--logfile", tmpFile.Name(),
				"--endpointRegex", "/api/.*",
				"--clusterArgSets", "1,1,32,0.1"},
			expectError: false,
		},
		{
			name: "Custom log format",
			args: []string{"flokbn", "static",
				"--logfile", tmpFile.Name(),
				"--logFormat", "%h %^ %^ [%t] \"%r\" %s %b %^ \"%u\"",
				"--clusterArgSets", "1,1,32,0.1"},
			expectError: false,
		},
		{
			name: "Invalid user agent regex",
			args: []string{"flokbn", "static",
				"--logfile", tmpFile.Name(),
				"--useragentRegex", "[invalid",
				"--clusterArgSets", "1,1,32,0.1"},
			expectError: true,
			errorMatch:  "invalid useragentRegex pattern",
		},
		{
			name: "Invalid endpoint regex",
			args: []string{"flokbn", "static",
				"--logfile", tmpFile.Name(),
				"--endpointRegex", "*invalid",
				"--clusterArgSets", "1,1,32,0.1"},
			expectError: true,
			errorMatch:  "invalid endpointRegex pattern",
		},
		{
			name: "Combined filters and time range",
			args: []string{"flokbn", "static",
				"--logfile", tmpFile.Name(),
				"--useragentRegex", ".*Mozilla.*",
				"--endpointRegex", "/api/.*",
				"--startTime", "2024-01-01",
				"--endTime", "2024-12-31",
				"--clusterArgSets", "1,1,32,0.1"},
			expectError: false,
		},
		{
			name: "Plain output mode",
			args: []string{"flokbn", "static",
				"--logfile", tmpFile.Name(),
				"--clusterArgSets", "1,1,32,0.1",
				"--plain"},
			expectError: false,
		},
		{
			name: "Plain output with compact (should work)",
			args: []string{"flokbn", "static",
				"--logfile", tmpFile.Name(),
				"--clusterArgSets", "1,1,32,0.1",
				"--plain",
				"--compact"},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Capture output
			oldStdout := os.Stdout
			oldStderr := os.Stderr
			r, w, _ := os.Pipe()
			os.Stdout = w
			os.Stderr = w

			// Note: We should not reset flag.CommandLine as it interferes with benchmark tests
			// Instead, we'll work with the existing command line state

			var capturedOutput bytes.Buffer
			done := make(chan bool)
			go func() {
				buf := make([]byte, 1024)
				for {
					n, err := r.Read(buf)
					if err != nil {
						break
					}
					capturedOutput.Write(buf[:n])
				}
				done <- true
			}()

			// Run the CLI command
			err := App.Run(tt.args)

			// Restore output
			w.Close()
			os.Stdout = oldStdout
			os.Stderr = oldStderr
			<-done

			output := capturedOutput.String()

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none. Output: %s", output)
				} else if tt.errorMatch != "" && !strings.Contains(err.Error(), tt.errorMatch) && !strings.Contains(output, tt.errorMatch) {
					t.Errorf("Expected error to contain '%s', got: %v. Output: %s", tt.errorMatch, err, output)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v. Output: %s", err, output)
				}
			}
		})
	}
}

// TestRegexValidation tests the regex compilation validation
func TestRegexValidation(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		valid   bool
	}{
		{"Valid user agent regex", ".*bot.*", true},
		{"Valid endpoint regex", "/api/.*", true},
		{"Valid complex regex", "^(GET|POST).*", true},
		{"Invalid regex - unclosed bracket", "[invalid", false},
		{"Invalid regex - invalid quantifier", "*invalid", false},
		{"Empty regex", "", true}, // Empty should be valid (no filtering)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := regexp.Compile(tt.pattern)
			isValid := err == nil

			if isValid != tt.valid {
				t.Errorf("Pattern '%s' validity expected %v, got %v. Error: %v",
					tt.pattern, tt.valid, isValid, err)
			}
		})
	}
}
