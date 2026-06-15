package testutil

import (
	"os"
	"strings"
	"testing"
)

// GenerateTestLogFile creates a temporary Apache Combined Log format file
// with fictional log entries for testing purposes.
// Returns the file path and a cleanup function.
func GenerateTestLogFile(t *testing.T, numLines int) (string, func()) {
	t.Helper()

	// Ensure at least 1000 lines
	if numLines < 1000 {
		numLines = 1000
	}

	tmpFile, err := os.CreateTemp("", "test_access_*.log")
	if err != nil {
		t.Fatalf("Failed to create temp log file: %v", err)
	}

	// Fictional sample log lines with diverse IP addresses and patterns
	sampleLines := []string{
		`192.168.1.100 - - [01/Jan/2025:10:15:30 +0000] "GET /api/users HTTP/1.1" 200 1024 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" "10.0.0.1"`,
		`172.16.45.67 - - [01/Jan/2025:10:15:31 +0000] "POST /api/login HTTP/1.1" 401 512 "-" "curl/7.68.0" "172.16.45.67"`,
		`10.20.30.40 - - [01/Jan/2025:10:15:32 +0000] "GET /static/logo.png HTTP/1.1" 200 8192 "https://example.com/" "Mozilla/5.0 (X11; Linux x86_64)" "10.20.30.40"`,
		`203.0.113.25 - admin [01/Jan/2025:10:15:33 +0000] "DELETE /api/cache HTTP/1.1" 204 0 "-" "AdminTool/2.0" "203.0.113.25"`,
		`198.51.100.88 - - [01/Jan/2025:10:15:34 +0000] "GET /dataset/?limit=100&offset=50 HTTP/1.1" 200 45678 "-" "Python-requests/2.28" "198.51.100.88"`,
		`192.0.2.150 - - [01/Jan/2025:10:15:35 +0000] "HEAD /robots.txt HTTP/1.1" 404 0 "-" "Googlebot/2.1" "192.0.2.150"`,
		`10.0.100.200 - user [01/Jan/2025:10:15:36 +0000] "PUT /api/profile/123 HTTP/1.1" 200 2048 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X)" "10.0.100.200"`,
		`172.31.255.1 - - [01/Jan/2025:10:15:37 +0000] "GET /health HTTP/1.1" 200 128 "-" "HealthChecker/1.0" "172.31.255.1"`,
		`10.50.75.90 - - [01/Jan/2025:10:15:38 +0000] "OPTIONS /api/cors HTTP/1.1" 200 0 "-" "Mozilla/5.0 (iPhone; CPU iPhone OS)" "10.50.75.90"`,
		`192.168.200.50 - - [01/Jan/2025:10:15:39 +0000] "GET /api/search?q=test&page=1 HTTP/1.1" 200 32768 "-" "Mozilla/5.0 (Android)" "192.168.200.50"`,
	}

	var content strings.Builder
	for i := 0; i < numLines; i++ {
		// Cycle through sample lines to create variety
		content.WriteString(sampleLines[i%len(sampleLines)])
		content.WriteString("\n")
	}

	if _, err := tmpFile.WriteString(content.String()); err != nil {
		t.Fatalf("Failed to write to temp log file: %v", err)
	}

	tmpFile.Close()

	cleanup := func() {
		os.Remove(tmpFile.Name())
	}

	return tmpFile.Name(), cleanup
}

// TempFilePath returns a cross-platform temporary file path
// with the given pattern. Does not create the file.
func TempFilePath(t *testing.T, pattern string) string {
	t.Helper()

	tmpFile, err := os.CreateTemp("", pattern)
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	path := tmpFile.Name()
	tmpFile.Close()
	os.Remove(path) // Remove immediately, just need the path

	return path
}

// TempDirPath returns a cross-platform temporary directory path
func TempDirPath(t *testing.T) string {
	t.Helper()
	return t.TempDir()
}
