package logparser

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ChristianF88/flokbn/ingestor"
	"github.com/ChristianF88/flokbn/testutil"
)

func ipStringToUint32(s string) uint32 {
	ip := net.ParseIP(s).To4()
	if ip == nil {
		return 0
	}
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

// parseLineForTest parses a single line into a fresh Request via the same
// compiled-format path the production file workers use (parseLineReuseOpt).
// It replaces the removed public ParseLine API for test purposes.
func parseLineForTest(p *Parser, line []byte) (*ingestor.Request, error) {
	req := &ingestor.Request{}
	if err := p.compiled.parseLineReuseOpt(line, req, p.SkipStringFields, p.SkipNonIPFields); err != nil {
		return nil, err
	}
	return req, nil
}

// Test data
var (
	apacheCombinedFormat = "%^ %^ %^ [%t] \"%r\" %s %b %^ \"%u\" \"%h\""
	testLogLine          = []byte(`198.51.10.21 - - [06/Jul/2025:19:57:26 +0000] "GET /dataset/?test HTTP/1.0" 200 13984 "-" "Mozilla/5.0" "14.191.169.89"`)
	customFormatLine     = []byte(`192.168.1.1 - - [10/Jul/2025:14:30:45 +0000] "GET /api/health HTTP/1.1" 200 1234 "-" "Mozilla/5.0" "10.0.0.100"`)

	// Additional test data for various formats
	nginxLogLine     = []byte(`10.0.0.1 - frank [10/Oct/2025:13:55:36 +0200] "POST /admin/login HTTP/1.1" 401 2326 "https://example.com/login" "curl/7.68.0" "10.0.0.1"`)
	minimalLogLine   = []byte(`203.0.113.45 - - [15/Nov/2025:08:30:12 +0000] "HEAD /robots.txt HTTP/1.1" 404 - "-" "-" "203.0.113.45"`)
	ipv6LogLine      = []byte(`2001:db8::1 - - [20/Dec/2025:16:45:22 +0000] "OPTIONS /api/cors HTTP/1.1" 200 0 "-" "Mozilla/5.0 (Windows NT 10.0)" "192.168.1.1"`)
	errorLogLine     = []byte(`172.16.0.100 - admin [25/Jan/2025:22:15:33 +0000] "GET /admin/dashboard?user=admin&filter=all HTTP/1.1" 500 1024 "https://admin.example.com/" "Mozilla/5.0 (X11; Linux x86_64)" "172.16.0.100"`)
	malformedLogLine = []byte(`badip - - [invalid-date] "INVALID" 999 NaN "malformed" "agent" "192.168.1.1"`)
	longUriLogLine   = []byte(`192.168.1.50 - - [05/Mar/2025:11:20:45 +0000] "GET /api/v1/search?q=test&limit=50&offset=100&sort=date&order=desc&format=json&include=metadata HTTP/1.1" 200 15000 "-" "APIClient/1.0" "192.168.1.50"`)

	// Test data for delimiter-based parsing (comma-separated IPs)
	drupalLogLine   = []byte(`189.115.84.87, 198.51.10.21 - - [18/Jul/2025:15:30:00 +0200] "GET /psi/islandora/search HTTP/1.1" 200 + 1466 25769 25108 0 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" id=- 17528454000884281609985 0 0 #9985`)
	drupalLogFormat = "%h, %^ %^ %^ [%t] \"%^ %r %^\" %s %^ %b %^ %^ %^ %^ \"%u\" %^ %^ %^ %^ %^ #%^"
)

func TestParser_BasicParsing(t *testing.T) {
	parser, err := NewParser(apacheCombinedFormat)
	if err != nil {
		t.Fatal(err)
	}

	req, err := parseLineForTest(parser, testLogLine)
	if err != nil {
		t.Fatal(err)
	}

	// Validate all fields were parsed correctly
	if req.IPUint32 == 0 {
		t.Error("IP should not be zero")
	}
	if req.IPUint32 != ipStringToUint32("14.191.169.89") {
		t.Errorf("Expected IP 14.191.169.89, got %s", ingestor.Uint32ToIPString(req.IPUint32))
	}

	if req.Timestamp.IsZero() {
		t.Error("Timestamp should not be zero")
	}
	expectedTime := time.Date(2025, 7, 6, 19, 57, 26, 0, time.UTC)
	if !req.Timestamp.Equal(expectedTime) {
		t.Errorf("Expected timestamp %v, got %v", expectedTime, req.Timestamp)
	}

	if req.Method != ingestor.GET {
		t.Errorf("Expected GET method, got %v", req.Method)
	}

	if req.URI != "/dataset/?test" {
		t.Errorf("Expected URI /dataset/?test, got %s", req.URI)
	}

	if req.Status != 200 {
		t.Errorf("Expected status 200, got %d", req.Status)
	}

	if req.Bytes != 13984 {
		t.Errorf("Expected bytes 13984, got %d", req.Bytes)
	}

	if req.UserAgent != "Mozilla/5.0" {
		t.Errorf("Expected user agent Mozilla/5.0, got %s", req.UserAgent)
	}
}

func TestParser_CustomFormat(t *testing.T) {
	parser, err := NewParser(apacheCombinedFormat)
	if err != nil {
		t.Fatal(err)
	}

	req, err := parseLineForTest(parser, customFormatLine)
	if err != nil {
		t.Fatal(err)
	}

	if req.IPUint32 != ipStringToUint32("10.0.0.100") {
		t.Errorf("Expected IP 10.0.0.100, got %s", ingestor.Uint32ToIPString(req.IPUint32))
	}

	if req.Method != ingestor.GET {
		t.Errorf("Expected method GET, got %v", req.Method)
	}

	if req.URI != "/api/health" {
		t.Errorf("Expected URI /api/health, got %s", req.URI)
	}

	if req.Status != 200 {
		t.Errorf("Expected status 200, got %d", req.Status)
	}

	if req.Bytes != 1234 {
		t.Errorf("Expected bytes 1234, got %d", req.Bytes)
	}
}

func TestParser_DelimiterParsing(t *testing.T) {
	parser, err := NewParser(drupalLogFormat)
	if err != nil {
		t.Fatal(err)
	}

	req, err := parseLineForTest(parser, drupalLogLine)
	if err != nil {
		t.Fatal(err)
	}

	// Validate that IP was parsed correctly (stopping at comma, not including it)
	if req.IPUint32 == 0 {
		t.Error("IP should not be zero")
	}
	if req.IPUint32 != ipStringToUint32("189.115.84.87") {
		t.Errorf("Expected IP 189.115.84.87, got %s", ingestor.Uint32ToIPString(req.IPUint32))
	}

	// Validate timestamp parsing
	if req.Timestamp.IsZero() {
		t.Error("Timestamp should not be zero")
	}

	// Validate URI parsing from quoted request field
	if req.URI != "/psi/islandora/search" {
		t.Errorf("Expected URI /psi/islandora/search, got %s", req.URI)
	}

	// Validate status code
	if req.Status != 200 {
		t.Errorf("Expected status 200, got %d", req.Status)
	}

	// Validate user agent parsing (in quotes)
	expectedUserAgent := "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
	if req.UserAgent != expectedUserAgent {
		t.Errorf("Expected user agent %s, got %s", expectedUserAgent, req.UserAgent)
	}
}

func TestParser_StandaloneURI(t *testing.T) {
	// Test format with standalone URI field - "%m %U" should be equivalent to "%r"
	standaloneFormat := "%h %^ %^ [%t] %m %U %^ %s %b \"%^\" \"%u\""
	testLogLine := []byte(`192.168.1.100 - - [10/Jul/2025:14:30:45 +0000] GET /api/health/check HTTP/1.1 200 1234 "-" "Mozilla/5.0"`)

	parser, err := NewParser(standaloneFormat)
	if err != nil {
		t.Fatal(err)
	}

	req, err := parseLineForTest(parser, testLogLine)
	if err != nil {
		t.Fatal(err)
	}

	// Validate all fields were parsed correctly
	if req.IPUint32 == 0 {
		t.Error("IP should not be zero")
	}
	if req.IPUint32 != ipStringToUint32("192.168.1.100") {
		t.Errorf("Expected IP 192.168.1.100, got %s", ingestor.Uint32ToIPString(req.IPUint32))
	}

	// Validate method parsing
	if req.Method != ingestor.GET {
		t.Errorf("Expected method GET, got %v", req.Method)
	}

	// Validate standalone URI parsing
	if req.URI != "/api/health/check" {
		t.Errorf("Expected URI /api/health/check, got %s", req.URI)
	}

	// Validate status code
	if req.Status != 200 {
		t.Errorf("Expected status 200, got %d", req.Status)
	}

	// Validate bytes
	if req.Bytes != 1234 {
		t.Errorf("Expected bytes 1234, got %d", req.Bytes)
	}

	// Validate user agent
	if req.UserAgent != "Mozilla/5.0" {
		t.Errorf("Expected user agent Mozilla/5.0, got %s", req.UserAgent)
	}
}

func TestParser_ComprehensiveFormats(t *testing.T) {
	tests := []struct {
		name           string
		format         string
		logLine        []byte
		expectedIP     string
		expectedMethod ingestor.HTTPMethod
		expectedURI    string
		expectedStatus uint16
		expectedBytes  uint32
		expectedUA     string
	}{
		{
			name:           "Apache Combined Log Format",
			format:         "%h %^ %^ [%t] \"%r\" %s %b \"%^\" \"%u\"",
			logLine:        []byte(`192.168.1.1 - - [10/Oct/2025:13:55:36 +0200] "POST /api/login HTTP/1.1" 401 2326 "https://example.com/login" "curl/7.68.0"`),
			expectedIP:     "192.168.1.1",
			expectedMethod: ingestor.POST,
			expectedURI:    "/api/login",
			expectedStatus: 401,
			expectedBytes:  2326,
			expectedUA:     "curl/7.68.0",
		},
		{
			name:           "Nginx Format with request line parsing",
			format:         "%h %^ %^ [%t] \"%r\" %s %b \"%^\" \"%u\"",
			logLine:        []byte(`10.0.0.100 - - [15/Nov/2025:08:30:12 +0000] "HEAD /robots.txt HTTP/1.1" 404 0 "-" "Googlebot/2.1"`),
			expectedIP:     "10.0.0.100",
			expectedMethod: ingestor.HEAD,
			expectedURI:    "/robots.txt",
			expectedStatus: 404,
			expectedBytes:  0,
			expectedUA:     "Googlebot/2.1",
		},
		{
			name:           "Comma-separated proxy format (like Drupal)",
			format:         "%h, %^ %^ %^ [%t] \"%r\" %s %^ %b %^ %^ %^ \"%^\" \"%u\"",
			logLine:        []byte(`203.0.113.45, 198.51.10.21 - - [25/Dec/2025:16:45:22 +0000] "GET /search?q=test HTTP/1.1" 200 + 15000 25769 25108 0 "-" "Mozilla/5.0 (Windows NT 10.0)"`),
			expectedIP:     "203.0.113.45",
			expectedMethod: ingestor.GET,
			expectedURI:    "/search?q=test",
			expectedStatus: 200,
			expectedBytes:  15000,
			expectedUA:     "Mozilla/5.0 (Windows NT 10.0)",
		},
		{
			name:           "Space-separated with standalone method and URI",
			format:         "%h %^ %^ [%t] %m %U %^ %s %b %^ \"%u\"",
			logLine:        []byte(`172.16.0.5 user auth [01/Jan/2025:00:00:00 +0000] PUT /api/users/123 HTTP/1.1 204 0 extra "RestClient/1.0"`),
			expectedIP:     "172.16.0.5",
			expectedMethod: ingestor.PUT,
			expectedURI:    "/api/users/123",
			expectedStatus: 204,
			expectedBytes:  0,
			expectedUA:     "RestClient/1.0",
		},
		{
			name:           "Mixed format with bytes and method",
			format:         "%h %^ %^ [%t] %m %U %^ %s %b \"%u\"",
			logLine:        []byte(`10.1.1.50 admin - [20/Feb/2025:14:22:33 +0100] DELETE /api/cache/clear HTTP/1.1 200 512 "AdminTool/2.0"`),
			expectedIP:     "10.1.1.50",
			expectedMethod: ingestor.DELETE,
			expectedURI:    "/api/cache/clear",
			expectedStatus: 200,
			expectedBytes:  512,
			expectedUA:     "AdminTool/2.0",
		},
		{
			name:           "Custom format with standalone method at end",
			format:         "%h [%t] %U %s %b \"%u\" %m",
			logLine:        []byte(`198.51.100.25 [05/Mar/2025:11:20:45 +0000] /health/check 200 42 "HealthChecker/1.0" GET`),
			expectedIP:     "198.51.100.25",
			expectedMethod: ingestor.GET,
			expectedURI:    "/health/check",
			expectedStatus: 200,
			expectedBytes:  42,
			expectedUA:     "HealthChecker/1.0",
		},
		{
			name:           "Standard format with OPTIONS method",
			format:         "%h %^ %^ [%t] \"%r\" %s %b %^ \"%u\"",
			logLine:        []byte(`127.0.0.1 daemon info [10/Apr/2025:09:15:30 +0000] "OPTIONS /api/cors HTTP/1.1" 200 0 local "Mozilla/5.0 (X11; Linux)"`),
			expectedIP:     "127.0.0.1",
			expectedMethod: ingestor.OPTIONS,
			expectedURI:    "/api/cors",
			expectedStatus: 200,
			expectedBytes:  0,
			expectedUA:     "Mozilla/5.0 (X11; Linux)",
		},
		{
			name:           "Space-separated with quoted URI",
			format:         "%h %^ %^ [%t] %m \"%U\" %^ %s %b %u",
			logLine:        []byte(`192.0.2.100 - - [18/May/2025:22:10:05 +0000] PUT "/api/users/edit profile" HTTP/1.1 422 1024 APIClient`),
			expectedIP:     "192.0.2.100",
			expectedMethod: ingestor.PUT,
			expectedURI:    "/api/users/edit profile",
			expectedStatus: 422,
			expectedBytes:  1024,
			expectedUA:     "APIClient",
		},
		{
			name:           "Minimal format with only required fields",
			format:         "%h [%t] %m %U %s",
			logLine:        []byte(`203.0.113.1 [12/Jun/2025:16:30:00 +0000] GET /favicon.ico 404`),
			expectedIP:     "203.0.113.1",
			expectedMethod: ingestor.GET,
			expectedURI:    "/favicon.ico",
			expectedStatus: 404,
			expectedBytes:  0,  // Not specified
			expectedUA:     "", // Not specified
		},
		{
			name:           "Standard format with cache headers",
			format:         "%h %^ %^ [%t] \"%r\" %s %b %^ \"%u\"",
			logLine:        []byte(`10.10.10.1 proxy cache [30/Jul/2025:08:45:12 +0200] "GET /static/style.css HTTP/1.1" 304 0 hit "Mozilla/5.0 (Safari)"`),
			expectedIP:     "10.10.10.1",
			expectedMethod: ingestor.GET,
			expectedURI:    "/static/style.css",
			expectedStatus: 304,
			expectedBytes:  0,
			expectedUA:     "Mozilla/5.0 (Safari)",
		},
		{
			name:           "Load balancer format with multiple IPs",
			format:         "%h %^ %^ %^ [%t] \"%r\" %s %b \"%^\" \"%u\" %^",
			logLine:        []byte(`198.51.100.10 10.0.0.1 proxy upstream [15/Aug/2025:12:00:00 +0000] "POST /api/webhook HTTP/1.1" 201 256 "https://webhook.site" "GitHub-Hookshot/abc123" 0.125`),
			expectedIP:     "198.51.100.10",
			expectedMethod: ingestor.POST,
			expectedURI:    "/api/webhook",
			expectedStatus: 201,
			expectedBytes:  256,
			expectedUA:     "GitHub-Hookshot/abc123",
		},
		{
			name:           "JSON-like log format (space separated)",
			format:         "%h %^ %^ [%t] %m %U %^ %s %b %^ \"%u\" %^",
			logLine:        []byte(`172.20.0.5 request_id trace_id [25/Sep/2025:19:30:45 +0000] GET /api/metrics HTTP/2.0 200 4096 duration "Prometheus/2.0" extra`),
			expectedIP:     "172.20.0.5",
			expectedMethod: ingestor.GET,
			expectedURI:    "/api/metrics",
			expectedStatus: 200,
			expectedBytes:  4096,
			expectedUA:     "Prometheus/2.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser, err := NewParser(tt.format)
			if err != nil {
				t.Fatalf("Failed to create parser with format %q: %v", tt.format, err)
			}

			req, err := parseLineForTest(parser, tt.logLine)
			if err != nil {
				t.Fatalf("Failed to parse log line %q with format %q: %v", string(tt.logLine), tt.format, err)
			}

			// Validate IP
			if req.IPUint32 == 0 {
				t.Error("IP should not be zero")
			} else if req.IPUint32 != ipStringToUint32(tt.expectedIP) {
				t.Errorf("Expected IP %s, got %s", tt.expectedIP, ingestor.Uint32ToIPString(req.IPUint32))
			}

			// Validate Method
			if req.Method != tt.expectedMethod {
				t.Errorf("Expected method %v, got %v", tt.expectedMethod, req.Method)
			}

			// Validate URI
			if req.URI != tt.expectedURI {
				t.Errorf("Expected URI %q, got %q", tt.expectedURI, req.URI)
			}

			// Validate Status
			if req.Status != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, req.Status)
			}

			// Validate Bytes
			if req.Bytes != tt.expectedBytes {
				t.Errorf("Expected bytes %d, got %d", tt.expectedBytes, req.Bytes)
			}

			// Validate User Agent
			if req.UserAgent != tt.expectedUA {
				t.Errorf("Expected user agent %q, got %q", tt.expectedUA, req.UserAgent)
			}

			// Validate Timestamp is parsed (not zero)
			if req.Timestamp.IsZero() {
				t.Error("Timestamp should not be zero")
			}
		})
	}
}

func TestParser_QuotedVsUnquotedParsing(t *testing.T) {
	// Test the key difference: %r works with quoted request lines, %m %U %^ works with unquoted separate fields
	tests := []struct {
		name           string
		format         string
		logLine        []byte
		expectedIP     string
		expectedMethod ingestor.HTTPMethod
		expectedURI    string
		expectedStatus uint16
		shouldWork     bool
	}{
		{
			name:           "%r with quoted request line (CORRECT usage)",
			format:         "%h [%t] \"%r\" %s",
			logLine:        []byte(`192.168.1.1 [10/Jul/2025:14:30:45 +0000] "GET /api/users HTTP/1.1" 200`),
			expectedIP:     "192.168.1.1",
			expectedMethod: ingestor.GET,
			expectedURI:    "/api/users",
			expectedStatus: 200,
			shouldWork:     true,
		},
		{
			name:           "%r with unquoted separate fields (INCORRECT usage - will fail)",
			format:         "%h [%t] %r %s",
			logLine:        []byte(`192.168.1.1 [10/Jul/2025:14:30:45 +0000] GET /api/users HTTP/1.1 200`),
			expectedIP:     "192.168.1.1",
			expectedMethod: ingestor.GET,
			expectedURI:    "/api/users",
			expectedStatus: 200,
			shouldWork:     false, // This will NOT work correctly
		},
		{
			name:           "%m %U %^ with unquoted separate fields (CORRECT usage)",
			format:         "%h [%t] %m %U %^ %s",
			logLine:        []byte(`192.168.1.1 [10/Jul/2025:14:30:45 +0000] GET /api/users HTTP/1.1 200`),
			expectedIP:     "192.168.1.1",
			expectedMethod: ingestor.GET,
			expectedURI:    "/api/users",
			expectedStatus: 200,
			shouldWork:     true,
		},
		{
			name:           "%m %U %^ with quoted request line (INCORRECT usage - will fail)",
			format:         "%h [%t] \"%m %U %^\" %s",
			logLine:        []byte(`192.168.1.1 [10/Jul/2025:14:30:45 +0000] "GET /api/users HTTP/1.1" 200`),
			expectedIP:     "192.168.1.1",
			expectedMethod: ingestor.GET,
			expectedURI:    "/api/users",
			expectedStatus: 200,
			shouldWork:     false, // This will NOT work correctly
		},
		{
			name:           "%r with complex quoted request",
			format:         "%h [%t] \"%r\" %s %b",
			logLine:        []byte(`10.0.0.1 [15/Jul/2025:16:45:30 +0000] "POST /api/login?redirect=/dashboard&secure=true HTTP/1.1" 401 1024`),
			expectedIP:     "10.0.0.1",
			expectedMethod: ingestor.POST,
			expectedURI:    "/api/login?redirect=/dashboard&secure=true",
			expectedStatus: 401,
			shouldWork:     true,
		},
		{
			name:           "%m %U with complex unquoted fields",
			format:         "%h [%t] %m %U %^ %s %b",
			logLine:        []byte(`10.0.0.1 [15/Jul/2025:16:45:30 +0000] POST /api/login?redirect=/dashboard&secure=true HTTP/1.1 401 1024`),
			expectedIP:     "10.0.0.1",
			expectedMethod: ingestor.POST,
			expectedURI:    "/api/login?redirect=/dashboard&secure=true",
			expectedStatus: 401,
			shouldWork:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser, err := NewParser(tt.format)
			if err != nil {
				t.Fatalf("Failed to create parser with format %q: %v", tt.format, err)
			}

			req, err := parseLineForTest(parser, tt.logLine)

			if tt.shouldWork {
				// This test should work correctly
				if err != nil {
					t.Fatalf("Expected parsing to succeed but got error: %v", err)
				}

				// Validate IP
				if req.IPUint32 == 0 {
					t.Error("IP should not be zero")
				} else if req.IPUint32 != ipStringToUint32(tt.expectedIP) {
					t.Errorf("Expected IP %s, got %s", tt.expectedIP, ingestor.Uint32ToIPString(req.IPUint32))
				}

				// Validate Method
				if req.Method != tt.expectedMethod {
					t.Errorf("Expected method %v, got %v", tt.expectedMethod, req.Method)
				}

				// Validate URI
				if req.URI != tt.expectedURI {
					t.Errorf("Expected URI %q, got %q", tt.expectedURI, req.URI)
				}

				// Validate Status
				if req.Status != tt.expectedStatus {
					t.Errorf("Expected status %d, got %d", tt.expectedStatus, req.Status)
				}

				// Validate Timestamp is parsed (not zero)
				if req.Timestamp.IsZero() {
					t.Error("Timestamp should not be zero")
				}
			} else {
				// This test should fail or produce incorrect results
				if err == nil {
					t.Logf("Parsing succeeded but results may be incorrect:")
					t.Logf("  IP: %v", ingestor.Uint32ToIPString(req.IPUint32))
					t.Logf("  Method: %v", req.Method)
					t.Logf("  URI: %q", req.URI)
					t.Logf("  Status: %d", req.Status)

					// Check if results are actually wrong
					correctResults := (req.IPUint32 != 0 && req.IPUint32 == ipStringToUint32(tt.expectedIP) &&
						req.Method == tt.expectedMethod &&
						req.URI == tt.expectedURI &&
						req.Status == tt.expectedStatus)

					if correctResults {
						t.Error("Expected incorrect parsing but got correct results - test assumption may be wrong")
					}
				}
				// If parsing failed, that's expected for incorrect usage
			}
		})
	}
}

func TestParser_InvalidFormats(t *testing.T) {
	tests := []struct {
		name       string
		format     string
		shouldFail bool
	}{
		{"empty format", "", true},
		{"invalid field", "%x %h", true},
		{"malformed", "%%h", true},
		{"duplicate IP", "%h %^ %h", true},
		{"duplicate timestamp", "%t %^ %t", true},
		{"duplicate request", "%r %^ %r", true},
		{"duplicate method", "%m %^ %m", true},
		{"duplicate status", "%s %^ %s", true},
		{"duplicate bytes", "%b %^ %b", true},
		{"duplicate user agent", "%u %^ %u", true},
		{"duplicate URI", "%U %^ %U", true},
		{"unsupported format code", "%R %^ %h", true},
		{"no IP field", "%^ %^ [%t] \"%r\" %s %b", true},
		{"valid with skips", "%^ %^ %^ [%t] \"%r\" %s %b %^ \"%u\" \"%h\"", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser, err := NewParser(tt.format)
			if tt.shouldFail {
				if err == nil {
					t.Errorf("Expected format validation to fail for '%s', but it succeeded", tt.format)
				}
				return
			}

			if err != nil {
				t.Errorf("Expected format validation to succeed for '%s', but got error: %v", tt.format, err)
				return
			}

			// Should not crash, just return empty/partial results
			req, _ := parseLineForTest(parser, testLogLine)
			if req == nil {
				t.Error("Parser should return a request struct even for invalid formats")
			}
		})
	}
}

func TestParser_VariousLogFormats(t *testing.T) {
	tests := []struct {
		name     string
		format   string
		logLine  []byte
		expected struct {
			ip       string
			method   ingestor.HTTPMethod
			uri      string
			status   uint16
			bytes    uint32
			hasAgent bool
		}
	}{
		{
			name:    "nginx combined log",
			format:  apacheCombinedFormat,
			logLine: nginxLogLine,
			expected: struct {
				ip       string
				method   ingestor.HTTPMethod
				uri      string
				status   uint16
				bytes    uint32
				hasAgent bool
			}{
				ip:       "10.0.0.1",
				method:   ingestor.POST,
				uri:      "/admin/login",
				status:   401,
				bytes:    2326,
				hasAgent: true,
			},
		},
		{
			name:    "minimal log with missing bytes",
			format:  apacheCombinedFormat,
			logLine: minimalLogLine,
			expected: struct {
				ip       string
				method   ingestor.HTTPMethod
				uri      string
				status   uint16
				bytes    uint32
				hasAgent bool
			}{
				ip:       "203.0.113.45",
				method:   ingestor.HEAD,
				uri:      "/robots.txt",
				status:   404,
				bytes:    0, // Should be 0 for "-"
				hasAgent: false,
			},
		},
		{
			name:    "error status code log",
			format:  apacheCombinedFormat,
			logLine: errorLogLine,
			expected: struct {
				ip       string
				method   ingestor.HTTPMethod
				uri      string
				status   uint16
				bytes    uint32
				hasAgent bool
			}{
				ip:       "172.16.0.100",
				method:   ingestor.GET,
				uri:      "/admin/dashboard",
				status:   500,
				bytes:    1024,
				hasAgent: true,
			},
		},
		{
			name:    "long URI with query parameters",
			format:  apacheCombinedFormat,
			logLine: longUriLogLine,
			expected: struct {
				ip       string
				method   ingestor.HTTPMethod
				uri      string
				status   uint16
				bytes    uint32
				hasAgent bool
			}{
				ip:       "192.168.1.50",
				method:   ingestor.GET,
				uri:      "/api/v1/search",
				status:   200,
				bytes:    15000,
				hasAgent: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser, err := NewParser(tt.format)
			if err != nil {
				t.Fatal(err)
			}

			req, err := parseLineForTest(parser, tt.logLine)
			if err != nil {
				t.Fatal(err)
			}

			if req.IPUint32 == 0 || req.IPUint32 != ipStringToUint32(tt.expected.ip) {
				t.Errorf("Expected IP %s, got %s", tt.expected.ip, ingestor.Uint32ToIPString(req.IPUint32))
			}

			if req.Method != tt.expected.method {
				t.Errorf("Expected method %v, got %v", tt.expected.method, req.Method)
			}

			if !strings.HasPrefix(req.URI, tt.expected.uri) {
				t.Errorf("Expected URI to start with %s, got %s", tt.expected.uri, req.URI)
			}

			if req.Status != tt.expected.status {
				t.Errorf("Expected status %d, got %d", tt.expected.status, req.Status)
			}

			if req.Bytes != tt.expected.bytes {
				t.Errorf("Expected bytes %d, got %d", tt.expected.bytes, req.Bytes)
			}

			hasAgent := req.UserAgent != "" && req.UserAgent != "-"
			if hasAgent != tt.expected.hasAgent {
				t.Errorf("Expected hasAgent %v, got %v (agent: %s)", tt.expected.hasAgent, hasAgent, req.UserAgent)
			}
		})
	}
}

func TestParser_EdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		format      string
		logLine     []byte
		shouldPass  bool
		description string
	}{
		{
			name:        "malformed log line",
			format:      apacheCombinedFormat,
			logLine:     malformedLogLine,
			shouldPass:  true, // Should not crash, but may have invalid data
			description: "Parser should handle malformed input gracefully",
		},
		{
			name:        "empty log line",
			format:      apacheCombinedFormat,
			logLine:     []byte(""),
			shouldPass:  true,
			description: "Empty input should not crash",
		},
		{
			name:        "very short log line",
			format:      apacheCombinedFormat,
			logLine:     []byte("short"),
			shouldPass:  true,
			description: "Short input should not crash",
		},
		{
			name:        "IPv6 address",
			format:      apacheCombinedFormat,
			logLine:     ipv6LogLine,
			shouldPass:  true,
			description: "IPv6 addresses should be handled (though may not parse perfectly)",
		},
		{
			name:        "unicode in user agent",
			format:      apacheCombinedFormat,
			logLine:     []byte(`192.168.1.1 - - [01/Jan/2025:00:00:00 +0000] "GET / HTTP/1.1" 200 1024 "-" "Mozilla/5.0 (🚀 test)"`),
			shouldPass:  true,
			description: "Unicode characters should not cause crashes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser, err := NewParser(tt.format)
			if err != nil && tt.shouldPass {
				t.Fatal(err)
			}

			req, err := parseLineForTest(parser, tt.logLine)
			if err != nil && tt.shouldPass {
				t.Fatal(err)
			}

			if req == nil {
				t.Error("Parser should always return a request struct")
			}

			t.Logf("%s: Completed without crash", tt.description)
		})
	}
}

// TestParser_IPv6FieldYieldsZero is the URGENT-21 repro for the log parser:
// when the %h (IP) field holds an IPv6 address, the IPv4-only fast path
// (parseIPv4ToUint32) must yield IPUint32 == 0 (a reject sentinel), never a
// bogus IPv4. A colon is neither a digit nor a dot, so any IPv6 form — plain or
// IPv4-mapped — funnels to 0. Downstream clustering skips IPUint32 == 0, so an
// IPv6 line is never counted as a successful IPv4 request.
func TestParser_IPv6FieldYieldsZero(t *testing.T) {
	// %h is the FIRST field so the IPv6 address lands in the IP slot.
	format := `%h %^ %^ [%t] "%r" %s %b "%u"`
	parser, err := NewParser(format)
	if err != nil {
		t.Fatal(err)
	}

	lines := []string{
		`2001:db8::1 - - [20/Dec/2025:16:45:22 +0000] "GET /v6 HTTP/1.1" 200 0 "UA"`,
		`::1 - - [20/Dec/2025:16:45:22 +0000] "GET /v6 HTTP/1.1" 200 0 "UA"`,
		`::ffff:192.168.1.1 - - [20/Dec/2025:16:45:22 +0000] "GET /v6 HTTP/1.1" 200 0 "UA"`,
	}
	for _, line := range lines {
		req, err := parseLineForTest(parser, []byte(line))
		if err != nil {
			// A reject (error) is acceptable; what matters is IPUint32 never
			// becomes a usable IPv4. Continue to the IPUint32 assertion when
			// a request is returned.
			continue
		}
		if req.IPUint32 != 0 {
			t.Errorf("IPv6 line %q: IPUint32 = %d, want 0 (IPv6 must not yield a usable IPv4)", line, req.IPUint32)
		}
	}

	// Sanity: a real IPv4 in the same %h slot still parses to a non-zero value,
	// proving the format and parser are wired correctly (no false-zero regression).
	v4 := `203.0.113.7 - - [20/Dec/2025:16:45:22 +0000] "GET /ok HTTP/1.1" 200 0 "UA"`
	req, err := parseLineForTest(parser, []byte(v4))
	if err != nil {
		t.Fatalf("unexpected error on IPv4 line: %v", err)
	}
	if req.IPUint32 != ipStringToUint32("203.0.113.7") {
		t.Errorf("IPv4 control: IPUint32 = %d, want %d", req.IPUint32, ipStringToUint32("203.0.113.7"))
	}
}

func TestParser_FileProcessing(t *testing.T) {
	// Generate test log file with at least 1000 lines
	testFile, cleanup := testutil.GenerateTestLogFile(t, 1000)
	defer cleanup()

	parser, err := NewParser(apacheCombinedFormat)
	if err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	requests, err := parser.ParseFile(testFile)
	duration := time.Since(start)

	if err != nil {
		t.Fatal("File parsing failed:", err)
	}

	if len(requests) < 1000 {
		t.Errorf("Should have parsed at least 1000 requests, got %d", len(requests))
	}

	rate := float64(len(requests)) / duration.Seconds()
	t.Logf("Parsed %d requests in %v (%.0f req/sec)", len(requests), duration, rate)

	// Validate first few requests to ensure parsing quality
	for i, req := range requests[:min(10, len(requests))] {
		if req.IPUint32 == 0 {
			t.Errorf("Request %d: missing IP", i)
		}
		if req.Timestamp.IsZero() {
			t.Errorf("Request %d: missing timestamp", i)
		}
	}
}

// Benchmarks
func BenchmarkParser_SingleLine(b *testing.B) {
	parser, _ := NewParser(apacheCombinedFormat)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		req, err := parseLineForTest(parser, testLogLine)
		if err != nil {
			b.Fatal(err)
		}
		_ = req
	}
}

func BenchmarkParser_CustomFormat(b *testing.B) {
	parser, _ := NewParser("%h %^ %^ [%t] \"%r\" %s %b \"%u\"")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		req, err := parseLineForTest(parser, testLogLine)
		if err != nil {
			b.Fatal(err)
		}
		_ = req
	}
}

func BenchmarkParser_ZeroAlloc(b *testing.B) {
	parser, _ := NewParser(apacheCombinedFormat)
	req := &ingestor.Request{}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		err := parser.compiled.parseLineReuseOpt(testLogLine, req, parser.SkipStringFields, parser.SkipNonIPFields)
		if err != nil {
			b.Fatal(err)
		}
		// Reset fields that allocate
		req.IPUint32 = 0
		req.URI = ""
		req.UserAgent = ""
	}
}

func BenchmarkStaticParser_Comparison(b *testing.B) {
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		evt := map[string]interface{}{"message": string(testLogLine)}
		var req ingestor.Request
		if err := parseEventStaticMock(evt, &req); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParser_SkippedFields(b *testing.B) {
	// Only parse IP and status, skip everything else
	parser, _ := NewParser("%h %^ %^ %^ %^ %s %^ %^ %^")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		req, err := parseLineForTest(parser, testLogLine)
		if err != nil {
			b.Fatal(err)
		}
		_ = req
	}
}

func BenchmarkParser_MinimalFields(b *testing.B) {
	// Only parse IP address
	parser, _ := NewParser("%h %^ %^ %^ %^ %^ %^ %^ %^")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		req, err := parseLineForTest(parser, testLogLine)
		if err != nil {
			b.Fatal(err)
		}
		_ = req
	}
}

func BenchmarkParser_VariousFormats(b *testing.B) {
	formats := []struct {
		name   string
		format string
		line   []byte
	}{
		{"nginx_combined", apacheCombinedFormat, nginxLogLine},
		{"minimal_log", apacheCombinedFormat, minimalLogLine},
		{"error_log", apacheCombinedFormat, errorLogLine},
		{"long_uri", apacheCombinedFormat, longUriLogLine},
	}

	for _, f := range formats {
		b.Run(f.name, func(b *testing.B) {
			parser, _ := NewParser(f.format)

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				req, err := parseLineForTest(parser, f.line)
				if err != nil {
					b.Fatal(err)
				}
				_ = req
			}
		})
	}
}

func BenchmarkParser_FileProcessing(b *testing.B) {
	// Generate test log file with 100k lines for realistic benchmark
	testFile, cleanup := testutil.GenerateTestLogFile(&testing.T{}, 100000)
	defer cleanup()

	parser, _ := NewParser(apacheCombinedFormat)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		requests, err := parser.ParseFile(testFile)
		if err != nil {
			b.Fatal(err)
		}
		b.ReportMetric(float64(len(requests)), "requests")
	}
}

func TestParser_ZeroByteFile(t *testing.T) {
	tmpDir := t.TempDir()
	emptyFile := tmpDir + "/empty.log"

	f, err := os.Create(emptyFile)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	parser, err := NewParser(apacheCombinedFormat)
	if err != nil {
		t.Fatal(err)
	}

	requests, err := parser.ParseFile(emptyFile)
	if err != nil {
		t.Fatalf("ParseFile on empty file should not error, got: %v", err)
	}

	if len(requests) != 0 {
		t.Errorf("Expected 0 requests from empty file, got %d", len(requests))
	}
}

func TestParser_SingleLine(t *testing.T) {
	tmpDir := t.TempDir()
	singleFile := tmpDir + "/single.log"

	line := `198.51.10.21 - - [06/Jul/2025:19:57:26 +0000] "GET /dataset/?test HTTP/1.0" 200 13984 "-" "Mozilla/5.0" "14.191.169.89"` + "\n"

	if err := os.WriteFile(singleFile, []byte(line), 0644); err != nil {
		t.Fatal(err)
	}

	parser, err := NewParser(apacheCombinedFormat)
	if err != nil {
		t.Fatal(err)
	}

	requests, err := parser.ParseFile(singleFile)
	if err != nil {
		t.Fatalf("ParseFile on single-line file should not error, got: %v", err)
	}

	if len(requests) != 1 {
		t.Fatalf("Expected exactly 1 request, got %d", len(requests))
	}

	req := requests[0]

	if req.IPUint32 != ipStringToUint32("14.191.169.89") {
		t.Errorf("Expected IP 14.191.169.89, got %s", ingestor.Uint32ToIPString(req.IPUint32))
	}

	expectedTime := time.Date(2025, 7, 6, 19, 57, 26, 0, time.UTC)
	if !req.Timestamp.Equal(expectedTime) {
		t.Errorf("Expected timestamp %v, got %v", expectedTime, req.Timestamp)
	}

	if req.Method != ingestor.GET {
		t.Errorf("Expected method GET, got %v", req.Method)
	}

	if req.URI != "/dataset/?test" {
		t.Errorf("Expected URI /dataset/?test, got %s", req.URI)
	}

	if req.Status != 200 {
		t.Errorf("Expected status 200, got %d", req.Status)
	}

	if req.Bytes != 13984 {
		t.Errorf("Expected bytes 13984, got %d", req.Bytes)
	}

	if req.UserAgent != "Mozilla/5.0" {
		t.Errorf("Expected user agent Mozilla/5.0, got %s", req.UserAgent)
	}
}

// Mock static parser for performance comparison
func parseEventStaticMock(evt map[string]interface{}, out *ingestor.Request) error {
	msg, ok := evt["message"].(string)
	if !ok {
		return fmt.Errorf("missing message field")
	}

	// Simplified parsing similar to original static parser
	fields := strings.Fields(msg)
	if len(fields) > 0 {
		out.IPUint32 = ipStringToUint32(fields[0])
	}

	// Parse timestamp
	start := strings.IndexByte(msg, '[')
	end := strings.IndexByte(msg, ']')
	if start >= 0 && end > start {
		t, err := time.Parse("02/Jan/2006:15:04:05 -0700", msg[start+1:end])
		if err == nil {
			out.Timestamp = t.UTC()
		}
	}

	// Parse quoted parts
	quoted := strings.Split(msg, "\"")
	if len(quoted) >= 6 {
		requestLine := quoted[1]
		parts := strings.Fields(requestLine)
		if len(parts) >= 2 {
			out.Method = ingestor.ParseMethod(parts[0])
			out.URI = parts[1]
		}

		statusAndBytes := strings.TrimSpace(quoted[2])
		fields := strings.Fields(statusAndBytes)
		if len(fields) >= 2 {
			if status, err := strconv.Atoi(fields[0]); err == nil {
				out.Status = uint16(status)
			}
			if bytes, err := strconv.Atoi(fields[1]); err == nil {
				out.Bytes = uint32(bytes)
			}
		}

		if len(quoted) >= 6 {
			out.UserAgent = strings.TrimSpace(quoted[5])
		}
	}

	return nil
}

// TestParser_MethodFromRequestLineSentinel is the regression test for URGENT-10
// finding 1 (parser.go:985). Previously the %r request-line arm used
// `req.Method == 0` as an "unset" sentinel, but GET == 0, so a %m-parsed GET was
// silently overwritten by the method in the %r request line. The fix makes a
// standalone %m authoritative (the %r arm only fills Method when no %m exists),
// so the zero value is never treated as "unset".
func TestParser_MethodFromRequestLineSentinel(t *testing.T) {
	tests := []struct {
		name           string
		format         string
		logLine        []byte
		expectedMethod ingestor.HTTPMethod
		expectedURI    string
	}{
		{
			// THE BUG: %m parses GET (==0); the %r request line is a POST. Before
			// the fix the GET was clobbered to POST. Now %m wins => GET.
			name:           "m_GET_before_r_POST: %m wins (GET, not overwritten)",
			format:         `%h [%t] %m "%r" %s`,
			logLine:        []byte(`192.168.1.1 [10/Jul/2025:14:30:45 +0000] GET "POST /api/login HTTP/1.1" 200`),
			expectedMethod: ingestor.GET,
			expectedURI:    "/api/login",
		},
		{
			// Symmetric: %m POST, %r GET. %m wins => POST (not the previous behavior
			// either, since POST!=0 it was kept, but assert it stays correct).
			name:           "m_POST_before_r_GET: %m wins (POST)",
			format:         `%h [%t] %m "%r" %s`,
			logLine:        []byte(`192.168.1.1 [10/Jul/2025:14:30:45 +0000] POST "GET /home HTTP/1.1" 200`),
			expectedMethod: ingestor.POST,
			expectedURI:    "/home",
		},
		{
			// %r BEFORE %m: %m is still authoritative and overwrites whatever %r
			// would have parsed, because %m runs after %r in format order and
			// FieldType 2 always stores. %m GET must survive (not be left as the
			// %r-parsed POST).
			name:           "r_POST_before_m_GET: %m wins (GET)",
			format:         `%h [%t] "%r" %m %s`,
			logLine:        []byte(`192.168.1.1 [10/Jul/2025:14:30:45 +0000] "POST /api/login HTTP/1.1" GET 200`),
			expectedMethod: ingestor.GET,
			expectedURI:    "/api/login",
		},
		{
			// %r ONLY (no %m): the fallback must still write the method, INCLUDING
			// GET. Proves the no-%m path is unchanged for GET.
			name:           "r_only_GET: fallback writes GET",
			format:         `%h [%t] "%r" %s`,
			logLine:        []byte(`192.168.1.1 [10/Jul/2025:14:30:45 +0000] "GET /index.html HTTP/1.1" 200`),
			expectedMethod: ingestor.GET,
			expectedURI:    "/index.html",
		},
		{
			// %r ONLY (no %m) with POST: unchanged fallback behavior.
			name:           "r_only_POST: fallback writes POST",
			format:         `%h [%t] "%r" %s`,
			logLine:        []byte(`192.168.1.1 [10/Jul/2025:14:30:45 +0000] "POST /submit HTTP/1.1" 200`),
			expectedMethod: ingestor.POST,
			expectedURI:    "/submit",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser, err := NewParser(tt.format)
			if err != nil {
				t.Fatalf("NewParser(%q): %v", tt.format, err)
			}
			req, err := parseLineForTest(parser, tt.logLine)
			if err != nil {
				t.Fatalf("parse %q: %v", string(tt.logLine), err)
			}
			if req.Method != tt.expectedMethod {
				t.Errorf("Method: expected %v, got %v", tt.expectedMethod, req.Method)
			}
			if req.URI != tt.expectedURI {
				t.Errorf("URI: expected %q, got %q", tt.expectedURI, req.URI)
			}
		})
	}
}

// TestValidateFormat_DuplicateMessages is the regression test for URGENT-10
// finding 2 (parser.go:773-808). The 8-arm duplicate-field switch was collapsed
// to a single code->name map with one parameterized error. This asserts each
// duplicated field code is still rejected with a duplicate-specific message
// naming both the human field and the %code, the unsupported-code and
// missing-%h errors are preserved, and that a valid combined %m+%r format (a
// non-duplicate combination) is still accepted.
func TestValidateFormat_DuplicateMessages(t *testing.T) {
	dupCases := []struct {
		code byte
		name string
	}{
		{'h', "IP"},
		{'t', "timestamp"},
		{'r', "request"},
		{'m', "method"},
		{'s', "status"},
		{'b', "bytes"},
		{'U', "URI"},
		{'u', "user agent"},
	}
	for _, dc := range dupCases {
		// Always include %h so the missing-IP check never masks the duplicate
		// error for non-%h codes; for the %h case the format is two %h.
		format := fmt.Sprintf("%%h %%^ %%%c %%%c", dc.code, dc.code)
		err := validateFormat(format)
		if err == nil {
			t.Errorf("code %%%c: expected duplicate error for %q, got nil", dc.code, format)
			continue
		}
		want := fmt.Sprintf("duplicate %s field (%%%c)", dc.name, dc.code)
		if !strings.Contains(err.Error(), want) {
			t.Errorf("code %%%c: error %q does not contain %q", dc.code, err.Error(), want)
		}
	}

	// Unsupported code is still rejected with the unsupported-code message.
	if err := validateFormat("%h %z"); err == nil || !strings.Contains(err.Error(), "unsupported format code %z") {
		t.Errorf("unsupported code: got %v, want 'unsupported format code %%z'", err)
	}

	// Missing %h is still rejected with the no-IP message.
	if err := validateFormat(`%^ [%t] "%r" %s`); err == nil || !strings.Contains(err.Error(), "no IP field (%h)") {
		t.Errorf("missing IP: got %v, want 'no IP field (%%h)'", err)
	}

	// A valid combined %m + %r format (no duplicates) is still accepted.
	if err := validateFormat(`%h [%t] %m "%r" %s`); err != nil {
		t.Errorf("valid %%m+%%r format rejected: %v", err)
	}
}

// TestValidateFormat_ExportedWrapper proves the exported ValidateFormat is a
// faithful thin wrapper over the unexported validateFormat (CFG-02): it accepts
// the default format and a representative good format, and rejects a missing-%h
// format with the same message.
func TestValidateFormat_ExportedWrapper(t *testing.T) {
	if err := ValidateFormat(DefaultLogFormat); err != nil {
		t.Errorf("DefaultLogFormat must validate, got: %v", err)
	}
	if err := ValidateFormat(`%h %^ %^ [%t] "%r" %s %b %^ "%u"`); err != nil {
		t.Errorf("a representative good format must validate, got: %v", err)
	}
	if err := ValidateFormat("%s %b"); err == nil || !strings.Contains(err.Error(), "no IP field (%h)") {
		t.Errorf("missing-%%h format must be rejected: %v", err)
	}
}

// TestValidateFormat_EquivalentToCompileFormat documents (and locks) the
// equivalence ValidateFormat(f)==nil <=> compileFormat(f) succeeds, for a
// representative good and bad format (CFG-02 4a). This is what lets
// config.Validate gate a barrier-passed format and never have the downstream
// NewParser reject it.
func TestValidateFormat_EquivalentToCompileFormat(t *testing.T) {
	formats := []string{
		DefaultLogFormat,
		`%h %^ %^ [%t] "%r" %s %b %^ "%u"`,
		"%s %b",        // missing %h => both reject
		"%h %h",        // duplicate => both reject
		`%h [%t] "%r"`, // good
	}
	for _, f := range formats {
		vfErr := ValidateFormat(f)
		_, cfErr := compileFormat(f)
		if (vfErr == nil) != (cfErr == nil) {
			t.Errorf("format %q: ValidateFormat err=%v but compileFormat err=%v (must agree)", f, vfErr, cfErr)
		}
	}
}
