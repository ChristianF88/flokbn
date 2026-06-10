package logparser

import (
	"os"
	"testing"
)

func FuzzParallelParser(f *testing.F) {
	// Seed with real Apache Combined Log lines
	seeds := []string{
		`198.51.10.21 - - [06/Jul/2025:19:57:26 +0000] "GET /dataset/?test HTTP/1.0" 200 13984 "-" "Mozilla/5.0" "14.191.169.89"`,
		`192.168.1.100 - - [01/Jan/2025:10:15:30 +0000] "GET /api/users HTTP/1.1" 200 1024 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" "10.0.0.1"`,
		`10.0.0.1 - frank [10/Oct/2025:13:55:36 +0200] "POST /admin/login HTTP/1.1" 401 2326 "https://example.com/login" "curl/7.68.0" "10.0.0.1"`,
		// Edge cases
		``,
		`short`,
		"   \t\t   ",
		`badip - - [invalid-date] "INVALID" 999 NaN "malformed" "agent" "192.168.1.1"`,
		// Extremely long URI
		`192.168.1.1 - - [01/Jan/2025:00:00:00 +0000] "GET /` + string(make([]byte, 8192)) + ` HTTP/1.1" 200 0 "-" "test" "192.168.1.1"`,
		// Null bytes
		"192.168.1.1 - - [01/Jan/2025:00:00:00 +0000] \"GET /\x00path HTTP/1.1\" 200 0 \"-\" \"test\" \"192.168.1.1\"",
		// Mismatched quotes
		`192.168.1.1 - - [01/Jan/2025:00:00:00 +0000] "GET /path HTTP/1.1 200 0 "-" "test" "192.168.1.1"`,
	}

	for _, s := range seeds {
		f.Add([]byte(s))
	}

	format := `%^ %^ %^ [%t] "%r" %s %b %^ "%u" "%h"`
	parser, err := NewParallelParser(format)
	if err != nil {
		f.Fatal(err)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		// Write data to temp file and parse
		tmpDir := t.TempDir()
		tmpFile := tmpDir + "/fuzz.log"
		if err := os.WriteFile(tmpFile, data, 0644); err != nil {
			return
		}
		// Should not panic
		parser.ParseFile(tmpFile)
	})
}

func FuzzLogFormatParsing(f *testing.F) {
	// Seed with known valid formats
	seeds := []string{
		`%^ %^ %^ [%t] "%r" %s %b %^ "%u" "%h"`,
		`%h %^ %^ [%t] "%r" %s %b "%^" "%u"`,
		`%h [%t] %m %U %^ %s %b "%u"`,
		`%h [%t] "%r" %s`,
		// Edge cases
		``,
		`%h`,
		`%h %h`, // duplicate
	}

	for _, s := range seeds {
		f.Add(s)
	}

	testLine := []byte(`192.168.1.1 - - [01/Jan/2025:00:00:00 +0000] "GET / HTTP/1.1" 200 0 "-" "test" "192.168.1.1"`)

	f.Fuzz(func(t *testing.T, format string) {
		// Creating parser with arbitrary format should not panic
		parser, err := NewParallelParser(format)
		if err != nil {
			return // Invalid format is fine
		}
		// Parsing with valid parser should not panic
		parseLineForTest(parser, testLine)
	})
}
