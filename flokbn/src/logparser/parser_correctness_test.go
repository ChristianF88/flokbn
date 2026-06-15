package logparser

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// FLOKBN-039 correctness tests: timestamp EOL bounds, status/bytes validation
// with malformed-field counters, escaped quotes in quoted fields, and
// streaming/chunked counter parity.

// mustNewParser builds a parser or fails the test.
func mustNewParser(t *testing.T, format string) *Parser {
	t.Helper()
	p, err := NewParser(format)
	if err != nil {
		t.Fatalf("NewParser(%q): %v", format, err)
	}
	return p
}

// TestParseTimestamp_EOLBounds verifies the end-aware timestamp guard:
// timestamps whose closing bracket sits at end-of-line (with or without a
// timezone suffix) must parse, the helper must never read past `end`, and
// fields shorter than the 20-byte fast-path window must yield time.Time{}.
func TestParseTimestamp_EOLBounds(t *testing.T) {
	wallClock := time.Date(2025, time.July, 6, 19, 57, 26, 0, time.UTC)

	t.Run("direct", func(t *testing.T) {
		cases := []struct {
			name       string
			line       string
			start, end int
			want       time.Time
		}{
			{"exact 20 bytes at EOL", "06/Jul/2025:19:57:26", 0, 20, wallClock},
			{"19 bytes at EOL", "06/Jul/2025:19:57:2", 0, 19, time.Time{}},
			{"end past len(line)", "06/Jul/2025:19:57:26", 0, 21, time.Time{}},
			{"with timezone, end at closing bracket", "[06/Jul/2025:19:57:26 +0000]", 1, 27, wallClock},
			{"bracket at very end of buffer", "[06/Jul/2025:19:57:26]", 1, 21, wallClock},
			{"garbage month", "06/Xyz/2025:19:57:26", 0, 20, time.Time{}},
			{"empty field", "", 0, 0, time.Time{}},
		}
		for _, tc := range cases {
			got := parseTimestamp([]byte(tc.line), tc.start, tc.end)
			if !got.Equal(tc.want) {
				t.Errorf("%s: parseTimestamp(%q, %d, %d) = %v, want %v",
					tc.name, tc.line, tc.start, tc.end, got, tc.want)
			}
		}
	})

	t.Run("via parseLineReuseOpt", func(t *testing.T) {
		p := mustNewParser(t, "%h [%t]")
		cases := []struct {
			name string
			line string
			want time.Time
		}{
			{"bracket at EOL with TZ", "1.2.3.4 [06/Jul/2025:19:57:26 +0000]", wallClock},
			{"no TZ, bracket at EOL (headline regression)", "1.2.3.4 [06/Jul/2025:19:57:26]", wallClock},
			{"unterminated bracket, exactly 20 ts bytes at EOL", "1.2.3.4 [06/Jul/2025:19:57:26", wallClock},
			{"unterminated bracket, 19 ts bytes at EOL", "1.2.3.4 [06/Jul/2025:19:57:2", time.Time{}},
			{"garbage month", "1.2.3.4 [06/Xyz/2025:19:57:26 +0000]", time.Time{}},
			// Decided behavior (Variant A): a timezone offset is IGNORED — the
			// wall-clock digits are returned as UTC, so +0200 parses to the same
			// instant string as +0000.
			{"TZ offset ignored, wall-clock as UTC", "1.2.3.4 [06/Jul/2025:19:57:26 +0200]", wallClock},
		}
		for _, tc := range cases {
			req, err := parseLineForTest(p, []byte(tc.line))
			if err != nil {
				t.Fatalf("%s: parse error: %v", tc.name, err)
			}
			if !req.Timestamp.Equal(tc.want) {
				t.Errorf("%s: Timestamp = %v, want %v", tc.name, req.Timestamp, tc.want)
			}
			if req.IPUint32 != ipStringToUint32("1.2.3.4") {
				t.Errorf("%s: IPUint32 = %d, want 1.2.3.4", tc.name, req.IPUint32)
			}
		}
	})
}

// combinedLineWithStatus builds an Apache combined-style line (matching
// apacheCombinedFormat) with the given status and bytes tokens.
func combinedLineWithStatusBytes(status, bytesField string) []byte {
	return []byte(fmt.Sprintf(
		`1.2.3.4 - - [06/Jul/2025:19:57:26 +0000] "GET /x HTTP/1.1" %s %s "-" "test-agent" "5.6.7.8"`,
		status, bytesField))
}

// TestParseStatus_Validation verifies status digit validation: only exactly
// three ASCII digits produce a non-zero status; "-" is a silent absent value;
// everything else zeroes the field and increments the malformedStatus counter.
func TestParseStatus_Validation(t *testing.T) {
	cases := []struct {
		status      string
		wantStatus  uint16
		wantCounted uint64
	}{
		{"200", 200, 0},
		{"404", 404, 0},
		{"2XX", 0, 1},
		{"X00", 0, 1},
		{"20", 0, 1},
		{"2000", 0, 1},
		// 999 is not a real HTTP status but is three digits — documented leniency.
		{"999", 999, 0},
		{"-", 0, 0}, // Apache convention for absent: silent zero, NOT counted
	}
	for _, tc := range cases {
		p := mustNewParser(t, apacheCombinedFormat)
		req, err := parseLineForTest(p, combinedLineWithStatusBytes(tc.status, "100"))
		if err != nil {
			t.Fatalf("status %q: parse error: %v", tc.status, err)
		}
		if req.Status != tc.wantStatus {
			t.Errorf("status %q: Status = %d, want %d", tc.status, req.Status, tc.wantStatus)
		}
		if got := p.Stats().MalformedStatus; got != tc.wantCounted {
			t.Errorf("status %q: MalformedStatus = %d, want %d", tc.status, got, tc.wantCounted)
		}
		if got := p.Stats().MalformedBytes; got != 0 {
			t.Errorf("status %q: unexpected MalformedBytes = %d", tc.status, got)
		}
	}
}

// TestParseBytes_Validation verifies bytes-field validation: any non-digit in
// the field zeroes the value and increments malformedBytes; "-" stays silent.
func TestParseBytes_Validation(t *testing.T) {
	t.Run("via parseLineReuseOpt", func(t *testing.T) {
		cases := []struct {
			bytesField  string
			wantBytes   uint32
			wantCounted uint64
		}{
			{"1234", 1234, 0},
			{"0", 0, 0},
			{"-", 0, 0}, // absent: silent, NOT counted
			{"12ab", 0, 1},
			{"ab12", 0, 1},
		}
		for _, tc := range cases {
			p := mustNewParser(t, apacheCombinedFormat)
			req, err := parseLineForTest(p, combinedLineWithStatusBytes("200", tc.bytesField))
			if err != nil {
				t.Fatalf("bytes %q: parse error: %v", tc.bytesField, err)
			}
			if req.Bytes != tc.wantBytes {
				t.Errorf("bytes %q: Bytes = %d, want %d", tc.bytesField, req.Bytes, tc.wantBytes)
			}
			if got := p.Stats().MalformedBytes; got != tc.wantCounted {
				t.Errorf("bytes %q: MalformedBytes = %d, want %d", tc.bytesField, got, tc.wantCounted)
			}
			if got := p.Stats().MalformedStatus; got != 0 {
				t.Errorf("bytes %q: unexpected MalformedStatus = %d", tc.bytesField, got)
			}
		}
	})

	t.Run("direct parseBytes", func(t *testing.T) {
		cases := []struct {
			input      string
			start, end int
			want       uint32
			wantOK     bool
		}{
			{"1234", 0, 4, 1234, true},
			{"0", 0, 1, 0, true},
			{"007", 0, 3, 7, true},
			{"12ab", 0, 4, 0, false},
			{"ab12", 0, 4, 0, false},
			{"1 2", 0, 3, 0, false},
			{"", 0, 0, 0, false}, // start >= end
		}
		for _, tc := range cases {
			got, ok := parseBytes([]byte(tc.input), tc.start, tc.end)
			if got != tc.want || ok != tc.wantOK {
				t.Errorf("parseBytes(%q, %d, %d) = (%d, %v), want (%d, %v)",
					tc.input, tc.start, tc.end, got, ok, tc.want, tc.wantOK)
			}
		}
	})
}

// TestQuotedField_EscapedQuotes verifies that a backslash-escaped quote inside
// a quoted field no longer truncates the field (misaligning every later field,
// including the IP), that backslash PARITY is honored (`\\"` closes), and that
// extractIPOnly stays in exact parity with the full parser.
func TestQuotedField_EscapedQuotes(t *testing.T) {
	cases := []struct {
		name       string
		line       string
		wantUA     string
		wantIP     string // "" means expect IPUint32 == 0
		wantStatus uint16
		wantBytes  uint32
	}{
		{
			name:       "escaped quotes mid-UA (misalignment regression)",
			line:       `1.2.3.4 - - [06/Jul/2025:19:57:26 +0000] "GET /x HTTP/1.1" 200 123 "-" "Mozilla \"Edge\" Browser" "9.8.7.6"`,
			wantUA:     `Mozilla \"Edge\" Browser`,
			wantIP:     "9.8.7.6",
			wantStatus: 200,
			wantBytes:  123,
		},
		{
			name:       "UA ending in literal backslash (even parity closes)",
			line:       `1.2.3.4 - - [06/Jul/2025:19:57:26 +0000] "GET /x HTTP/1.1" 200 123 "-" "foo\\" "9.8.7.6"`,
			wantUA:     `foo\\`,
			wantIP:     "9.8.7.6",
			wantStatus: 200,
			wantBytes:  123,
		},
		{
			name:       "multiple escaped quotes",
			line:       `1.2.3.4 - - [06/Jul/2025:19:57:26 +0000] "GET /x HTTP/1.1" 200 123 "-" "a\"b\"c" "9.8.7.6"`,
			wantUA:     `a\"b\"c`,
			wantIP:     "9.8.7.6",
			wantStatus: 200,
			wantBytes:  123,
		},
		{
			name:       "escaped quote with no later quote: field runs to EOL, IP zero",
			line:       `1.2.3.4 - - [06/Jul/2025:19:57:26 +0000] "GET /x HTTP/1.1" 200 123 "-" "abc\"def`,
			wantUA:     `abc\"def`,
			wantIP:     "",
			wantStatus: 200,
			wantBytes:  123,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := mustNewParser(t, apacheCombinedFormat)
			req, err := parseLineForTest(p, []byte(tc.line))
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			if req.UserAgent != tc.wantUA {
				t.Errorf("UserAgent = %q, want %q (raw escapes kept, alignment fix only)", req.UserAgent, tc.wantUA)
			}
			wantIP := uint32(0)
			if tc.wantIP != "" {
				wantIP = ipStringToUint32(tc.wantIP)
			}
			if req.IPUint32 != wantIP {
				t.Errorf("IPUint32 = %d, want %d (%q)", req.IPUint32, wantIP, tc.wantIP)
			}
			if req.Status != tc.wantStatus {
				t.Errorf("Status = %d, want %d", req.Status, tc.wantStatus)
			}
			if req.Bytes != tc.wantBytes {
				t.Errorf("Bytes = %d, want %d", req.Bytes, tc.wantBytes)
			}

			// Parity contract: extractIPOnly must return the exact IP the full
			// parser stored, for the same input bytes.
			if got := p.compiled.extractIPOnly([]byte(tc.line)); got != req.IPUint32 {
				t.Errorf("extractIPOnly = %d, full parse = %d — parity broken", got, req.IPUint32)
			}
		})
	}
}

// TestScanQuotedClose exercises the slow-path helper directly, in particular
// backslash parity at the start of the field content.
func TestScanQuotedClose(t *testing.T) {
	cases := []struct {
		name         string
		line         string
		contentStart int
		firstQuote   int
		want         int
	}{
		// `\"x"` content starting at 0: quote at 1 escaped, closes at 3.
		{"single escape", `\"x"`, 0, 1, 3},
		// `\\"` even parity: quote at 2 is NOT escaped.
		{"double backslash closes", `\\"`, 0, 2, 2},
		// `\\\"x"` odd parity: quote at 3 escaped, closes at 5.
		{"triple backslash escapes", `\\\"x"`, 0, 3, 5},
		// no later quote -> len(line)
		{"no closing quote", `\"abc`, 0, 1, 5},
		// backslashes before contentStart must not count toward parity
		{"parity stops at contentStart", `\"x`, 1, 1, 1},
	}
	for _, tc := range cases {
		if got := scanQuotedClose([]byte(tc.line), tc.contentStart, tc.firstQuote); got != tc.want {
			t.Errorf("%s: scanQuotedClose(%q, %d, %d) = %d, want %d",
				tc.name, tc.line, tc.contentStart, tc.firstQuote, got, tc.want)
		}
	}
}

// malformedCountFixture builds a log file with a known mix of good lines,
// bad-status lines (IP 9.9.9.9), bad-bytes lines (IP 8.8.8.8) and silent "-"
// lines. Returns (content, totalLines, badStatus, badBytes).
func malformedCountFixture() (string, int, uint64, uint64) {
	var b strings.Builder
	good := 10
	badStatus := 3
	badBytes := 2
	dashes := 2
	for i := 0; i < good; i++ {
		fmt.Fprintf(&b, "1.2.3.%d - - [06/Jul/2025:19:57:%02d +0000] \"GET /ok HTTP/1.1\" 200 100 \"-\" \"ua\" \"1.2.3.%d\"\n", i, i, i)
	}
	for i := 0; i < badStatus; i++ {
		fmt.Fprintf(&b, "9.9.9.9 - - [06/Jul/2025:19:58:%02d +0000] \"GET /bad-status HTTP/1.1\" 5XX 100 \"-\" \"ua\" \"9.9.9.9\"\n", i)
	}
	for i := 0; i < badBytes; i++ {
		fmt.Fprintf(&b, "8.8.8.8 - - [06/Jul/2025:19:59:%02d +0000] \"GET /bad-bytes HTTP/1.1\" 200 12x4 \"-\" \"ua\" \"8.8.8.8\"\n", i)
	}
	for i := 0; i < dashes; i++ {
		fmt.Fprintf(&b, "7.7.7.7 - - [06/Jul/2025:20:00:%02d +0000] \"GET /dash HTTP/1.1\" - - \"-\" \"ua\" \"7.7.7.7\"\n", i)
	}
	return b.String(), good + badStatus + badBytes + dashes, uint64(badStatus), uint64(badBytes)
}

func writeFixture(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "malformed.log")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

// TestParseFileMalformedFieldCounts_Streaming verifies the counters through
// the streaming file path: malformed lines are KEPT (field zeroed) and the
// counters tally exactly the bad-status/bad-bytes lines; "-" is not counted.
func TestParseFileMalformedFieldCounts_Streaming(t *testing.T) {
	content, total, wantStatus, wantBytes := malformedCountFixture()
	path := writeFixture(t, content)

	p := mustNewParser(t, apacheCombinedFormat)
	// Default flags: SkipNonIPFields=false, so status/bytes are parsed.
	reqs, err := p.ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	if len(reqs) != total {
		t.Fatalf("len(requests) = %d, want %d (malformed lines must be KEPT)", len(reqs), total)
	}
	stats := p.Stats()
	if stats.MalformedStatus != wantStatus || stats.MalformedBytes != wantBytes {
		t.Errorf("Stats() = %+v, want {MalformedStatus:%d MalformedBytes:%d}", stats, wantStatus, wantBytes)
	}

	badStatusIP := ipStringToUint32("9.9.9.9")
	badBytesIP := ipStringToUint32("8.8.8.8")
	for _, r := range reqs {
		if r.IPUint32 == badStatusIP && r.Status != 0 {
			t.Errorf("bad-status line: Status = %d, want 0", r.Status)
		}
		if r.IPUint32 == badBytesIP && r.Bytes != 0 {
			t.Errorf("bad-bytes line: Bytes = %d, want 0", r.Bytes)
		}
	}
}

// TestParseFileMalformedFieldCounts_Chunked verifies the chunked concurrent
// path produces identical counts to streaming, across small chunk sizes that
// force lines to straddle chunk boundaries.
func TestParseFileMalformedFieldCounts_Chunked(t *testing.T) {
	content, total, wantStatus, wantBytes := malformedCountFixture()
	path := writeFixture(t, content)

	for _, cs := range []int64{256, 1024, 4096} {
		p := mustNewParser(t, apacheCombinedFormat) // fresh parser: counters are cumulative
		reqs := parseConcurrentFull(t, p, path, cs)
		if len(reqs) != total {
			t.Fatalf("chunk=%d: len(requests) = %d, want %d", cs, len(reqs), total)
		}
		stats := p.Stats()
		if stats.MalformedStatus != wantStatus || stats.MalformedBytes != wantBytes {
			t.Errorf("chunk=%d: Stats() = %+v, want {MalformedStatus:%d MalformedBytes:%d}",
				cs, stats, wantStatus, wantBytes)
		}
	}
}

// TestMalformedFieldCountsZeroWhenSkipNonIP verifies the IP-only mode never
// touches the counters: status/bytes are not scanned at all.
func TestMalformedFieldCountsZeroWhenSkipNonIP(t *testing.T) {
	content, total, _, _ := malformedCountFixture()
	path := writeFixture(t, content)

	p := mustNewParser(t, apacheCombinedFormat)
	p.SkipNonIPFields = true
	reqs, err := p.ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	if len(reqs) != total {
		t.Fatalf("len(requests) = %d, want %d", len(reqs), total)
	}
	if stats := p.Stats(); stats.MalformedStatus != 0 || stats.MalformedBytes != 0 {
		t.Errorf("SkipNonIPFields=true: Stats() = %+v, want all zero", stats)
	}
}
