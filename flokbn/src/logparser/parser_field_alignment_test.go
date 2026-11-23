package logparser

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ChristianF88/flokbn/accesslog"
)

// legacyDefaultLogFormat is the default format before the referer slot was
// quoted. Existing configs still spell it out, so it must stay safe.
const legacyDefaultLogFormat = `%^ %^ %^ [%t] "%r" %s %b %^ "%u" "%h"`

// TestSkipField_QuotedValueWithSpaces is the regression test for the field
// misalignment that let a client choose the banned IP: a `%^` slot that the
// format does not quote was scanned as a bare token, so a quoted value
// containing a space (Referer "http://a b") shifted every later field by one
// and %h was read from the User-Agent.
func TestSkipField_QuotedValueWithSpaces(t *testing.T) {
	const realIP = "203.0.113.9"
	line := []byte(`10.0.0.1 - - [23/Nov/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 123 "http://a b" "8.8.8.7" "203.0.113.9"`)

	formats := map[string]string{
		"legacy default (unquoted referer slot)": legacyDefaultLogFormat,
		"current default":                        DefaultLogFormat,
	}
	for name, format := range formats {
		t.Run(name, func(t *testing.T) {
			p := mustNewParser(t, format)
			req, err := parseLineForTest(p, line)
			if err != nil {
				t.Fatal(err)
			}
			if got := accesslog.Uint32ToIPString(req.IPUint32); got != realIP {
				t.Errorf("full parse: IP = %s, want %s (the trailing %%h field, not the User-Agent)", got, realIP)
			}
			if req.UserAgent != "8.8.8.7" {
				t.Errorf("UserAgent = %q, want %q", req.UserAgent, "8.8.8.7")
			}
			if req.Status != 200 || req.Bytes != 123 {
				t.Errorf("status/bytes = %d/%d, want 200/123", req.Status, req.Bytes)
			}
			if got := accesslog.Uint32ToIPString(p.compiled.extractIPOnly(line)); got != realIP {
				t.Errorf("IP-only parse: IP = %s, want %s", got, realIP)
			}
		})
	}
}

// TestSkipField_QuotedValueWithSpaces_File drives the reported reproduction end
// to end through ParseFileIPs: 3000 lines whose Referer contains a space and
// whose User-Agent is an address in 8.8.8.0/24 must yield only the real
// trailing client IP.
func TestSkipField_QuotedValueWithSpaces_File(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 3000; i++ {
		fmt.Fprintf(&b, `10.0.0.1 - - [23/Nov/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 123 "http://a b" "8.8.8.%d" "203.0.113.9"`+"\n", i%250+1)
	}
	path := filepath.Join(t.TempDir(), "access.log")
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}

	for _, format := range []string{legacyDefaultLogFormat, DefaultLogFormat} {
		p := mustNewParser(t, format)
		ips, invalid, err := p.ParseFileIPs(path)
		if err != nil {
			t.Fatal(err)
		}
		if invalid != 0 || len(ips) != 3000 {
			t.Fatalf("format %q: got %d IPs, %d invalid; want 3000, 0", format, len(ips), invalid)
		}
		want := ipStringToUint32("203.0.113.9")
		for _, ip := range ips {
			if ip != want {
				t.Fatalf("format %q: parsed IP %s, want only 203.0.113.9", format, accesslog.Uint32ToIPString(ip))
			}
		}
	}
}

// TestAutoQuote_AnyField: a value that starts with a double quote is scanned
// up to its closing quote whatever the format says, for every field type.
func TestAutoQuote_AnyField(t *testing.T) {
	t.Run("unquoted %h slot, quoted value", func(t *testing.T) {
		p := mustNewParser(t, `%^ %h %s`)
		req, _ := parseLineForTest(p, []byte(`"a b" "192.0.2.7" 404`))
		if got := accesslog.Uint32ToIPString(req.IPUint32); got != "192.0.2.7" {
			t.Errorf("IP = %s, want 192.0.2.7", got)
		}
		if req.Status != 404 {
			t.Errorf("Status = %d, want 404", req.Status)
		}
	})

	t.Run("unquoted %r slot, quoted request line", func(t *testing.T) {
		p := mustNewParser(t, `%h %r %s`)
		req, _ := parseLineForTest(p, []byte(`192.0.2.7 "POST /login HTTP/1.1" 401`))
		if req.Method != accesslog.POST || req.URI != "/login" || req.Status != 401 {
			t.Errorf("method/URI/status = %v/%q/%d, want POST//login/401", req.Method, req.URI, req.Status)
		}
	})

	t.Run("escaped quote inside an auto-quoted skip", func(t *testing.T) {
		p := mustNewParser(t, `%^ %h`)
		line := []byte(`"a \" b" 192.0.2.7`)
		if got := accesslog.Uint32ToIPString(p.compiled.extractIPOnly(line)); got != "192.0.2.7" {
			t.Errorf("IP = %s, want 192.0.2.7", got)
		}
	})

	t.Run("unquoted value in a quoted slot still works", func(t *testing.T) {
		p := mustNewParser(t, DefaultLogFormat)
		line := []byte(`10.0.0.1 - - [23/Nov/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 123 - "curl/8" "203.0.113.9"`)
		req, _ := parseLineForTest(p, line)
		if got := accesslog.Uint32ToIPString(req.IPUint32); got != "203.0.113.9" {
			t.Errorf("IP = %s, want 203.0.113.9", got)
		}
		if req.UserAgent != "curl/8" {
			t.Errorf("UserAgent = %q, want curl/8", req.UserAgent)
		}
	})
}

// TestAutoQuote_GroupOpeningQuoteIsNotAField: a literal quote in the format
// that opens a GROUP of space-separated fields ("%^ %r %^") is not the start of
// a quoted value, so the first field of the group keeps its token scan.
func TestAutoQuote_GroupOpeningQuoteIsNotAField(t *testing.T) {
	p := mustNewParser(t, drupalLogFormat)
	req, err := parseLineForTest(p, drupalLogLine)
	if err != nil {
		t.Fatal(err)
	}
	if req.URI != "/psi/islandora/search" || req.Status != 200 {
		t.Errorf("URI/status = %q/%d, want /psi/islandora/search/200", req.URI, req.Status)
	}
	if req.UserAgent != "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" {
		t.Errorf("UserAgent = %q", req.UserAgent)
	}
}

// TestDefaultLogFormat_QuotesEveryQuotedSlot pins the default format: the
// referer slot is quoted like the request, User-Agent and client-IP slots.
func TestDefaultLogFormat_QuotesEveryQuotedSlot(t *testing.T) {
	const want = `%^ %^ %^ [%t] "%r" %s %b "%^" "%u" "%h"`
	if DefaultLogFormat != want {
		t.Errorf("DefaultLogFormat = %q, want %q", DefaultLogFormat, want)
	}
}

// refFieldBounds is a deliberately plain reference for the field walk: it
// returns the [start,end) content bounds of every extractor ({-1,-1} when the
// line ended before the field). It uses byte-at-a-time loops and the original
// flag-driven "advance" step, so it shares no scanning code with the two
// hand-optimised production walkers it is compared against.
func refFieldBounds(cf *CompiledFormat, line []byte) [][2]int {
	out := make([][2]int, len(cf.extractors))
	for i := range out {
		out[i] = [2]int{-1, -1}
	}
	pos := 0
	for i, e := range cf.extractors {
		if pos >= len(line) {
			break
		}
		for pos < len(line) && line[pos] == ' ' {
			pos++
		}
		start := pos
		closedSlot := false // the value was scanned as a quoted or bracketed string
		switch {
		case e.autoQuote && pos < len(line) && line[pos] == '"':
			closedSlot = true
			pos++
			start = pos
			for pos < len(line) {
				if line[pos] == '"' {
					backslashes := 0
					for j := pos - 1; j >= start && line[j] == '\\'; j-- {
						backslashes++
					}
					if backslashes%2 == 0 {
						break
					}
				}
				pos++
			}
		case e.Brackets && pos < len(line) && line[pos] == '[':
			closedSlot = true
			pos++
			start = pos
			for pos < len(line) && line[pos] != ']' {
				pos++
			}
		default:
			for pos < len(line) && line[pos] != e.Delimiter && line[pos] != ' ' {
				pos++
			}
		}
		out[i] = [2]int{start, pos}

		closerConsumed := false
		if e.autoQuote && pos < len(line) && line[pos] == '"' {
			pos++
			closerConsumed = true
		} else if e.Brackets && pos < len(line) && line[pos] == ']' {
			pos++
			closerConsumed = true
		} else if pos < len(line) && line[pos] == e.Delimiter {
			pos++
		}
		// The delimiter behind a closing quote/bracket belongs to the field.
		if closedSlot && closerConsumed && pos < len(line) && line[pos] == e.after {
			pos++
		}
	}
	return out
}

// alignmentFormats are the format shapes the differential walk test covers.
var alignmentFormats = []string{
	DefaultLogFormat,
	legacyDefaultLogFormat,
	`%h %^ %^ [%t] "%r" %s %b "%^" "%u"`,
	`%h %^ %^ [%t] "%r" %s %b %^ "%u"`,
	`%^ %h [%t] "%r" %s`,
	`%h`,
	`"%h"`,
	`%h [%t] "%u"`,
	`%h [%t] %m %U %^ %s %b "%u"`,
	`%h [%t] "%m %U %^" %s`,
	`%^ %^ "%u" %U %h`,
	`%t %u %h`,
	drupalLogFormat,
	`%h|[%t]|%m|%U|%s`,
	`[%t]|"%u"|%U|%h`,
	`%^,"%u",%h,%s`,
	`%^|%^|%h`,
	`"%u";[%t];%h`,
}

// alignmentTokens are the pieces random lines are assembled from: plain
// values, quotes, brackets, escapes and delimiters in every awkward position.
var alignmentTokens = []string{
	" ", " ", " ", "  ", `"`, `"`, `"-"`, `""`, `\`, `\"`, `\\`, "[", "]", "-", ",", "|", "#",
	"203.0.113.9", "8.8.8.7", "10.0.0.1", "999.1.1.1", "1.2.3", "GET", "/a/b?c=d", "HTTP/1.1",
	"200", "1234", "Mozilla/5.0", "(X11; Linux)", "http://a", "10/Oct/2025:13:55:36 +0200",
	`"http://a b"`, `"8.8.8.7"`, `"203.0.113.9"`, `[10/Oct/2025:13:55:36 +0200]`, `"GET /x HTTP/1.1"`,
	`"8.8.8.7, 203.0.113.9"`, "8.8.8.7,203.0.113.9", ", ",
	"|", "|", ";", `"|`, `]|`, `";`, "||",
}

// TestDiffFieldWalk_AgainstReference cross-checks both production walkers
// (full parse and IP-only) against refFieldBounds on random lines: the IP, the
// User-Agent and the standalone URI must come from exactly the bytes the
// reference attributes to those fields.
func TestDiffFieldWalk_AgainstReference(t *testing.T) {
	rng := rand.New(rand.NewSource(20261123))

	lines := make([][]byte, 0, 6000)
	for i := 0; i < 6000; i++ {
		var b strings.Builder
		for n := rng.Intn(24); n > 0; n-- {
			b.WriteString(alignmentTokens[rng.Intn(len(alignmentTokens))])
		}
		lines = append(lines, []byte(b.String()))
	}

	for _, format := range alignmentFormats {
		cf, err := compileFormat(format)
		if err != nil {
			t.Fatalf("compileFormat(%q): %v", format, err)
		}
		for _, line := range lines {
			bounds := refFieldBounds(cf, line)

			var wantIP uint32
			var wantUA, wantURI string
			checkUA, checkURI := false, false
			for i, e := range cf.extractors {
				s, end := bounds[i][0], bounds[i][1]
				if s < 0 || s >= end {
					continue
				}
				switch e.FieldType {
				case 0:
					if wantIP = parseIPv4ToUint32(line, s, end); wantIP == 0 {
						wantIP = forwardedTailIP(line, s, end)
					}
				case 6:
					wantUA, checkUA = string(line[s:end]), true
				case 7:
					wantURI, checkURI = string(line[s:end]), true
				}
			}

			if got := cf.extractIPOnly(line); got != wantIP {
				t.Fatalf("format %q line %q: extractIPOnly = %s, reference = %s",
					format, line, accesslog.Uint32ToIPString(got), accesslog.Uint32ToIPString(wantIP))
			}
			var req accesslog.Request
			_ = cf.parseUsingCompiledFormatOpt(line, &req, false, false)
			if req.IPUint32 != wantIP {
				t.Fatalf("format %q line %q: full parse IP = %s, reference = %s",
					format, line, accesslog.Uint32ToIPString(req.IPUint32), accesslog.Uint32ToIPString(wantIP))
			}
			if checkUA && req.UserAgent != wantUA {
				t.Fatalf("format %q line %q: UserAgent = %q, reference = %q", format, line, req.UserAgent, wantUA)
			}
			if checkURI && req.URI != wantURI {
				t.Fatalf("format %q line %q: URI = %q, reference = %q", format, line, req.URI, wantURI)
			}
		}
	}
}
