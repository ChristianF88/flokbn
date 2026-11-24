package logparser

import (
	"math/rand"
	"strings"
	"testing"

	"github.com/ChristianF88/flokbn/accesslog"
)

// Differential tests: the file parser with re-alignment against the walkers
// it replaced (legacy_walk_test.go).
//
// Re-alignment changes how a line is read in exactly two situations, and the
// tests call a line with one of them anomalous:
//
//  1. a slot that the format encloses and that can be re-aligned - "[%t]", or
//     a quoted slot behind a bare free-text field or behind "[%t]" - holds a
//     bare value instead of a bracketed or quoted one;
//  2. a bare free-text value stops at a space although the format ends its
//     slot with another delimiter.
//
// Every other line must parse byte-identically: same address from the IP-only
// walk, same Request (including the zone of the timestamp) and same
// malformed-field counts from the full walk, in every skip mode.

// walkResult is everything a walk produces, in comparable form.
type walkResult struct {
	ip, bytes                       uint32
	status                          uint16
	method                          accesslog.HTTPMethod
	unixNano                        int64
	zoneName                        string
	zoneOffset                      int
	uri, userAgent                  string
	malformedStatus, malformedBytes uint64
}

func resultOf(req *accesslog.Request, c *parseCounters) walkResult {
	name, offset := req.Timestamp.Zone()
	r := walkResult{
		ip: req.IPUint32, bytes: req.Bytes, status: req.Status, method: req.Method,
		zoneName: name, zoneOffset: offset, uri: req.URI, userAgent: req.UserAgent,
		malformedStatus: c.malformedStatus.Load(), malformedBytes: c.malformedBytes.Load(),
	}
	if !req.Timestamp.IsZero() {
		r.unixNano = req.Timestamp.UnixNano()
	}
	return r
}

// formatPair is one format compiled twice: positional for the legacy walkers,
// re-aligning for the current ones.
type formatPair struct {
	format     string
	positional *CompiledFormat
	realigning *CompiledFormat
}

func newFormatPair(t testing.TB, format string) formatPair {
	t.Helper()
	positional, err := compileFormat(format)
	if err != nil {
		t.Fatalf("compileFormat(%q): %v", format, err)
	}
	realigning, err := compileFormat(format)
	if err != nil {
		t.Fatal(err)
	}
	realigning.enableRealign()
	return formatPair{format: format, positional: positional, realigning: realigning}
}

// anomalous reports whether line has one of the two anomalies for this
// format. It walks the line positionally with plain byte loops of its own, up
// to the first slot where re-alignment would step in; until there both
// parsers read the same bytes.
func (fp formatPair) anomalous(line []byte) bool {
	pos := 0
	for i, e := range fp.positional.extractors {
		for pos < len(line) && line[pos] == ' ' {
			pos++
		}
		if pos >= len(line) {
			return false
		}
		switch {
		case e.autoQuote && line[pos] == '"':
			pos++
			start := pos
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
			if pos < len(line) {
				pos++
				if pos < len(line) && line[pos] == e.after {
					pos++
				}
			}
		case e.Brackets && line[pos] == '[':
			for pos < len(line) && line[pos] != ']' {
				pos++
			}
			if pos < len(line) {
				pos++
				if pos < len(line) && line[pos] == e.after {
					pos++
				}
			}
		default:
			kind := fp.realigning.extractors[i].resync
			if kind > resyncSpan {
				return true // anomaly 1
			}
			for pos < len(line) && line[pos] != e.Delimiter && line[pos] != ' ' {
				pos++
			}
			if pos < len(line) {
				if line[pos] == e.Delimiter {
					pos++
				} else if kind == resyncSpan {
					return true // anomaly 2
				}
			}
		}
	}
	return false
}

// compare runs both parsers over line in every mode and reports the first
// difference, or "".
func (fp formatPair) compare(line []byte) string {
	if got, want := fp.realigning.extractIPOnly(line), fp.positional.legacyExtractIPOnly(line); got != want {
		return "IP-only walk: " + accesslog.Uint32ToIPString(got) + ", previous parser: " + accesslog.Uint32ToIPString(want)
	}
	for _, mode := range []struct {
		name                   string
		skipStrings, skipNonIP bool
	}{{"full", false, false}, {"skipStrings", true, false}, {"skipNonIP", true, true}} {
		var got, want accesslog.Request
		var gotCounters, wantCounters parseCounters
		current, previous := *fp.realigning, *fp.positional
		current.counters, previous.counters = &gotCounters, &wantCounters
		_ = current.parseUsingCompiledFormatOpt(line, &got, mode.skipStrings, mode.skipNonIP)
		_ = previous.legacyParseLine(line, &want, mode.skipStrings, mode.skipNonIP)
		if g, w := resultOf(&got, &gotCounters), resultOf(&want, &wantCounters); g != w {
			return mode.name + " walk differs from the previous parser"
		}
	}
	return ""
}

// realignFormats are the formats of the differential tests: the format shapes
// of the existing walk test plus the ones re-alignment has rules for.
var realignFormats = append([]string{
	ipFirstCombinedFormat,
	`%^ %^ "%r" %s %b "%^" "%u" "%h"`,
	`%h %^ "%u"`,
	`%h|%t|%U|%s`,
	`%h;%u;%s`,
	`%^ "%m %U %^" %s "%h"`,
	`[%^] %h %s`,
	`%h:%^ %^ [%t]`,
	`%h [%t] %U %s`,
	`%^|[%t]|"%u"|%h`,
	`"%u" "%^" [%t] %h`,
}, alignmentFormats...)

// wellFormedLine writes a random line that follows format: every bare value
// is a token without a space, a quote, a bracket or its own delimiter, every
// quoted value is arbitrary text with its quotes escaped, every bracketed
// timestamp is valid. Literals are copied from the format.
func wellFormedLine(rng *rand.Rand, format string) string {
	bare := []string{"-", "frank", "203.0.113.9", "10.1.2.3", "GET", "POST", "/a/b?c=d", "/", "200", "404", "1234", "0",
		"Mozilla/5.0", "curl/8.4", "x_y.z", "999.1.1.1", "2001:db8::1"}
	quoted := []string{"-", "", "GET /a b HTTP/1.1", "GET /x HTTP/1.1", "http://a b/c", "Mozilla/5.0 (X11; Linux x86_64)",
		`say \"hi\" [now]`, `back\\slash`, "203.0.113.9", "8.8.8.8, 203.0.113.9", "[12/Mar/2024:15:04:05 +0000]", " lead", "a|b;c,d"}
	stamps := []string{"12/Mar/2024:15:04:05 +0000", "06/Jul/2025:19:57:26 -0700", "31/Dec/2023:23:59:59", "29/Feb/2024:00:00:00 +0530"}

	var b strings.Builder
	for i := 0; i < len(format); i++ {
		if format[i] != '%' || i+1 >= len(format) {
			b.WriteByte(format[i])
			continue
		}
		code := format[i+1]
		var next, prev byte
		if i+2 < len(format) {
			next = format[i+2]
		}
		if i > 0 {
			prev = format[i-1]
		}
		switch {
		case prev == '"' && next == '"':
			if code == 'h' {
				b.WriteString(bare[2+rng.Intn(2)])
			} else {
				b.WriteString(quoted[rng.Intn(len(quoted))])
			}
		case code == 't':
			ts := stamps[rng.Intn(len(stamps))]
			if prev != '[' {
				ts = stamps[2] // a bare timestamp cannot hold the space of an offset
			}
			b.WriteString(ts)
		default:
			for {
				v := bare[rng.Intn(len(bare))]
				if next == 0 || !strings.ContainsRune(v, rune(next)) {
					b.WriteString(v)
					break
				}
			}
		}
		i++
	}
	return b.String()
}

// TestDiffRealign_WellFormedLines: lines that follow their format parse
// byte-identically with and without re-alignment.
func TestDiffRealign_WellFormedLines(t *testing.T) {
	rng := rand.New(rand.NewSource(20261124))
	for _, format := range realignFormats {
		fp := newFormatPair(t, format)
		for i := 0; i < 3000; i++ {
			line := []byte(wellFormedLine(rng, format))
			if fp.anomalous(line) {
				t.Fatalf("format %q: generated line %q is not well-formed", format, line)
			}
			if diff := fp.compare(line); diff != "" {
				t.Fatalf("format %q line %q: %s", format, line, diff)
			}
		}
	}
}

// TestDiffRealign_RandomLines: of arbitrary lines, only the anomalous ones may
// parse differently from the previous parser.
func TestDiffRealign_RandomLines(t *testing.T) {
	rng := rand.New(rand.NewSource(20261125))
	lines := make([][]byte, 0, 8000)
	for i := 0; i < 8000; i++ {
		var b strings.Builder
		for n := rng.Intn(24); n > 0; n-- {
			b.WriteString(alignmentTokens[rng.Intn(len(alignmentTokens))])
		}
		lines = append(lines, []byte(b.String()))
	}

	same, changed := 0, 0
	for _, format := range realignFormats {
		fp := newFormatPair(t, format)
		for _, line := range lines {
			diff := fp.compare(line)
			if fp.anomalous(line) {
				if diff != "" {
					changed++
				}
				continue
			}
			same++
			if diff != "" {
				t.Fatalf("format %q line %q has no anomaly, but: %s", format, line, diff)
			}
		}
	}
	// Guard against a vacuous test: most random lines are not anomalous, and
	// re-alignment does change some of the ones that are.
	if same < 50000 || changed < 1000 {
		t.Errorf("coverage too thin: %d lines compared equal, %d anomalous lines re-aligned", same, changed)
	}
}

// FuzzRealign holds for arbitrary input what the differential tests hold for
// generated input: no panic, both walkers agree on the address, and a line
// without an anomaly parses exactly as it did before.
func FuzzRealign(f *testing.F) {
	for _, s := range []string{
		`10.0.0.1 - - [12/Mar/2024:15:04:05 +0000] "GET /x HTTP/1.1" 200 10 "-" "UA" "203.0.113.7"`,
		`10.0.0.1 - john doe [12/Mar/2024:15:04:05 +0000] "GET /x HTTP/1.1" 200 10 "8.8.8.8" "UA" "203.0.113.7"`,
		`10.0.0.1 - a [01/Jan/2020:00:00:00 +0000] [12/Mar/2024:15:04:05 +0000] "GET /x HTTP/1.1" 200 10 "-" "UA" "203.0.113.7"`,
		`10.0.0.1 - a b] [ "x [12/Mar/2024:15:04:05 +0000] "GET /x HTTP/1.1" 200 10 "-" "UA" "203.0.113.7"`,
		`203.0.113.7|[12/Mar/2024:15:04:05 +0000]|GET|/a b c|404`,
		`x "GET /a b \" c HTTP/1.1" 200 "203.0.113.7"`,
		`10.0.0.1 - - 12/Mar/2024:15:04:05] "GET`,
		``, ` `, `[`, `"`, `[]`, `" "`, `a [`, `a "`,
	} {
		f.Add([]byte(s))
	}
	var pairs []formatPair
	for _, format := range []string{
		DefaultLogFormat, legacyDefaultLogFormat, ipFirstCombinedFormat,
		`%h|[%t]|%m|%U|%s`, `%^ "%m %U %^" %s "%h"`, `%^ %^ "%r" %s %b "%^" "%u" "%h"`, `[%^] %h %s`,
	} {
		pairs = append(pairs, newFormatPair(f, format))
	}
	f.Fuzz(func(t *testing.T, line []byte) {
		for _, fp := range pairs {
			var req accesslog.Request
			var counters parseCounters
			current := *fp.realigning
			current.counters = &counters
			_ = current.parseUsingCompiledFormatOpt(line, &req, false, false)
			if ip := fp.realigning.extractIPOnly(line); ip != req.IPUint32 {
				t.Fatalf("format %q: IP-only walk %s, full walk %s", fp.format,
					accesslog.Uint32ToIPString(ip), accesslog.Uint32ToIPString(req.IPUint32))
			}
			if !fp.anomalous(line) {
				if diff := fp.compare(line); diff != "" {
					t.Fatalf("format %q, line without an anomaly: %s", fp.format, diff)
				}
			}
		}
	})
}
