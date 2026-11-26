package logparser

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ChristianF88/flokbn/accesslog"
)

// ipFirstCombinedFormat is the combined log format with the client address in
// the first field (the live default).
const ipFirstCombinedFormat = `%h %^ %^ [%t] "%r" %s %b "%^" "%u"`

// TestSpaceInUserField_Evasion is the regression test for the reported
// evasion: the user name of a combined log line is whatever the client sent as
// its basic-auth name. With a space in it every later field used to sit one
// slot off, so the line was dropped (default format, %h last) or kept with a
// zero timestamp and the wrong request and User-Agent (IP-first format) - and
// the client was invisible to static detection or to its filters.
func TestSpaceInUserField_Evasion(t *testing.T) {
	cases := []struct {
		name, format, line string
	}{
		{"default format (IP last)", DefaultLogFormat,
			`10.0.0.1 - john doe [12/Mar/2024:15:04:05 +0000] "GET /x HTTP/1.1" 200 10 "-" "UA" "203.0.113.7"`},
		{"default format, several spaces", DefaultLogFormat,
			`10.0.0.1 - a b c d e f g h i j [12/Mar/2024:15:04:05 +0000] "GET /x HTTP/1.1" 200 10 "-" "UA" "203.0.113.7"`},
		{"IP-first combined format", ipFirstCombinedFormat,
			`203.0.113.7 - john doe [12/Mar/2024:15:04:05 +0000] "GET /x HTTP/1.1" 200 10 "-" "UA"`},
	}
	const wantIP = "203.0.113.7"
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := mustNewParser(t, tc.format)
			line := []byte(tc.line)

			if got := accesslog.Uint32ToIPString(p.compiled.extractIPOnly(line)); got != wantIP {
				t.Errorf("IP-only walk: IP = %s, want %s", got, wantIP)
			}
			req, err := parseLineForTest(p, line)
			if err != nil {
				t.Fatal(err)
			}
			if got := accesslog.Uint32ToIPString(req.IPUint32); got != wantIP {
				t.Errorf("full walk: IP = %s, want %s", got, wantIP)
			}
			if req.Timestamp.IsZero() || req.Timestamp.Unix() != 1710255845 {
				t.Errorf("Timestamp = %v, want 2024-03-12T15:04:05Z", req.Timestamp)
			}
			if req.Method != accesslog.GET || req.URI != "/x" || req.Status != 200 || req.Bytes != 10 || req.UserAgent != "UA" {
				t.Errorf("fields behind the user name misparsed: %+v", req)
			}
			if got := p.Stats(); got != (ParseStats{}) {
				t.Errorf("Stats() = %+v, want zero", got)
			}
		})
	}
}

// TestSpaceInUserField_File drives the evasion through every reader: 2000
// lines from one client whose user name holds a space must all be attributed
// to that client by the streaming and the chunked reader, in the IP-only and
// in the full parse.
func TestSpaceInUserField_File(t *testing.T) {
	for _, tc := range []struct{ name, format, line string }{
		{"default format", DefaultLogFormat,
			`10.0.0.1 - john doe [12/Mar/2024:15:04:05 +0000] "GET /x HTTP/1.1" 200 10 "-" "UA" "203.0.113.7"`},
		{"IP-first format", ipFirstCombinedFormat,
			`203.0.113.7 - john doe [12/Mar/2024:15:04:05 +0000] "GET /x HTTP/1.1" 200 10 "-" "UA"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const n = 2000
			path := filepath.Join(t.TempDir(), "access.log")
			if err := os.WriteFile(path, []byte(strings.Repeat(tc.line+"\n", n)), 0o644); err != nil {
				t.Fatal(err)
			}
			want := ipStringToUint32("203.0.113.7")
			p := mustNewParser(t, tc.format)

			checkIPs := func(label string, ips []uint32, invalid int) {
				t.Helper()
				if len(ips) != n || invalid != 0 {
					t.Fatalf("%s: %d IPs, %d invalid; want %d, 0", label, len(ips), invalid, n)
				}
				for _, ip := range ips {
					if ip != want {
						t.Fatalf("%s: IP %s, want 203.0.113.7", label, accesslog.Uint32ToIPString(ip))
					}
				}
			}
			checkReqs := func(label string, reqs []accesslog.Request) {
				t.Helper()
				if len(reqs) != n {
					t.Fatalf("%s: %d requests, want %d", label, len(reqs), n)
				}
				for _, r := range reqs {
					if r.IPUint32 != want || r.Timestamp.Unix() != 1710255845 || r.URI != "/x" || r.UserAgent != "UA" || r.Status != 200 {
						t.Fatalf("%s: misparsed request %+v", label, r)
					}
				}
			}

			ips, invalid := parseStreamingIPs(t, p, path)
			checkIPs("streaming IP-only", ips, invalid)
			ips, invalid = parseConcurrentIPs(t, p, path, 4096)
			checkIPs("chunked IP-only", ips, invalid)
			checkReqs("streaming full", parseStreamingFull(t, p, path))
			checkReqs("chunked full", parseConcurrentFull(t, p, path, 4096))
		})
	}
}

// craftedUsers is what a client can put into the bare user field of a combined
// log line on a server that escapes quotes there (nginx writes \x22, Apache
// \"). None of it may change which bytes the later fields get.
var craftedUsers = []string{
	`-`,
	`a b`,
	`a  b   c`,
	`a [x]`,
	`a [x] [y] [z]`,
	`a [01/Jan/2020:00:00:00 +0000]`,
	`[01/Jan/2020:00:00:00 +0000]`,
	`a b [01/Jan/2020:00:00:00 +0000] c`,
	`a 01/Jan/2020:00:00:00`,
	`a 01/Jan/2020:00:00:00 b`,
	`a b]`,
	`a ]`,
	`[[[[ ]]]]`,
	`a b c d e f g 8.8.8.8`,
	`a 8.8.8.8 b`,
	`a \"b c\"`,
	`a \x22b c\x22 8.8.8.8`,
	`a|b ;c,d`,
}

// TestCraftedUserField_CannotMoveLaterFields: with a format that is properly
// specified, a space, a bracket, a forged timestamp or an address in the user
// field leaves %h, %t and every other field on the bytes the server wrote for
// them. The Referer is 8.8.8.8 throughout: one slot off and the default
// format would read the client address from it.
func TestCraftedUserField_CannotMoveLaterFields(t *testing.T) {
	formats := []struct{ name, format, lineFmt string }{
		{"default format (IP last)", DefaultLogFormat,
			`10.0.0.1 - %s [12/Mar/2024:15:04:05 +0000] "GET /x HTTP/1.1" 200 10 "8.8.8.8" "UA" "203.0.113.7"`},
		{"legacy default (bare referer slot)", legacyDefaultLogFormat,
			`10.0.0.1 - %s [12/Mar/2024:15:04:05 +0000] "GET /x HTTP/1.1" 200 10 "8.8.8.8" "UA" "203.0.113.7"`},
		{"IP-first combined format", ipFirstCombinedFormat,
			`203.0.113.7 - %s [12/Mar/2024:15:04:05 +0000] "GET /x HTTP/1.1" 200 10 "8.8.8.8" "UA"`},
		{"no timestamp, quoted request behind the user", `%^ %^ "%r" %s %b "%^" "%u" "%h"`,
			`10.0.0.1 %s "GET /x HTTP/1.1" 200 10 "8.8.8.8" "UA" "203.0.113.7"`},
	}
	want := ipStringToUint32("203.0.113.7")
	for _, f := range formats {
		p := mustNewParser(t, f.format)
		for _, user := range craftedUsers {
			line := []byte(strings.Replace(f.lineFmt, "%s", user, 1))
			if got := p.compiled.extractIPOnly(line); got != want {
				t.Errorf("%s, user %q: IP-only walk = %s, want 203.0.113.7", f.name, user, accesslog.Uint32ToIPString(got))
			}
			var req accesslog.Request
			_ = p.compiled.parseLineReuseOpt(line, &req, false, false)
			if req.IPUint32 != want {
				t.Errorf("%s, user %q: full walk IP = %s, want 203.0.113.7", f.name, user, accesslog.Uint32ToIPString(req.IPUint32))
			}
			if req.Method != accesslog.GET || req.URI != "/x" || req.Status != 200 || req.Bytes != 10 || req.UserAgent != "UA" {
				t.Errorf("%s, user %q: fields misparsed: %+v", f.name, user, req)
			}
			if strings.Contains(f.format, "%t") && req.Timestamp.Unix() != 1710255845 {
				t.Errorf("%s, user %q: Timestamp = %v, want the server's 2024-03-12T15:04:05Z", f.name, user, req.Timestamp)
			}
		}
		if got := p.Stats(); got != (ParseStats{}) {
			t.Errorf("%s: Stats() = %+v, want zero", f.name, got)
		}
	}
}

// TestBareField_RunsToItsDelimiter: a bare free-text field that the format
// ends with a delimiter other than a space runs to that delimiter, spaces
// included. An address, a method, a status and a byte count cannot hold a
// space, so for them the space still ends the value.
func TestBareField_RunsToItsDelimiter(t *testing.T) {
	const ip = "203.0.113.7"
	cases := []struct {
		name, format, line string
		uri, ua            string
		status             uint16
		noTimestamp        bool
	}{
		{name: "pipe-delimited URI", format: `%h|[%t]|%m|%U|%s`,
			line: `203.0.113.7|[12/Mar/2024:15:04:05 +0000]|GET|/a b c|404`, uri: "/a b c", status: 404},
		{name: "pipe-delimited skip in front of the address", format: `%^|%h|%s`,
			line: `john doe|203.0.113.7|200`, status: 200, noTimestamp: true},
		{name: "bare timestamp with a zone offset", format: `%h|%t|%U|%s`,
			line: `203.0.113.7|12/Mar/2024:15:04:05 +0000|/x|200`, uri: "/x", status: 200},
		{name: "bare User-Agent between semicolons", format: `%h;%u;%s`,
			line: `203.0.113.7;Mozilla/5.0 (X11 Linux);200`, ua: "Mozilla/5.0 (X11 Linux)", status: 200, noTimestamp: true},
		{name: "last field of a quoted group", format: `%^ "%m %U %^" %s "%h"`,
			line: `x "GET /a b HTTP/1.1" 200 "203.0.113.7"`, uri: "/a", status: 200, noTimestamp: true},
		{name: "bracketed skip field", format: `[%^] %h %s`,
			line: `[some id] 203.0.113.7 200`, status: 200, noTimestamp: true},
		{name: "no further delimiter: the space ends the value", format: `%h|%U|%s`,
			line: `203.0.113.7|/a b`, uri: "/a", noTimestamp: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := mustNewParser(t, tc.format)
			line := []byte(tc.line)
			if got := accesslog.Uint32ToIPString(p.compiled.extractIPOnly(line)); got != ip {
				t.Errorf("IP-only walk = %s, want %s", got, ip)
			}
			req, _ := parseLineForTest(p, line)
			if got := accesslog.Uint32ToIPString(req.IPUint32); got != ip {
				t.Errorf("full walk IP = %s, want %s", got, ip)
			}
			if req.URI != tc.uri || req.UserAgent != tc.ua || req.Status != tc.status {
				t.Errorf("URI/UA/status = %q/%q/%d, want %q/%q/%d", req.URI, req.UserAgent, req.Status, tc.uri, tc.ua, tc.status)
			}
			if !tc.noTimestamp && req.Timestamp.Unix() != 1710255845 {
				t.Errorf("Timestamp = %v, want 2024-03-12T15:04:05Z", req.Timestamp)
			}
		})
	}

	t.Run("typed fields keep ending at the space", func(t *testing.T) {
		// The line has no port: %h must not run on to the colon of the timestamp.
		p := mustNewParser(t, `%h:%^ %^ [%t]`)
		line := []byte(`203.0.113.7 - - [12/Mar/2024:15:04:05 +0000]`)
		if got := accesslog.Uint32ToIPString(p.compiled.extractIPOnly(line)); got != ip {
			t.Errorf("IP = %s, want %s", got, ip)
		}
	})
}

// TestRealign_ReadingsThatDoNotChange pins lines that deviate from their
// format in ways the parser has always tolerated. Re-alignment must leave
// them alone.
func TestRealign_ReadingsThatDoNotChange(t *testing.T) {
	const ip = "203.0.113.7"
	cases := []struct{ name, format, line string }{
		{"timestamp without brackets", ipFirstCombinedFormat,
			`203.0.113.7 - - 12/Mar/2024:15:04:05 "GET /x HTTP/1.1" 200 10 "-" "UA"`},
		{"timestamp without the opening bracket", ipFirstCombinedFormat,
			`203.0.113.7 - - 12/Mar/2024:15:04:05] "GET /x HTTP/1.1" 200 10 "-" "UA"`},
		{"quoted timestamp in a bracketed slot", ipFirstCombinedFormat,
			`203.0.113.7 - - "12/Mar/2024:15:04:05 +0000" "GET /x HTTP/1.1" 200 10 "-" "UA"`},
		{"bare dash in the quoted referer slot", DefaultLogFormat,
			`10.0.0.1 - - [12/Mar/2024:15:04:05 +0000] "GET /x HTTP/1.1" 200 10 - "UA" "203.0.113.7"`},
		{"bare value in the quoted User-Agent slot", DefaultLogFormat,
			`10.0.0.1 - - [12/Mar/2024:15:04:05 +0000] "GET /x HTTP/1.1" 200 10 "-" UA "203.0.113.7"`},
		{"bare address in the quoted %h slot", DefaultLogFormat,
			`10.0.0.1 - - [12/Mar/2024:15:04:05 +0000] "GET /x HTTP/1.1" 200 10 "-" "UA" 203.0.113.7`},
		{"extra fields behind the last one", DefaultLogFormat,
			`10.0.0.1 - - [12/Mar/2024:15:04:05 +0000] "GET /x HTTP/1.1" 200 10 "-" "UA" "203.0.113.7" rt=0.004 "x y"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := mustNewParser(t, tc.format)
			positional, err := compileFormat(tc.format)
			if err != nil {
				t.Fatal(err)
			}
			line := []byte(tc.line)
			var want, got accesslog.Request
			_ = positional.legacyParseLine(line, &want, false, false)
			_ = p.compiled.parseLineReuseOpt(line, &got, false, false)
			if resultOf(&got, p.compiled.counters) != resultOf(&want, positional.counters) {
				t.Errorf("parse changed:\n got  %+v\n want %+v", got, want)
			}
			if accesslog.Uint32ToIPString(got.IPUint32) != ip || got.Timestamp.Unix() != 1710255845 || got.URI != "/x" || got.UserAgent != "UA" {
				t.Errorf("unexpected reading: %+v", got)
			}
			if ipOnly := p.compiled.extractIPOnly(line); ipOnly != got.IPUint32 {
				t.Errorf("IP-only walk = %s, full walk = %s", accesslog.Uint32ToIPString(ipOnly), accesslog.Uint32ToIPString(got.IPUint32))
			}
		})
	}
}

// TestRealign_AmbiguousFormats documents where the format itself cannot say
// which field a space belongs to: a bare field followed by a single space and
// another bare field. The first space ends the field there, as it always did.
func TestRealign_AmbiguousFormats(t *testing.T) {
	t.Run("bare field directly in front of a bare %h", func(t *testing.T) {
		p := mustNewParser(t, `%^ %h [%t] "%r"`)
		line := []byte(`john doe 203.0.113.7 [12/Mar/2024:15:04:05 +0000] "GET /x HTTP/1.1"`)
		if got := p.compiled.extractIPOnly(line); got != 0 {
			t.Errorf("IP = %s; the format cannot say that 'doe' is not the address", accesslog.Uint32ToIPString(got))
		}
		// The fields from the bracketed timestamp on are still read correctly.
		req, _ := parseLineForTest(p, line)
		if req.Timestamp.Unix() != 1710255845 || req.URI != "/x" {
			t.Errorf("fields behind the anchor misparsed: %+v", req)
		}
	})
	t.Run("bare fields behind the timestamp", func(t *testing.T) {
		p := mustNewParser(t, `%h [%t] %U %s`)
		req, _ := parseLineForTest(p, []byte(`203.0.113.7 [12/Mar/2024:15:04:05 +0000] /a b 200`))
		if req.URI != "/a" || req.Status != 0 {
			t.Errorf("URI/status = %q/%d, want /a and an unreadable status", req.URI, req.Status)
		}
	})
}

// TestRealign_DoesNotAllocate: the slow path is taken for lines a client
// wrote, so it must not allocate either.
func TestRealign_DoesNotAllocate(t *testing.T) {
	p := mustNewParser(t, DefaultLogFormat)
	pipe := mustNewParser(t, `%h|[%t]|%m|%U|%s`)
	lines := [][]byte{
		[]byte(`10.0.0.1 - john doe [12/Mar/2024:15:04:05 +0000] "GET /x HTTP/1.1" 200 10 "-" "UA" "203.0.113.7"`),
		[]byte(`10.0.0.1 - a [01/Jan/2020:00:00:00 +0000] b [12/Mar/2024:15:04:05 +0000] "GET /x HTTP/1.1" 200 10 "-" "UA" "203.0.113.7"`),
		[]byte(`10.0.0.1 - a [x] [12/Mar/2024:15:04:05 +0000] "GET /x HTTP/1.1" 200 10 "-" "UA" "203.0.113.7"`),
	}
	pipeLine := []byte(`203.0.113.7|[12/Mar/2024:15:04:05 +0000]|GET|/a b c|404`)
	var req accesslog.Request
	run := func() {
		for _, line := range lines {
			if p.compiled.extractIPOnly(line) == 0 {
				t.Fatal("line not re-aligned")
			}
			_ = p.compiled.parseLineReuseOpt(line, &req, false, false)
		}
		_ = pipe.compiled.extractIPOnly(pipeLine)
		_ = pipe.compiled.parseLineReuseOpt(pipeLine, &req, false, false)
	}
	run() // warm the zone-offset cache
	if allocs := testing.AllocsPerRun(200, run); allocs != 0 {
		t.Errorf("re-alignment allocated %.1f times per run, want 0", allocs)
	}
}

// TestRealign_LinearTime feeds the slow path lines built to make a careless
// search rescan: a megabyte of brackets, of quotes, of tokens. With a
// quadratic search any one of them takes minutes; the whole test has to stay
// far below a second.
func TestRealign_LinearTime(t *testing.T) {
	const n = 1 << 20
	tail := ` [12/Mar/2024:15:04:05 +0000] "GET /x HTTP/1.1" 200 10 "-" "UA" "203.0.113.7"`
	lines := map[string]string{
		"open brackets":          `10.0.0.1 - a ` + strings.Repeat("[", n) + tail,
		"spaced open brackets":   `10.0.0.1 - a ` + strings.Repeat("[ ", n/2) + tail,
		"empty brackets":         `10.0.0.1 - a ` + strings.Repeat("[] ", n/3) + tail,
		"near-timestamps":        `10.0.0.1 - a ` + strings.Repeat("[12/Mar/2024:15:04:0x] ", n/23) + tail,
		"tokens":                 `10.0.0.1 - a ` + strings.Repeat("b ", n/2) + tail,
		"closing brackets":       `10.0.0.1 - a ` + strings.Repeat("b] ", n/3) + tail,
		"escaped quotes":         `10.0.0.1 - a ` + strings.Repeat(`\"`, n/2) + tail,
		"glued quotes, no tail":  `10.0.0.1 - a b [12/Mar/2024:15:04:05 +0000] x` + strings.Repeat(`y"`, n/2),
		"brackets, no timestamp": `10.0.0.1 - a ` + strings.Repeat("[", n),
	}
	p := mustNewParser(t, DefaultLogFormat)
	want := ipStringToUint32("203.0.113.7")
	start := time.Now()
	for name, s := range lines {
		line := []byte(s)
		ip := p.compiled.extractIPOnly(line)
		var req accesslog.Request
		_ = p.compiled.parseLineReuseOpt(line, &req, false, false)
		if req.IPUint32 != ip {
			t.Errorf("%s: IP-only walk and full walk disagree", name)
		}
		if strings.HasSuffix(s, tail) && ip != want {
			t.Errorf("%s: IP = %s, want 203.0.113.7", name, accesslog.Uint32ToIPString(ip))
		}
	}
	// 18 walks over 1 MiB each. Linear work is a few milliseconds; the bound is
	// generous for a loaded CI machine and still far from what a rescan costs.
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("re-alignment of 9 adversarial 1 MiB lines took %v", d)
	}
}

// TestRealign_Residuals pins what a client can still do. These are the cases
// the documentation lists (docs: reference/log-formats, "Spaces in bare
// fields"); the test is here so that a change to any of them is noticed.
func TestRealign_Residuals(t *testing.T) {
	want := ipStringToUint32("203.0.113.7")

	t.Run("an unclosed bracket costs the line its timestamp, nothing else", func(t *testing.T) {
		// The bracket of the user name swallows the real timestamp. The line
		// keeps its address and its other fields, but has no time.
		p := mustNewParser(t, DefaultLogFormat)
		for _, user := range []string{"a [", "a [x"} {
			line := []byte(`10.0.0.1 - ` + user + ` [12/Mar/2024:15:04:05 +0000] "GET /x HTTP/1.1" 200 10 "8.8.8.8" "UA" "203.0.113.7"`)
			req, _ := parseLineForTest(p, line)
			if req.IPUint32 != want || p.compiled.extractIPOnly(line) != want || req.URI != "/x" || req.UserAgent != "UA" {
				t.Errorf("user %q: misparsed %+v", user, req)
			}
			if !req.Timestamp.IsZero() {
				t.Errorf("user %q: Timestamp = %v; this case is documented as losing it", user, req.Timestamp)
			}
		}
	})

	t.Run("a bare field behind the timestamp is not an anchor", func(t *testing.T) {
		// Nothing tells a bracketed token of the user name from the timestamp
		// when no quote follows it. A space alone is still harmless.
		p := mustNewParser(t, `%^ %^ %^ [%t] %m %U %s "%h"`)
		spaced := []byte(`10.0.0.1 - a b [12/Mar/2024:15:04:05 +0000] GET /x 200 "203.0.113.7"`)
		if got := p.compiled.extractIPOnly(spaced); got != want {
			t.Errorf("user with a space: IP = %s, want 203.0.113.7", accesslog.Uint32ToIPString(got))
		}
		bracketed := []byte(`10.0.0.1 - a [x] [12/Mar/2024:15:04:05 +0000] GET /x 200 "203.0.113.7"`)
		if got := p.compiled.extractIPOnly(bracketed); got != 0 {
			t.Errorf("user with a bracketed token: IP = %s; documented as a dropped line", accesslog.Uint32ToIPString(got))
		}
	})

	t.Run("an unescaped quote in a bare field", func(t *testing.T) {
		// Only a server that does not escape quotes in the user name writes
		// this. The quoted fields are then no longer the server's alone.
		p := mustNewParser(t, DefaultLogFormat)
		line := []byte(`10.0.0.1 - a "b [12/Mar/2024:15:04:05 +0000] "GET /x HTTP/1.1" 200 10 "8.8.8.8" "UA" "203.0.113.7"`)
		if got := p.compiled.extractIPOnly(line); got != 0 {
			t.Errorf("IP = %s; documented as a dropped line", accesslog.Uint32ToIPString(got))
		}
	})
}
