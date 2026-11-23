package ingestor

import (
	"testing"

	"github.com/ChristianF88/flokbn/logparser"
)

// TestLiveStaticUserAgentParity is the AUDIT-08 cross-package parity guard.
//
// The live ingestor (parseLine) and the static compiled-format parser must
// extract the IDENTICAL UserAgent for the same log line, including
// Apache-escaped quotes (`\"`) in the request line and referer. The static
// parser skips backslash-escaped quotes via scanQuotedClose; the live parser
// duplicates that logic in scanQuotedCloseStr.
//
// The static format mirrors the live wire shape that parseLine assumes:
// IP first, timestamp in brackets, quoted request line, status, bytes, quoted
// referer (skipped), quoted user-agent. The referer is a QUOTED skip field
// (`"%^"`) so the static parser scans it escape-aware too - exactly what the
// live walk now does.
func TestLiveStaticUserAgentParity(t *testing.T) {
	const format = `%h %^ %^ [%t] "%r" %s %b "%^" "%u"`
	lp, err := logparser.NewLineParser(format)
	if err != nil {
		t.Fatalf("NewLineParser(%q): %v", format, err)
	}

	cases := []struct {
		line   string
		wantUA string // expected UserAgent BOTH parsers must produce
	}{
		// Clean line: the common fast path.
		{`1.2.3.4 - - [12/Mar/2024:15:04:05 -0700] "GET / HTTP/1.1" 200 10 "-" "RealUA"`, "RealUA"},
		// Escaped quote inside the request URI.
		{`1.2.3.4 - - [12/Mar/2024:15:04:05 -0700] "GET /a\"b HTTP/1.1" 200 10 "-" "RealUA"`, "RealUA"},
		// Escaped quote inside the referer.
		{`1.2.3.4 - - [12/Mar/2024:15:04:05 -0700] "GET / HTTP/1.1" 200 10 "ref\"erer" "RealUA"`, "RealUA"},
		// Escaped quotes in BOTH request line and referer.
		{`1.2.3.4 - - [12/Mar/2024:15:04:05 -0700] "GET /a\"b HTTP/1.1" 200 10 "r\"ef" "RealUA"`, "RealUA"},
		// Escaped quote inside the UA itself (kept raw, alignment-only).
		{`1.2.3.4 - - [12/Mar/2024:15:04:05 -0700] "GET / HTTP/1.1" 200 10 "-" "Mozilla\"Evil"`, `Mozilla\"Evil`},
		// Even backslashes do NOT escape the request close quote (parity bug if mishandled).
		{`1.2.3.4 - - [12/Mar/2024:15:04:05 -0700] "GET /x\\" 200 10 "-" "RealUA"`, "RealUA"},
		// Triple backslash escapes the inner quote (odd parity).
		{`1.2.3.4 - - [12/Mar/2024:15:04:05 -0700] "GET /a\\\"b HTTP/1.1" 200 10 "-" "RealUA"`, "RealUA"},
		// Escaped quote in request AND in UA together.
		{`1.2.3.4 - - [12/Mar/2024:15:04:05 -0700] "GET /a\"b HTTP/1.1" 200 10 "-" "UA\"X"`, `UA\"X`},
		// Empty UA field.
		{`1.2.3.4 - - [12/Mar/2024:15:04:05 -0700] "GET / HTTP/1.1" 200 10 "-" ""`, ""},
		// Missing UA field entirely (only 4 quotes): both must yield empty.
		{`1.2.3.4 - - [12/Mar/2024:15:04:05 -0700] "GET / HTTP/1.1" 200 10 "-" `, ""},
	}

	for _, tc := range cases {
		line := tc.line
		// Static extraction (strings NOT skipped so UserAgent is populated).
		var staticReq Request
		if err := lp.ParseLine(line, &staticReq); err != nil {
			t.Fatalf("static parse %q: %v", line, err)
		}

		// Live extraction.
		var liveReq Request
		if _, lerr := parseLine(line, &liveReq); lerr != nil {
			t.Fatalf("live parse %q: %v", line, lerr)
		}

		if liveReq.UserAgent != staticReq.UserAgent {
			t.Errorf("UA parity broken for %q:\n  live   = %q\n  static = %q",
				line, liveReq.UserAgent, staticReq.UserAgent)
		}
		// Pin the concrete expected value so an all-empty (or otherwise matching
		// but wrong) result cannot pass the equality check vacuously.
		if liveReq.UserAgent != tc.wantUA {
			t.Errorf("UA for %q = %q, want %q", line, liveReq.UserAgent, tc.wantUA)
		}
		if staticReq.UserAgent != tc.wantUA {
			t.Errorf("static UA for %q = %q, want %q", line, staticReq.UserAgent, tc.wantUA)
		}
	}
}
