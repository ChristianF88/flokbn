package ingestor

import (
	"errors"
	"fmt"
	"math/rand"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ChristianF88/flokbn/accesslog"
	"github.com/ChristianF88/flokbn/logparser"
)

// Differential test: the hardcoded live parser that TCPIngestor used to have
// (kept as legacyParseLine in legacy_parser_test.go) against the compiled
// default live format (logparser.DefaultLiveLogFormat through
// logparser.LineParser), which replaced it.
//
// Three layers:
//
//   - TestLiveParserDiff_Corpus runs every log line of the ingestor tests and
//     the logparser fuzz seeds through both parsers. A line either parses
//     identically in every field (liveParserSameCorpus), or it is listed in
//     liveParserDivergences with what each parser makes of it and why the new
//     result is accepted.
//   - TestLiveParserDiff_Generated requires identical results for generated
//     well-formed combined-log lines (random addresses, users, zone offsets,
//     escaped quotes, "-" fields).
//   - FuzzLiveParserDiff holds the properties that survive arbitrary input:
//     no panic, an accepted line has an address and a timestamp, both parsers
//     agree on the address whenever both accept, and the new parser drops a
//     line the old one took only for the two listed reasons.
//
// Arbitrary malformed input is deliberately NOT required to parse the same.
// The old parser searched for the next quote or bracket from wherever it was;
// the compiled format takes the fields by position. Once a line is not a
// combined-log line the two disagree in ways that cannot be enumerated, and
// the fields involved (method, URI, status, bytes, User-Agent) only feed the
// optional filters. Which lines are dropped is what decides detection, and
// the fuzz target pins that.
//
// Not visible in the compared values, and also different on purpose:
//
//   - Request.IP (the legacy net.IP) is no longer filled: nothing reads it,
//     and filling it cost one allocation per event. GetIPNet derives it.
//   - Request.Timestamp carries a named fixed zone ("+0200") or UTC instead of
//     time.Local or an unnamed zone. Instant and offset are the same.
//   - The reasons for dropping a line are the fixed values
//     logparser.ErrInvalidIP and ErrInvalidTimestamp. The old texts, including
//     the IPv6-specific one, were never shown to anyone: ReadBatch only counts.
//   - A malformed status or bytes field on a line that is then dropped is
//     counted, as in a file parse. The old parser dropped such a line before
//     it reached those fields.

// outcome is what a parser made of one line, reduced to comparable values.
type outcome struct {
	rejected  bool
	ip        uint32
	unix      int64 // the instant
	zone      int   // seconds east of UTC
	method    HTTPMethod
	uri       string
	status    uint16
	bytes     uint32
	userAgent string
	malformed int
}

var methodNames = map[HTTPMethod]string{
	GET: "GET", POST: "POST", PUT: "PUT", DELETE: "DELETE",
	HEAD: "HEAD", OPTIONS: "OPTIONS", PATCH: "PATCH", UNKNOWN: "UNKNOWN",
}

// String renders an outcome the way liveParserDivergences spells it:
//
//	1.2.3.4 2024-03-12T15:04:05-0700 GET "/x" 200 10 ua="UA" malformed=0
func (o outcome) String() string {
	if o.rejected {
		return "rejected"
	}
	ts := time.Unix(o.unix, 0).In(time.FixedZone("", o.zone)).Format("2006-01-02T15:04:05-0700")
	return fmt.Sprintf("%s %s %s %q %d %d ua=%q malformed=%d",
		accesslog.Uint32ToIPString(o.ip), ts, methodNames[o.method], o.uri, o.status, o.bytes, o.userAgent, o.malformed)
}

func outcomeOf(req *Request, malformed int, err error) outcome {
	if err != nil {
		return outcome{rejected: true}
	}
	_, zone := req.Timestamp.Zone()
	return outcome{
		ip: req.IPUint32, unix: req.Timestamp.Unix(), zone: zone,
		method: req.Method, uri: req.URI, status: req.Status, bytes: req.Bytes,
		userAgent: req.UserAgent, malformed: malformed,
	}
}

// legacyOutcome parses line with the old parser, behind the same recover
// guard ReadBatch used.
func legacyOutcome(line string) (o outcome) {
	defer func() {
		if r := recover(); r != nil {
			o = outcome{rejected: true}
		}
	}()
	var req Request
	malformed, err := legacyParseLine(line, &req)
	return outcomeOf(&req, malformed, err)
}

// compiledOutcome parses line with lp. The malformed count is the growth of
// the parser's counters, so lp must not be shared between goroutines here.
func compiledOutcome(lp *logparser.LineParser, line string) (outcome, error) {
	var req Request
	before := lp.Stats()
	err := lp.ParseLine(line, &req)
	after := lp.Stats()
	malformed := int(after.MalformedStatus + after.MalformedBytes - before.MalformedStatus - before.MalformedBytes)
	return outcomeOf(&req, malformed, err), err
}

func defaultLiveParser(t testing.TB) *logparser.LineParser {
	t.Helper()
	lp, err := logparser.NewLineParser(logparser.DefaultLiveLogFormat)
	if err != nil {
		t.Fatalf("NewLineParser(DefaultLiveLogFormat): %v", err)
	}
	return lp
}

// liveParserSameCorpus: lines both parsers must read identically.
var liveParserSameCorpus = []string{
	// ingestor_test.go
	`notanip - - [12/Mar/2024:15:04:05 -0700] "GET / HTTP/1.1" 200 10 "-" "UA"`,
	`2001:db8::1 - - [12/Mar/2024:15:04:05 -0700] "GET / HTTP/1.1" 200 10 "-" "UA"`,
	`::1 - - [12/Mar/2024:15:04:05 -0700] "GET / HTTP/1.1" 200 10 "-" "UA"`,
	`::ffff:192.168.1.1 - - [12/Mar/2024:15:04:05 -0700] "GET / HTTP/1.1" 200 10 "-" "UA"`,
	`2001:db8::1 - - [12/Mar/2024:15:04:05 -0700] "GET /v6 HTTP/1.1" 200 1 "-" "UA"`,
	`10.0.0.1 - - [12/Mar/2024:15:04:05 -0700] "GET /ok HTTP/1.1" 200 1 "-" "UA"`,
	`192.168.1.1 - - [badtime] "GET / HTTP/1.1" 200 10 "-" "UA"`,
	`1.2.3.4 - - [06/Jul/2025:06:00:00 -0700] "GET / HTTP/1.1" 200 1 "-" "UA"`,
	`1.2.3.4 - - [06/Jul/2025:06:00:00 +0200] "GET / HTTP/1.1" 200 1 "-" "UA"`,
	`1.2.3.4 - - [06/Jul/2025:19:57:26] "GET / HTTP/1.1" 200 1 "-" "UA"`,
	`192.168.1.1 - - [12/Mar/2024:15:04:05 -0700] "GET / HTTP/1.1" 304 - "-" "UA"`,
	`192.168.1.1 - - [12/Mar/2024:15:04:05 -0700] "GET / HTTP/1.1" - - "-" "UA"`,
	`192.168.1.1 - - [12/Mar/2024:15:04:05 -0700] "GET / HTTP/1.1" 2XX 100 "-" "UA"`,
	`192.168.1.1 - - [12/Mar/2024:15:04:05 -0700] "GET / HTTP/1.1" 200 12x4 "-" "UA"`,
	`192.168.1.100 - - [12/Mar/2024:15:04:05 -0700] "GET / HTTP/1.1" 200 10 "-" "UA"`,
	`192.168.1.1 - - [12/Mar/2024:15:04:05 -0700] "FOO /foo HTTP/1.1" 404 0 "-" "UA"`,
	`192.168.1.1 - - [12/Mar/2024:15:04:05 -0700] "GET / HTTP/1.1" 200 10 "-" `,
	`192.168.1.1 - - [12/Mar/2024:15:04:05 -0700] "GET / HTTP/1.1"`,
	`192.168.1.1 - - [12/Mar/2024:15:04:05 -0700] "GET / HTTP/1.1" 200 10 "-" "UA"`,
	`1.2.3.4 - - [12/Mar/2024:15:04:05 -0700] "GET /a\"b HTTP/1.1" 200 10 "-" "RealUA"`,
	`1.2.3.4 - - [12/Mar/2024:15:04:05 -0700] "GET / HTTP/1.1" 200 10 "ref\"erer" "RealUA"`,
	`1.2.3.4 - - [12/Mar/2024:15:04:05 -0700] "GET /a\"b HTTP/1.1" 200 10 "r\"ef" "RealUA"`,
	`1.2.3.4 - - [12/Mar/2024:15:04:05 -0700] "GET / HTTP/1.1" 200 10 "-" "Mozilla\"Evil"`,
	`1.2.3.4 - - [12/Mar/2024:15:04:05 -0700] "GET /x\\" 200 10 "-" "RealUA"`,
	`1.2.3.4 - - [12/Mar/2024:15:04:05 -0700] "GET /a\\\"b HTTP/1.1" 200 10 "-" "RealUA"`,
	`1.2.3.4 - - [12/Mar/2024:15:04:05 -0700] "GET /api/users HTTP/1.1" 200 1024 "https://example.com/" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"`,
	`1.2.3.4 - - [12/Mar/2024:15:04:05 -0700] "GET /a\"b HTTP/1.1" 200 1024 "ref\"erer" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"`,
	`127.0.0.1 - - [12/Mar/2024:15:04:05 -0700] "GET /foo HTTP/1.1" 200 123 "-" "TestUA"`,
	`10.0.0.1 - - [12/Mar/2024:15:04:05 -0700] "POST /bar HTTP/1.1" 201 10 "-" "UA1"`,
	`10.0.0.2 - - [12/Mar/2024:15:05:05 -0700] "GET /baz HTTP/1.1" 404 0 "-" "UA2"`,
	`127.0.0.1 - - [12/Mar/2024:15:04:05 -0700] "GET /ok HTTP/1.1" 200 1 "-" "UA"`,
	// stats_test.go
	`192.168.1.1 - - [12/Mar/2024:15:04:05 -0700] "GET / HTTP/1.1" oops 10 "-" "UA"`,
	`192.168.1.1 - - [12/Mar/2024:15:04:05 -0700] "GET / HTTP/1.1" oops 12x4 "-" "UA"`,
	`10.0.0.1 - - [12/Mar/2024:15:04:05 -0700] "GET /a HTTP/1.1" 200 5 "-" "UA"`,
	`10.0.0.2 - - [12/Mar/2024:15:04:05 -0700] "GET /b HTTP/1.1" oops 5 "-" "UA"`,
	// timestamp_position_test.go: brackets in the ident and user fields
	`192.168.1.1 - [admin] [12/Mar/2024:15:04:05 -0700] "GET /x HTTP/1.1" 200 10 "-" "UA"`,
	`192.168.1.1 [id] bob [12/Mar/2024:15:04:05 -0700] "GET /x HTTP/1.1" 200 10 "-" "UA"`,
	`192.168.1.1 - a[b [12/Mar/2024:15:04:05 -0700] "GET /x HTTP/1.1" 200 10 "-" "UA"`,
	`192.168.1.1 - a]b [12/Mar/2024:15:04:05 -0700] "GET /x HTTP/1.1" 200 10 "-" "UA"`,
	`192.168.1.1 ][ [] [12/Mar/2024:15:04:05 -0700] "GET /x HTTP/1.1" 200 10 "-" "UA"`,
	`192.168.1.1 - - [12/Mar/2024:15:04:05 -0700] "GET /x HTTP/1.1" 200 10 "-" "UA"`,
	`192.168.1.1 - - [12/Mar/2024:15:04:05 -0700] "GET /x HTTP/1.1" 200 10 "http://r/?a[0]=1" "UA"`,
	// timestamp_position_test.go: timestamp not in fourth position. The old
	// parser fell back to the first bracket, the new one re-aligns on the
	// first bracket that holds a timestamp.
	`192.168.1.1 [12/Mar/2024:15:04:05 +0000] "GET /x HTTP/1.1" 200 10 "-" "UA"`,
	`192.168.1.1 [12/Mar/2024:15:04:05] "GET /x HTTP/1.1" 200 10 "-" "UA"`,
	`192.168.1.1 - [12/Mar/2024:15:04:05 +0000] "GET /x HTTP/1.1" 200 10 "-" "UA"`,
	`192.168.1.1 - - - [12/Mar/2024:15:04:05 +0000] "GET /x HTTP/1.1" 200 10 "-" "UA"`,
	`192.168.1.1 - john doe [12/Mar/2024:15:04:05 +0000] "GET /x HTTP/1.1" 200 10 "-" "UA"`,
	// timestamp_position_test.go: still rejected
	`192.168.1.1 - [admin] 12/Mar/2024 "GET / HTTP/1.1" 200 10 "-" "UA"`,
	`192.168.1.1 `,
	`192.168.1.1 - - `,
	// ingestor_lifecycle_test.go, lumberjack_test.go, wire_bench_test.go
	`10.1.2.3 - - [12/Mar/2024:15:04:05 +0000] "GET /a HTTP/1.1" 200 123 "-" "TestUA"`,
	`203.0.113.7 - - [12/Mar/2024:15:04:05 -0700] "GET /ok HTTP/1.1" 200 5 "-" "UA"`,
	`203.0.113.7 - - [12/Mar/2024:15:04:05 -0700] "GET /` + strings.Repeat("x", 1100) + ` HTTP/1.1" 200 5 "-" "UA"`,
	`198.51.0.1 - - [12/Mar/2024:15:04:05 -0700] "GET /api/items/1?page=2 HTTP/1.1" 200 5123 "https://example.com/list" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0 Safari/537.36"`,
	// live_static_ua_parity_test.go
	`1.2.3.4 - - [12/Mar/2024:15:04:05 -0700] "GET /a\"b HTTP/1.1" 200 10 "-" "UA\"X"`,
	`1.2.3.4 - - [12/Mar/2024:15:04:05 -0700] "GET / HTTP/1.1" 200 10 "-" ""`,
	// logparser fuzz seeds (FuzzParser, FuzzLogFormatParsing)
	`198.51.10.21 - - [06/Jul/2025:19:57:26 +0000] "GET /dataset/?test HTTP/1.0" 200 13984 "-" "Mozilla/5.0" "14.191.169.89"`,
	`192.168.1.100 - - [01/Jan/2025:10:15:30 +0000] "GET /api/users HTTP/1.1" 200 1024 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" "10.0.0.1"`,
	`10.0.0.1 - frank [10/Oct/2025:13:55:36 +0200] "POST /admin/login HTTP/1.1" 401 2326 "https://example.com/login" "curl/7.68.0" "10.0.0.1"`,
	``,
	`short`,
	"   \t\t   ",
	`badip - - [invalid-date] "INVALID" 999 NaN "malformed" "agent" "192.168.1.1"`,
	`192.168.1.1 - - [01/Jan/2025:00:00:00 +0000] "GET /` + string(make([]byte, 8192)) + ` HTTP/1.1" 200 0 "-" "test" "192.168.1.1"`,
	"192.168.1.1 - - [01/Jan/2025:00:00:00 +0000] \"GET /\x00path HTTP/1.1\" 200 0 \"-\" \"test\" \"192.168.1.1\"",
	`192.168.1.1 - - [01/Jan/2025:00:00:00 +0000] "GET /path HTTP/1.1" 200 10 "-" "Mozilla \"Edge\" Browser" "192.168.1.1"`,
	`192.168.1.1 - - [01/Jan/2025:00:00:00 +0000] "GET / HTTP/1.1" 2XX 10 "-" "test" "192.168.1.1"`,
	`10.0.0.1 - - [23/Nov/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 123 "http://a b" "8.8.8.7" "203.0.113.9"`,
	"192.168.1.1 - - [01/Jan/2025:00:00:00 +0000] \"GET / HTTP/1.1\" 200 10 \"-\" \"test\" \"192.168.1.1\"\r\n",
	`192.168.1.1 - - [01/Jan/2025:00:00:00 +0000] "GET / HTTP/1.1" 200 0 "-" "test" "192.168.1.1"`,
	// further shapes that must not differ
	`1.2.3.4 - - [31/Feb/2024:15:04:05 +0000] "GET / HTTP/1.1" 200 1 "-" "UA"`,
	`1.2.3.4 - - [12/Mar/2024:15:04:05.123 +0000] "GET / HTTP/1.1" 200 1 "-" "UA"`,
	`1.2.3.4 - - [12/Mar/2024:15:04:05 +0000] "get / HTTP/1.1" 200 1 "-" "UA"`,
	`1.2.3.4 - - [12/Mar/2024:15:04:05 +0000] "GET  /x  HTTP/1.1" 200 1 "-" "UA"`,
	`1.2.3.4 - - [12/Mar/2024:15:04:05 +0000] "GET / HTTP/1.1" 200 5`,
	`1.2.3.4 - - [12/Mar/2024:15:04:05 +0000] "GET / HTTP/1.1" 200 99999999999 "-" "UA"`,
	`1.2.3.4 - "john doe" [12/Mar/2024:15:04:05 +0000] "GET /x HTTP/1.1" 200 10 "-" "UA"`,
	`1.2.3.4 - - [12/Mar/2024:15:04:05 +0000] "GET /x HTTP/1.1" 200 10 "-" "UA" "10.9.8.7" rt=0.004`,
	`198.51.100.1, 203.0.113.7 - - [12/Mar/2024:15:04:05 +0000] "GET / HTTP/1.1" 200 1 "-" "UA"`,
	`1.2.3.4`,
	`nope - - [12/Mar/2024:15:04:05 +0000] "GET /x HTTP/1.1" oops 10 "-" "UA"`,
}

// liveParserDivergences: every line of the corpus the two parsers read
// differently, with both results pinned and the decision taken.
var liveParserDivergences = []struct {
	name     string
	line     string
	old, new string
	decision string
}{
	// --- client address ---
	{
		name:     "address 0.0.0.0",
		line:     `0.0.0.0 - - [12/Mar/2024:15:04:05 +0000] "GET / HTTP/1.1" 200 1 "-" "UA"`,
		old:      `0.0.0.0 2024-03-12T15:04:05+0000 GET "/" 200 1 ua="UA" malformed=0`,
		new:      `rejected`,
		decision: "wanted: 0 means 'no address' in the whole pipeline; the live loop skipped such a request anyway",
	},
	{
		name:     "address with a leading zero",
		line:     `010.1.2.3 - - [12/Mar/2024:15:04:05 +0000] "GET / HTTP/1.1" 200 1 "-" "UA"`,
		old:      `rejected`,
		new:      `10.1.2.3 2024-03-12T15:04:05+0000 GET "/" 200 1 ua="UA" malformed=0`,
		decision: "accepted: the compiled parser's documented IPv4 contract (1-3 digits per octet), same as static",
	},
	{
		name:     "leading space",
		line:     ` 1.2.3.4 - - [12/Mar/2024:15:04:05 +0000] "GET / HTTP/1.1" 200 1 "-" "UA"`,
		old:      `rejected`,
		new:      `1.2.3.4 2024-03-12T15:04:05+0000 GET "/" 200 1 ua="UA" malformed=0`,
		decision: "accepted: every field skips leading spaces, same as static",
	},
	{
		name:     "quoted address",
		line:     `"1.2.3.4" - - [12/Mar/2024:15:04:05 +0000] "GET / HTTP/1.1" 200 1 "-" "UA"`,
		old:      `rejected`,
		new:      `1.2.3.4 2024-03-12T15:04:05+0000 GET "/" 200 1 ua="UA" malformed=0`,
		decision: "accepted: a value that starts with a quote is read as a quoted field, same as static",
	},
	{
		name:     "forwarded list",
		line:     `198.51.100.1,203.0.113.7 - - [12/Mar/2024:15:04:05 +0000] "GET / HTTP/1.1" 200 1 "-" "UA"`,
		old:      `rejected`,
		new:      `203.0.113.7 2024-03-12T15:04:05+0000 GET "/" 200 1 ua="UA" malformed=0`,
		decision: "wanted: rightmost element of an X-Forwarded-For list, the one the nearest proxy appended",
	},
	{
		name:     "quoted forwarded list",
		line:     `"198.51.100.1, 203.0.113.7" - - [12/Mar/2024:15:04:05 +0000] "GET / HTTP/1.1" 200 1 "-" "UA"`,
		old:      `rejected`,
		new:      `203.0.113.7 2024-03-12T15:04:05+0000 GET "/" 200 1 ua="UA" malformed=0`,
		decision: "wanted: rightmost element of an X-Forwarded-For list",
	},

	// --- timestamp: stricter ---
	{
		name:     "lower-case month",
		line:     `1.2.3.4 - - [12/mar/2024:15:04:05 +0000] "GET / HTTP/1.1" 200 1 "-" "UA"`,
		old:      `1.2.3.4 2024-03-12T15:04:05+0000 GET "/" 200 1 ua="UA" malformed=0`,
		new:      `rejected`,
		decision: "wanted: strict timestamp (time.Parse matched month names case-insensitively)",
	},
	{
		name:     "one-digit hour",
		line:     `1.2.3.4 - - [12/Mar/2024:5:04:05 +0000] "GET / HTTP/1.1" 200 1 "-" "UA"`,
		old:      `1.2.3.4 2024-03-12T05:04:05+0000 GET "/" 200 1 ua="UA" malformed=0`,
		new:      `rejected`,
		decision: "wanted: strict timestamp (time.Parse took a one-digit hour)",
	},

	// --- timestamp: the zone offset is read from fixed columns ---
	{
		name:     "two spaces before the offset",
		line:     `1.2.3.4 - - [12/Mar/2024:15:04:05  -0700] "GET / HTTP/1.1" 200 1 "-" "UA"`,
		old:      `1.2.3.4 2024-03-12T15:04:05-0700 GET "/" 200 1 ua="UA" malformed=0`,
		new:      `1.2.3.4 2024-03-12T15:04:05+0000 GET "/" 200 1 ua="UA" malformed=0`,
		decision: "accepted: an offset that is not ' +HHMM' at its fixed position reads as UTC wall clock, same as static; no server writes this",
	},
	{
		name:     "offset with a colon",
		line:     `1.2.3.4 - - [12/Mar/2024:15:04:05 +07:00] "GET / HTTP/1.1" 200 1 "-" "UA"`,
		old:      `rejected`,
		new:      `1.2.3.4 2024-03-12T15:04:05+0000 GET "/" 200 1 ua="UA" malformed=0`,
		decision: "accepted: unreadable offset reads as UTC wall clock instead of dropping the line, same as static",
	},
	{
		name:     "text after the offset",
		line:     `1.2.3.4 - - [12/Mar/2024:15:04:05 +0000 extra] "GET / HTTP/1.1" 200 1 "-" "UA"`,
		old:      `rejected`,
		new:      `1.2.3.4 2024-03-12T15:04:05+0000 GET "/" 200 1 ua="UA" malformed=0`,
		decision: "accepted: bytes after the timestamp inside the brackets are ignored, same as static",
	},
	{
		name:     "timestamp without brackets",
		line:     `192.168.1.1 - - 12/Mar/2024:15:04:05 "GET / HTTP/1.1" 200 10 "-" "UA"`,
		old:      `rejected`,
		new:      `192.168.1.1 2024-03-12T15:04:05+0000 GET "/" 200 10 ua="UA" malformed=0`,
		decision: "accepted: the value in the %t position is a valid timestamp; the brackets are optional, same as static",
	},
	{
		name:     "unterminated timestamp bracket",
		line:     `192.168.1.1 - - [12/Mar/2024:15:04:05 +0000 "GET / HTTP/1.1" 200 10 "-" "UA"`,
		old:      `rejected`,
		new:      `192.168.1.1 2024-03-12T15:04:05+0000 GET "" 0 0 ua="" malformed=0`,
		decision: "accepted: address and timestamp are valid, the rest of the line is inside the bracket; same as static",
	},

	// --- timestamp located by re-alignment ---
	{
		name:     "user with a space and an open bracket",
		line:     `1.2.3.4 - x [y [12/Mar/2024:15:04:05 +0000] "GET /x HTTP/1.1" 200 10 "-" "UA"`,
		old:      `rejected`,
		new:      `1.2.3.4 2024-03-12T15:04:05+0000 GET "/x" 200 10 ua="UA" malformed=0`,
		decision: "wanted: the old fallback tried only the first bracket; re-alignment takes the first one that holds a timestamp, so this client can no longer hide",
	},
	{
		name:     "timestamp out of position with more bracketed fields behind it",
		line:     `192.168.1.1 [12/Mar/2024:15:04:05] x [y] "GET /x HTTP/1.1" 200 10 "-" "UA"`,
		old:      `192.168.1.1 2024-03-12T15:04:05+0000 GET "/x" 200 10 ua="UA" malformed=0`,
		new:      `192.168.1.1 2024-03-12T15:04:05+0000 UNKNOWN "" 0 0 ua="10" malformed=2`,
		decision: "accepted: address and timestamp agree; the fields behind the timestamp follow the format, and this layout needs its own logFormat",
	},
	{
		name:     "user field that is itself a timestamp",
		line:     `1.2.3.4 - [01/Jan/2020:00:00:00 +0000] [12/Mar/2024:15:04:05 +0000] "GET /x HTTP/1.1" 200 10 "-" "UA"`,
		old:      `1.2.3.4 2020-01-01T00:00:00+0000 GET "/x" 200 10 ua="UA" malformed=0`,
		new:      `1.2.3.4 2020-01-01T00:00:00+0000 UNKNOWN "" 0 0 ua="10" malformed=2`,
		decision: "accepted: both take the forged timestamp (unchanged weakness of an unquoted user field); only the filter fields differ",
	},

	// --- request line ---
	{
		name:     "method outside the known set",
		line:     `1.2.3.4 - - [12/Mar/2024:15:04:05 +0000] "PROPFIND /dav HTTP/1.1" 207 1 "-" "UA"`,
		old:      `1.2.3.4 2024-03-12T15:04:05+0000 UNKNOWN "/dav" 207 1 ua="UA" malformed=0`,
		new:      `1.2.3.4 2024-03-12T15:04:05+0000 PUT "/dav" 207 1 ua="UA" malformed=0`,
		decision: "accepted: the compiled parser classifies the method by its first letters; Method is not read anywhere",
	},
	{
		name:     "request line is a dash",
		line:     `1.2.3.4 - - [12/Mar/2024:15:04:05 +0000] "-" 400 0 "-" "-"`,
		old:      `1.2.3.4 2024-03-12T15:04:05+0000 GET "" 400 0 ua="-" malformed=0`,
		new:      `1.2.3.4 2024-03-12T15:04:05+0000 UNKNOWN "" 400 0 ua="-" malformed=0`,
		decision: "accepted: UNKNOWN is the better answer than the zero value GET; Method is not read anywhere",
	},
	{
		name:     "request line is binary garbage",
		line:     `1.2.3.4 - - [12/Mar/2024:15:04:05 +0000] "\x16\x03\x01" 400 157 "-" "-"`,
		old:      `1.2.3.4 2024-03-12T15:04:05+0000 GET "" 400 157 ua="-" malformed=0`,
		new:      `1.2.3.4 2024-03-12T15:04:05+0000 UNKNOWN "" 400 157 ua="-" malformed=0`,
		decision: "accepted: as above",
	},
	{
		name:     "tab inside the request line",
		line:     "1.2.3.4 - - [12/Mar/2024:15:04:05 +0000] \"GET\t/x HTTP/1.1\" 200 1 \"-\" \"UA\"",
		old:      `1.2.3.4 2024-03-12T15:04:05+0000 GET "/x" 200 1 ua="UA" malformed=0`,
		new:      `1.2.3.4 2024-03-12T15:04:05+0000 GET "HTTP/1.1" 200 1 ua="UA" malformed=0`,
		decision: "accepted: the request line is split at spaces only, same as static; web servers escape control bytes in the log",
	},
	{
		name:     "request line starts with a space",
		line:     `1.2.3.4 - - [12/Mar/2024:15:04:05 +0000] " GET /x HTTP/1.1" 200 1 "-" "UA"`,
		old:      `1.2.3.4 2024-03-12T15:04:05+0000 GET "/x" 200 1 ua="UA" malformed=0`,
		new:      `1.2.3.4 2024-03-12T15:04:05+0000 GET "GET" 200 1 ua="UA" malformed=0`,
		decision: "accepted: the method is the text up to the first space, same as static; only endpointRegex sees the difference",
	},

	// --- status and bytes (not read anywhere; only the malformed counter shows) ---
	{
		name:     "four-digit status",
		line:     `1.2.3.4 - - [12/Mar/2024:15:04:05 +0000] "GET / HTTP/1.1" 1000 1 "-" "UA"`,
		old:      `1.2.3.4 2024-03-12T15:04:05+0000 GET "/" 1000 1 ua="UA" malformed=0`,
		new:      `1.2.3.4 2024-03-12T15:04:05+0000 GET "/" 0 1 ua="UA" malformed=1`,
		decision: "accepted: a status is exactly three digits, same as static",
	},
	{
		name:     "two-digit status",
		line:     `1.2.3.4 - - [12/Mar/2024:15:04:05 +0000] "GET / HTTP/1.1" 99 1 "-" "UA"`,
		old:      `1.2.3.4 2024-03-12T15:04:05+0000 GET "/" 99 1 ua="UA" malformed=0`,
		new:      `1.2.3.4 2024-03-12T15:04:05+0000 GET "/" 0 1 ua="UA" malformed=1`,
		decision: "accepted: as above",
	},
	{
		name:     "negative bytes",
		line:     `1.2.3.4 - - [12/Mar/2024:15:04:05 +0000] "GET / HTTP/1.1" 200 -5 "-" "UA"`,
		old:      `1.2.3.4 2024-03-12T15:04:05+0000 GET "/" 200 4294967291 ua="UA" malformed=0`,
		new:      `1.2.3.4 2024-03-12T15:04:05+0000 GET "/" 200 0 ua="UA" malformed=0`,
		decision: "accepted: a bytes value starting with '-' is the absent value, same as static (the old result was a wrapped negative)",
	},
	{
		name:     "bytes with a plus sign",
		line:     `1.2.3.4 - - [12/Mar/2024:15:04:05 +0000] "GET / HTTP/1.1" 200 +5 "-" "UA"`,
		old:      `1.2.3.4 2024-03-12T15:04:05+0000 GET "/" 200 5 ua="UA" malformed=0`,
		new:      `1.2.3.4 2024-03-12T15:04:05+0000 GET "/" 200 0 ua="UA" malformed=1`,
		decision: "accepted: bytes is digits only, same as static",
	},
	{
		name:     "status without bytes",
		line:     `1.2.3.4 - - [12/Mar/2024:15:04:05 +0000] "GET / HTTP/1.1" 200`,
		old:      `1.2.3.4 2024-03-12T15:04:05+0000 GET "/" 0 0 ua="" malformed=0`,
		new:      `1.2.3.4 2024-03-12T15:04:05+0000 GET "/" 200 0 ua="" malformed=0`,
		decision: "accepted: the status that is there is read (the old parser wanted both or neither)",
	},

	// --- referer and User-Agent ---
	{
		name:     "unquoted referer",
		line:     `1.2.3.4 - - [12/Mar/2024:15:04:05 +0000] "GET / HTTP/1.1" 200 5 - "UA"`,
		old:      `1.2.3.4 2024-03-12T15:04:05+0000 GET "/" 200 5 ua="" malformed=0`,
		new:      `1.2.3.4 2024-03-12T15:04:05+0000 GET "/" 200 5 ua="UA" malformed=0`,
		decision: "wanted: the User-Agent is the field behind the referer, not the second quoted string",
	},
	{
		name:     "unterminated User-Agent",
		line:     `1.2.3.4 - - [12/Mar/2024:15:04:05 +0000] "GET / HTTP/1.1" 200 5 "-" "Mozilla/5.0 (trunc`,
		old:      `1.2.3.4 2024-03-12T15:04:05+0000 GET "/" 200 5 ua="" malformed=0`,
		new:      `1.2.3.4 2024-03-12T15:04:05+0000 GET "/" 200 5 ua="Mozilla/5.0 (trunc" malformed=0`,
		decision: "accepted: a quoted field without its closing quote runs to the end of the line, same as static",
	},
	{
		name:     "unterminated User-Agent after a malformed status",
		line:     `1.2.3.4 - - [12/Mar/2024:15:04:05 +0000] "GET /x HTTP/1.1" oops 10 "-" "UA`,
		old:      `1.2.3.4 2024-03-12T15:04:05+0000 GET "/x" 0 10 ua="" malformed=1`,
		new:      `1.2.3.4 2024-03-12T15:04:05+0000 GET "/x" 0 10 ua="UA" malformed=1`,
		decision: "accepted: as above",
	},
	{
		name:     "unquoted User-Agent",
		line:     `1.2.3.4 - - [12/Mar/2024:15:04:05 +0000] "GET / HTTP/1.1" 200 5 "-" UA`,
		old:      `1.2.3.4 2024-03-12T15:04:05+0000 GET "/" 200 5 ua="" malformed=0`,
		new:      `1.2.3.4 2024-03-12T15:04:05+0000 GET "/" 200 5 ua="UA" malformed=0`,
		decision: "accepted: a bare token in the %u position is the value, same as static",
	},

	// --- truncated and non-combined lines: kept instead of dropped ---
	{
		name:     "line ends after the timestamp",
		line:     `1.2.3.4 - - [12/Mar/2024:15:04:05 +0000]`,
		old:      `rejected`,
		new:      `1.2.3.4 2024-03-12T15:04:05+0000 GET "" 0 0 ua="" malformed=0`,
		decision: "accepted: address and timestamp are all detection needs; same as static, which keeps every line with a valid address",
	},
	{
		name:     "line ends inside the request",
		line:     `1.2.3.4 - - [12/Mar/2024:15:04:05 +0000] "GET /trunc`,
		old:      `rejected`,
		new:      `1.2.3.4 2024-03-12T15:04:05+0000 GET "/trunc" 0 0 ua="" malformed=0`,
		decision: "accepted: as above",
	},
	{
		name:     "request line without quotes",
		line:     `1.2.3.4 - - [12/Mar/2024:15:04:05 +0000] GET / HTTP/1.1 200 5`,
		old:      `rejected`,
		new:      `1.2.3.4 2024-03-12T15:04:05+0000 GET "" 0 0 ua="5" malformed=2`,
		decision: "accepted: the request is counted for its address; the other fields follow the format and this layout needs its own logFormat",
	},
	{
		name:     "text glued to the closing quote of the request",
		line:     `1.2.3.4 - - [12/Mar/2024:15:04:05 +0000] "GET /x HTTP/1.1"- 200 10 "-" "UA"`,
		old:      `1.2.3.4 2024-03-12T15:04:05+0000 GET "/x" 200 10 ua="UA" malformed=0`,
		new:      `1.2.3.4 2024-03-12T15:04:05+0000 GET "/x" 0 200 ua="-" malformed=0`,
		decision: "accepted: fields are taken by position, same as static; not a line a web server writes",
	},
	{
		name:     "request line with a missing closing quote (logparser fuzz seed)",
		line:     `192.168.1.1 - - [01/Jan/2025:00:00:00 +0000] "GET /path HTTP/1.1 200 0 "-" "test" "192.168.1.1"`,
		old:      `192.168.1.1 2025-01-01T00:00:00+0000 GET "/path" 0 0 ua=" " malformed=2`,
		new:      `192.168.1.1 2025-01-01T00:00:00+0000 GET "/path" 0 0 ua="" malformed=2`,
		decision: "accepted: as above",
	},
}

func TestLiveParserDiff_Corpus(t *testing.T) {
	lp := defaultLiveParser(t)

	for _, line := range liveParserSameCorpus {
		old := legacyOutcome(line)
		got, _ := compiledOutcome(lp, line)
		if old != got {
			t.Errorf("unlisted divergence for %.200q\n  old: %s\n  new: %s", line, old, got)
		}
	}

	for _, d := range liveParserDivergences {
		t.Run(d.name, func(t *testing.T) {
			if d.decision == "" {
				t.Fatal("divergence without a decision")
			}
			old := legacyOutcome(d.line)
			got, _ := compiledOutcome(lp, d.line)
			if old.String() != d.old {
				t.Errorf("old parser:\n  got  %s\n  want %s", old, d.old)
			}
			if got.String() != d.new {
				t.Errorf("compiled format:\n  got  %s\n  want %s", got, d.new)
			}
			if d.old == d.new {
				t.Error("listed as a divergence but both results are the same")
			}
		})
	}
}

// --- generated well-formed lines ---

var genMonths = []string{"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"}

func pick(rng *rand.Rand, options ...string) string {
	return options[rng.Intn(len(options))]
}

// genQuotedContent builds the inside of a quoted field from tokens that keep
// the closing quote unescaped: plain bytes, an escaped quote, an escaped
// backslash. spaces says whether the field may hold spaces.
func genQuotedContent(rng *rand.Rand, maxTokens int, spaces bool) string {
	const plain = `abcXYZ019/?&=%._-:;()[]+,~`
	var sb strings.Builder
	for n := rng.Intn(maxTokens + 1); n > 0; n-- {
		switch r := rng.Intn(20); {
		case r == 0:
			sb.WriteString(`\"`)
		case r == 1:
			sb.WriteString(`\\`)
		case r == 2 && spaces:
			sb.WriteByte(' ')
		default:
			sb.WriteByte(plain[rng.Intn(len(plain))])
		}
	}
	return sb.String()
}

// genCombinedLine returns one well-formed combined-log line as a web server
// would write it: canonical non-zero address, two-digit timestamp fields,
// known method, three-digit status or "-", digits or "-" for bytes.
func genCombinedLine(rng *rand.Rand) string {
	ip := fmt.Sprintf("%d.%d.%d.%d", 1+rng.Intn(254), rng.Intn(256), rng.Intn(256), rng.Intn(256))
	ident := pick(rng, "-", "-", "-", "id", "a]b", "[x]")
	user := pick(rng, "-", "-", "frank", "a[b", "bob@example.com", "[admin]", `d"q`)
	if ident == "-" && rng.Intn(10) == 0 {
		user = "john doe" // re-aligned by the new parser, bracket fallback in the old one
	}

	ts := fmt.Sprintf("%02d/%s/%04d:%02d:%02d:%02d",
		1+rng.Intn(28), genMonths[rng.Intn(12)], 1990+rng.Intn(60), rng.Intn(24), rng.Intn(60), rng.Intn(60))
	switch rng.Intn(4) {
	case 0: // zone-less
	case 1:
		ts += " +0000"
	default:
		ts += fmt.Sprintf(" %s%02d%s", pick(rng, "+", "-"), rng.Intn(15), pick(rng, "00", "30", "45"))
	}

	method := pick(rng, "GET", "GET", "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH")
	uri := "/" + genQuotedContent(rng, 40, false)
	proto := pick(rng, "HTTP/1.0", "HTTP/1.1", "HTTP/2.0")

	status := "-"
	if rng.Intn(20) != 0 {
		status = fmt.Sprintf("%d", 100+rng.Intn(500))
	}
	size := "-"
	if rng.Intn(10) != 0 {
		size = fmt.Sprintf("%d", rng.Intn(1_000_000_000))
	}

	referer := "-"
	if rng.Intn(2) == 0 {
		referer = "https://example.com/" + genQuotedContent(rng, 30, true)
	}
	userAgent := pick(rng, "-", "", "curl/8.5.0")
	if rng.Intn(2) == 0 {
		userAgent = "Mozilla/5.0 " + genQuotedContent(rng, 60, true)
	}
	tail := pick(rng, "", "", ` "10.9.8.7"`, ` rt=0.004 "-"`)

	return fmt.Sprintf(`%s %s %s [%s] "%s %s %s" %s %s "%s" "%s"%s`,
		ip, ident, user, ts, method, uri, proto, status, size, referer, userAgent, tail)
}

func TestLiveParserDiff_Generated(t *testing.T) {
	lp := defaultLiveParser(t)
	rng := rand.New(rand.NewSource(20261123))
	const lines = 50000
	for i := 0; i < lines; i++ {
		line := genCombinedLine(rng)
		old := legacyOutcome(line)
		got, _ := compiledOutcome(lp, line)
		if old.rejected {
			t.Fatalf("generator produced a line the old parser rejects: %q", line)
		}
		if old != got {
			t.Fatalf("divergence on a well-formed line (#%d)\n  line: %q\n  old:  %s\n  new:  %s", i, line, old, got)
		}
	}
}

// --- arbitrary input ---

// strictBracketTimestamp matches the inside of a timestamp bracket the way a
// web server writes it. Together with time.Parse (ranges, days per month) it
// is an independent statement of "this is a timestamp".
var strictBracketTimestamp = regexp.MustCompile(
	`^\d{2}/(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)/\d{4}:\d{2}:\d{2}:\d{2}( [+-]\d{4})?$`)

// hasBracketedTimestamp reports whether some "[...]" in line holds a strictly
// formatted, valid timestamp.
func hasBracketedTimestamp(line string) bool {
	for i := 0; i < len(line); i++ {
		if line[i] != '[' {
			continue
		}
		rest := line[i+1:]
		if len(rest) > 64 {
			rest = rest[:64]
		}
		n := strings.IndexByte(rest, ']')
		if n < 0 || !strictBracketTimestamp.MatchString(rest[:n]) {
			continue
		}
		layout := "02/Jan/2006:15:04:05 -0700"
		if n == 20 {
			layout = "02/Jan/2006:15:04:05"
		}
		if ts, err := time.Parse(layout, rest[:n]); err == nil && !ts.IsZero() {
			return true
		}
	}
	return false
}

// checkLiveParserProperties holds what must be true for ANY input.
func checkLiveParserProperties(t *testing.T, lp *logparser.LineParser, line string) {
	t.Helper()
	old := legacyOutcome(line)

	var req Request
	err := lp.ParseLine(line, &req) // must not panic
	switch {
	case err == nil:
		if req.IPUint32 == 0 || req.Timestamp.IsZero() {
			t.Fatalf("accepted without an address or a timestamp: %+v\n  line: %q", req, line)
		}
		// Same client whenever both parsers take the line.
		if !old.rejected && old.ip != req.IPUint32 {
			t.Fatalf("address differs: old %s, new %s\n  line: %q",
				accesslog.Uint32ToIPString(old.ip), accesslog.Uint32ToIPString(req.IPUint32), line)
		}
	case errors.Is(err, logparser.ErrInvalidTimestamp):
		// A line is only dropped for its timestamp when no bracket in it
		// holds one (so the old parser took it for a lenient timestamp or an
		// unusual layout, see the divergence table).
		if hasBracketedTimestamp(line) {
			t.Fatalf("dropped for its timestamp although a bracket holds a valid one\n  line: %q", line)
		}
	case errors.Is(err, logparser.ErrInvalidIP):
		// The old parser accepted exactly one address the new one refuses.
		if !old.rejected && old.ip != 0 {
			t.Fatalf("old parser accepted address %s, new parser rejects the line\n  line: %q",
				accesslog.Uint32ToIPString(old.ip), line)
		}
	default:
		t.Fatalf("unexpected error %v\n  line: %q", err, line)
	}
}

func FuzzLiveParserDiff(f *testing.F) {
	for _, line := range liveParserSameCorpus {
		f.Add(line)
	}
	for _, d := range liveParserDivergences {
		f.Add(d.line)
	}
	lp := defaultLiveParser(f)
	f.Fuzz(func(t *testing.T, line string) {
		checkLiveParserProperties(t, lp, line)
	})
}

// TestLiveParserDiff_Mutations runs the fuzz properties over a fixed set of
// random mutations of the corpus, so they are exercised on every `go test`
// and not only when the fuzzer runs.
func TestLiveParserDiff_Mutations(t *testing.T) {
	lp := defaultLiveParser(t)
	var seeds []string
	for _, line := range liveParserSameCorpus {
		if len(line) < 400 {
			seeds = append(seeds, line)
		}
	}
	for _, d := range liveParserDivergences {
		seeds = append(seeds, d.line)
	}
	alphabet := []byte(`"[] \-,:.0159azGPJ/+` + "\t")
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 200000; i++ {
		b := []byte(seeds[rng.Intn(len(seeds))])
		for k := 1 + rng.Intn(3); k > 0 && len(b) > 0; k-- {
			pos := rng.Intn(len(b))
			switch rng.Intn(4) {
			case 0:
				b[pos] = alphabet[rng.Intn(len(alphabet))]
			case 1:
				b = append(b[:pos], b[pos+1:]...)
			case 2:
				b = append(b[:pos], append([]byte{alphabet[rng.Intn(len(alphabet))]}, b[pos:]...)...)
			case 3:
				b = b[:pos]
			}
		}
		checkLiveParserProperties(t, lp, string(b))
	}
}
