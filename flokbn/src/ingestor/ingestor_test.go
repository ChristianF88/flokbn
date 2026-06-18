package ingestor

import (
	"net"
	"testing"
	"time"

	lj "github.com/elastic/go-lumber/lj"
)

func TestParseEvent_MissingMessageField(t *testing.T) {
	evt := map[string]interface{}{}
	var req Request
	_, err := parseEvent(evt, &req)
	if err == nil || err.Error() != "missing message field" {
		t.Errorf("expected missing message field error, got %v", err)
	}
}

func TestParseEvent_InvalidIP(t *testing.T) {
	log := `notanip - - [12/Mar/2024:15:04:05 -0700] "GET / HTTP/1.1" 200 10 "-" "UA"`
	evt := map[string]interface{}{"message": log}
	var req Request
	_, err := parseEvent(evt, &req)
	if err == nil || err.Error() != "invalid IP" {
		t.Errorf("expected invalid IP error, got %v", err)
	}
}

// TestParseEvent_RejectsIPv6 is the URGENT-21 repro: an IPv6 source address
// (parsed fine by net.ParseIP) used to flow through as IP=<v6> with IPUint32=0
// and be counted as a successful request. It must now be rejected with an error
// and NEVER stored (no IP, no IPUint32). Covers both a plain IPv6 literal and
// the IPv4-mapped form, since both must be purged.
func TestParseEvent_RejectsIPv6(t *testing.T) {
	cases := []struct {
		name string
		ip   string
	}{
		{"PlainIPv6", "2001:db8::1"},
		{"Loopback", "::1"},
		{"MappedIPv6", "::ffff:192.168.1.1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			log := tc.ip + ` - - [12/Mar/2024:15:04:05 -0700] "GET / HTTP/1.1" 200 10 "-" "UA"`
			evt := map[string]interface{}{"message": log}
			var req Request
			_, err := parseEvent(evt, &req)
			if err == nil {
				t.Fatalf("expected error for IPv6 %q, got nil", tc.ip)
			}
			if req.IP != nil {
				t.Errorf("IPv6 must not be stored: req.IP = %v", req.IP)
			}
			if req.IPUint32 != 0 {
				t.Errorf("IPv6 must not set IPUint32: got %d", req.IPUint32)
			}
		})
	}
}

// TestReadBatch_RejectsIPv6 proves the live-loop path counts an IPv6 event as a
// parse error (the operator-visible reject counter) and never appends it to
// output or counts it as a successful request.
func TestReadBatch_RejectsIPv6(t *testing.T) {
	ing := &TCPIngestor{
		events: make(chan *lj.Batch, 1),
	}
	ipv6 := `2001:db8::1 - - [12/Mar/2024:15:04:05 -0700] "GET /v6 HTTP/1.1" 200 1 "-" "UA"`
	valid := `10.0.0.1 - - [12/Mar/2024:15:04:05 -0700] "GET /ok HTTP/1.1" 200 1 "-" "UA"`
	ing.events <- makeBatch(
		map[string]interface{}{"message": ipv6},
		map[string]interface{}{"message": valid},
	)

	got, err := ing.ReadBatch()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected only the IPv4 request, got %d results", len(got))
	}
	if got[0].URI != "/ok" {
		t.Errorf("expected the IPv4 request, got URI %v", got[0].URI)
	}

	st := ing.Stats()
	if st.RequestsTotal != 1 {
		t.Errorf("RequestsTotal = %d, want 1 (IPv6 not counted as success)", st.RequestsTotal)
	}
	if st.ParseErrorsTotal != 1 {
		t.Errorf("ParseErrorsTotal = %d, want 1 (IPv6 rejected via reject counter)", st.ParseErrorsTotal)
	}
}

func TestParseEvent_InvalidTimestamp(t *testing.T) {
	log := `192.168.1.1 - - [badtime] "GET / HTTP/1.1" 200 10 "-" "UA"`
	evt := map[string]interface{}{"message": log}
	var req Request
	_, err := parseEvent(evt, &req)
	if err == nil {
		t.Errorf("expected error for invalid timestamp, got nil")
	}
}

// TestParseEvent_RetainsTimezoneOffset documents the live side of the URGENT-09
// timestamp-parity fix: the live ingestor parses the log offset (-0700/+0200)
// and retains it on Request.Timestamp. The wall-clock digits are unchanged
// (06:00 stays 06:00) and the absolute instant reflects the real offset — which
// is now exactly what the STATIC parser also produces for the same line, so live
// and static agree (the previous 7h skew came from the static side discarding
// the offset). A -0700 06:00 line is 13:00 UTC; a +0200 06:00 line is 04:00 UTC.
func TestParseEvent_RetainsTimezoneOffset(t *testing.T) {
	wallClockUTC := func() time.Time { return time.Date(2025, 7, 6, 6, 0, 0, 0, time.UTC) }
	cases := []struct {
		name      string
		log       string
		offsetSec int
	}{
		{"-0700", `1.2.3.4 - - [06/Jul/2025:06:00:00 -0700] "GET / HTTP/1.1" 200 1 "-" "UA"`, -7 * 3600},
		{"+0200", `1.2.3.4 - - [06/Jul/2025:06:00:00 +0200] "GET / HTTP/1.1" 200 1 "-" "UA"`, 2 * 3600},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var req Request
			if _, err := parseEvent(map[string]interface{}{"message": tc.log}, &req); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			// Wall-clock digits unchanged.
			if req.Timestamp.Hour() != 6 || req.Timestamp.Minute() != 0 {
				t.Errorf("wall-clock changed: got %v, want 06:00", req.Timestamp)
			}
			if _, off := req.Timestamp.Zone(); off != tc.offsetSec {
				t.Errorf("zone offset = %ds, want %ds", off, tc.offsetSec)
			}
			// Absolute instant = UTC wall-clock minus the offset.
			wantInstant := wallClockUTC().Add(time.Duration(-tc.offsetSec) * time.Second)
			if !req.Timestamp.Equal(wantInstant) {
				t.Errorf("instant = %v, want %v", req.Timestamp.UTC(), wantInstant)
			}
		})
	}
}

// TestParseEvent_AcceptsOffsetlessTimestampAsUTC is the AUDIT-07 repro: an
// offset-less Common/Apache-Log bracket field (e.g. [06/Jul/2025:19:57:26], 20
// bytes) was previously dropped by live (the offset-required layout failed →
// ParseError) while static keeps it as UTC. After the fix the live ingestor
// falls back to the zone-less layout: the event is accepted (err == nil), the
// wall-clock digits are preserved, and the zone is UTC (offset 0) — matching the
// static parser exactly. Genuinely malformed brackets ([badtime]) still fail
// both layouts (see TestParseEvent_InvalidTimestamp).
func TestParseEvent_AcceptsOffsetlessTimestampAsUTC(t *testing.T) {
	log := `1.2.3.4 - - [06/Jul/2025:19:57:26] "GET / HTTP/1.1" 200 1 "-" "UA"`
	var req Request
	if _, err := parseEvent(map[string]interface{}{"message": log}, &req); err != nil {
		t.Fatalf("offset-less timestamp must be accepted, got error: %v", err)
	}
	if h, m, s := req.Timestamp.Hour(), req.Timestamp.Minute(), req.Timestamp.Second(); h != 19 || m != 57 || s != 26 {
		t.Errorf("wall-clock = %02d:%02d:%02d, want 19:57:26", h, m, s)
	}
	if _, off := req.Timestamp.Zone(); off != 0 {
		t.Errorf("zone offset = %ds, want 0 (UTC)", off)
	}
	want := time.Date(2025, 7, 6, 19, 57, 26, 0, time.UTC)
	if !req.Timestamp.Equal(want) {
		t.Errorf("instant = %v, want %v", req.Timestamp.UTC(), want)
	}
}

// TestParseEvent_DashStatusBytesAreZeroNotMalformed is the URGENT-09 repro: a
// "-" (absent) status or bytes field must be treated as a silent zero, NOT
// counted as malformed — parity with the static log parser. Previously
// strconv.Atoi("-") errored and incremented malformed, systematically inflating
// MalformedFieldsTotal (304s and many proxies log "-" for bytes routinely).
func TestParseEvent_DashStatusBytesAreZeroNotMalformed(t *testing.T) {
	cases := []struct {
		name          string
		log           string
		wantStatus    uint16
		wantBytes     uint32
		wantMalformed int
	}{
		{
			name:          "dash bytes (304 with no body)",
			log:           `192.168.1.1 - - [12/Mar/2024:15:04:05 -0700] "GET / HTTP/1.1" 304 - "-" "UA"`,
			wantStatus:    304,
			wantBytes:     0,
			wantMalformed: 0,
		},
		{
			name:          "dash status and dash bytes",
			log:           `192.168.1.1 - - [12/Mar/2024:15:04:05 -0700] "GET / HTTP/1.1" - - "-" "UA"`,
			wantStatus:    0,
			wantBytes:     0,
			wantMalformed: 0,
		},
		{
			name:          "genuinely bad status still counts as malformed",
			log:           `192.168.1.1 - - [12/Mar/2024:15:04:05 -0700] "GET / HTTP/1.1" 2XX 100 "-" "UA"`,
			wantStatus:    0,
			wantBytes:     100,
			wantMalformed: 1,
		},
		{
			name:          "genuinely bad bytes still counts as malformed",
			log:           `192.168.1.1 - - [12/Mar/2024:15:04:05 -0700] "GET / HTTP/1.1" 200 12x4 "-" "UA"`,
			wantStatus:    200,
			wantBytes:     0,
			wantMalformed: 1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			evt := map[string]interface{}{"message": tc.log}
			var req Request
			malformed, err := parseEvent(evt, &req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if malformed != tc.wantMalformed {
				t.Errorf("malformed = %d, want %d", malformed, tc.wantMalformed)
			}
			if req.Status != tc.wantStatus {
				t.Errorf("Status = %d, want %d", req.Status, tc.wantStatus)
			}
			if req.Bytes != tc.wantBytes {
				t.Errorf("Bytes = %d, want %d", req.Bytes, tc.wantBytes)
			}
		})
	}
}

func TestParseEvent_SetsIPUint32(t *testing.T) {
	log := `192.168.1.100 - - [12/Mar/2024:15:04:05 -0700] "GET / HTTP/1.1" 200 10 "-" "UA"`
	evt := map[string]interface{}{"message": log}
	var req Request
	_, err := parseEvent(evt, &req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 192.168.1.100 = (192<<24) | (168<<16) | (1<<8) | 100 = 3232235876
	want := uint32(192)<<24 | uint32(168)<<16 | uint32(1)<<8 | 100
	if req.IPUint32 != want {
		t.Errorf("expected IPUint32 %d, got %d", want, req.IPUint32)
	}
	if req.IP.String() != "192.168.1.100" {
		t.Errorf("expected IP 192.168.1.100, got %v", req.IP)
	}
}

func TestParseEvent_UnknownMethod(t *testing.T) {
	log := `192.168.1.1 - - [12/Mar/2024:15:04:05 -0700] "FOO /foo HTTP/1.1" 404 0 "-" "UA"`
	evt := map[string]interface{}{"message": log}
	var req Request
	_, err := parseEvent(evt, &req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Method != UNKNOWN {
		t.Errorf("expected UNKNOWN method, got %v", req.Method)
	}
	if req.Status != 404 {
		t.Errorf("expected status 404, got %v", req.Status)
	}
	if req.UserAgent != "UA" {
		t.Errorf("expected UserAgent UA, got %v", req.UserAgent)
	}
}

func TestParseEvent_MissingUserAgent(t *testing.T) {
	// Only 5 quotes, so user agent will be empty
	log := `192.168.1.1 - - [12/Mar/2024:15:04:05 -0700] "GET / HTTP/1.1" 200 10 "-" `
	evt := map[string]interface{}{"message": log}
	var req Request
	_, err := parseEvent(evt, &req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.UserAgent != "" {
		t.Errorf("expected empty UserAgent, got %v", req.UserAgent)
	}
}

// TestParseEvent_TruncatedAtRequestEndQuote is the exact URGENT-01 repro: a
// message ending precisely at the closing request-line quote. Before the
// bounds-check, msg[end+2:] panicked (end+2 == len(msg)+1). It must now parse
// without panic, leaving Status and Bytes at zero and returning no error.
func TestParseEvent_TruncatedAtRequestEndQuote(t *testing.T) {
	log := `192.168.1.1 - - [12/Mar/2024:15:04:05 -0700] "GET / HTTP/1.1"`
	evt := map[string]interface{}{"message": log}
	var req Request
	malformed, err := parseEvent(evt, &req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if malformed != 0 {
		t.Errorf("expected 0 malformed fields, got %d", malformed)
	}
	if req.Status != 0 {
		t.Errorf("expected Status 0, got %d", req.Status)
	}
	if req.Bytes != 0 {
		t.Errorf("expected Bytes 0, got %d", req.Bytes)
	}
	if req.Method != GET {
		t.Errorf("expected GET method, got %v", req.Method)
	}
	if req.URI != "/" {
		t.Errorf("expected URI /, got %v", req.URI)
	}
}

// TestReadBatch_SurvivesTruncatedEvent proves the live-loop path (ReadBatch ->
// parseEventSafe -> parseEvent) does not panic on the truncated line and that
// the bounds-checked event parses successfully (it is a valid request, just
// without a status/bytes tail), so it IS included in output and is NOT counted
// as a parse error.
func TestReadBatch_SurvivesTruncatedEvent(t *testing.T) {
	ing := &TCPIngestor{
		events: make(chan *lj.Batch, 1),
	}
	truncated := `192.168.1.1 - - [12/Mar/2024:15:04:05 -0700] "GET / HTTP/1.1"`
	valid := `10.0.0.1 - - [12/Mar/2024:15:04:05 -0700] "GET /ok HTTP/1.1" 200 1 "-" "UA"`
	ing.events <- makeBatch(
		map[string]interface{}{"message": truncated},
		map[string]interface{}{"message": valid},
	)

	got, err := ing.ReadBatch()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Both events parse: truncated one (no status/bytes tail) + the valid one.
	if len(got) != 2 {
		t.Fatalf("expected 2 results, got %d", len(got))
	}
	if got[0].URI != "/" || got[0].Status != 0 || got[0].Bytes != 0 {
		t.Errorf("truncated event mis-parsed: %+v", got[0])
	}
	if got[1].URI != "/ok" {
		t.Errorf("expected second URI /ok, got %v", got[1].URI)
	}

	// The truncated line is handled by the bounds-check, NOT the recover path,
	// so it must not be counted as a parse error.
	st := ing.Stats()
	if st.ParseErrorsTotal != 0 {
		t.Errorf("ParseErrorsTotal = %d, want 0 (truncated line parses cleanly)", st.ParseErrorsTotal)
	}
	if st.RequestsTotal != 2 {
		t.Errorf("RequestsTotal = %d, want 2", st.RequestsTotal)
	}
	if st.MalformedFieldsTotal != 0 {
		t.Errorf("MalformedFieldsTotal = %d, want 0", st.MalformedFieldsTotal)
	}
}

// TestParseEventSafe_Transparent verifies the recover wrapper is transparent
// for normal input: it returns exactly what parseEvent returns (same malformed
// count, same error) for valid and for already-erroring events, so the
// recover() guard adds no behavior change on the non-panicking path.
func TestParseEventSafe_Transparent(t *testing.T) {
	valid := `192.168.1.1 - - [12/Mar/2024:15:04:05 -0700] "GET / HTTP/1.1" 200 10 "-" "UA"`
	var a, b Request
	mA, eA := parseEvent(map[string]interface{}{"message": valid}, &a)
	mB, eB := parseEventSafe(map[string]interface{}{"message": valid}, &b)
	if mA != mB || (eA == nil) != (eB == nil) {
		t.Errorf("safe wrapper diverged on valid: (%d,%v) vs (%d,%v)", mA, eA, mB, eB)
	}
	// Request contains a net.IP slice, so compare the parsed fields directly.
	if a.IPUint32 != b.IPUint32 || a.Status != b.Status || a.Bytes != b.Bytes ||
		a.Method != b.Method || a.URI != b.URI || a.UserAgent != b.UserAgent ||
		!a.Timestamp.Equal(b.Timestamp) || !a.IP.Equal(b.IP) {
		t.Errorf("safe wrapper produced different Request: %+v vs %+v", a, b)
	}

	// Erroring input: missing message field must still surface as an error
	// (not a recovered panic) with malformed == 0.
	m, err := parseEventSafe(map[string]interface{}{}, &Request{})
	if err == nil {
		t.Errorf("expected error for missing message field, got nil")
	}
	if m != 0 {
		t.Errorf("expected 0 malformed, got %d", m)
	}
}

// TestScanQuotedCloseStr asserts the string-typed escape-aware close scanner is
// byte-identical to the static parser's scanQuotedClose (mirroring
// logparser/parser_correctness_test.go:TestScanQuotedClose). These cases are the
// invariant the cross-package parity test relies on: ingestor cannot import
// logparser (import cycle), so the duplicated helper must match exactly.
func TestScanQuotedCloseStr(t *testing.T) {
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
		if got := scanQuotedCloseStr(tc.line, tc.contentStart, tc.firstQuote); got != tc.want {
			t.Errorf("%s: scanQuotedCloseStr(%q, %d, %d) = %d, want %d",
				tc.name, tc.line, tc.contentStart, tc.firstQuote, got, tc.want)
		}
	}
}

// TestParseEvent_EscapedQuotesUserAgent is the AUDIT-08 repro: an Apache-escaped
// quote (`\"`) inside the request line or referer must NOT shift the UA field.
// Before the fix, live counted raw `"` bytes from index 0 and captured the wrong
// substring as UserAgent; now the quoted fields are walked escape-aware so the
// correct UA is extracted. Field content keeps its raw escape bytes (alignment
// fix, not unescaping) — matching the static parser exactly.
func TestParseEvent_EscapedQuotesUserAgent(t *testing.T) {
	cases := []struct {
		name    string
		log     string
		wantUA  string
		wantURI string
	}{
		{
			name:    "escaped quote in request URI",
			log:     `1.2.3.4 - - [12/Mar/2024:15:04:05 -0700] "GET /a\"b HTTP/1.1" 200 10 "-" "RealUA"`,
			wantUA:  "RealUA",
			wantURI: `/a\"b`,
		},
		{
			name:    "escaped quote in referer",
			log:     `1.2.3.4 - - [12/Mar/2024:15:04:05 -0700] "GET / HTTP/1.1" 200 10 "ref\"erer" "RealUA"`,
			wantUA:  "RealUA",
			wantURI: "/",
		},
		{
			name:    "escaped quote in both request and referer",
			log:     `1.2.3.4 - - [12/Mar/2024:15:04:05 -0700] "GET /a\"b HTTP/1.1" 200 10 "r\"ef" "RealUA"`,
			wantUA:  "RealUA",
			wantURI: `/a\"b`,
		},
		{
			name:    "escaped quote inside the UA itself is kept raw",
			log:     `1.2.3.4 - - [12/Mar/2024:15:04:05 -0700] "GET / HTTP/1.1" 200 10 "-" "Mozilla\"Evil"`,
			wantUA:  `Mozilla\"Evil`,
			wantURI: "/",
		},
		{
			name:    "even backslashes do NOT escape the request close quote",
			log:     `1.2.3.4 - - [12/Mar/2024:15:04:05 -0700] "GET /x\\" 200 10 "-" "RealUA"`,
			wantUA:  "RealUA",
			wantURI: `/x\\`,
		},
		{
			name:    "triple backslash escapes the inner quote",
			log:     `1.2.3.4 - - [12/Mar/2024:15:04:05 -0700] "GET /a\\\"b HTTP/1.1" 200 10 "-" "RealUA"`,
			wantUA:  "RealUA",
			wantURI: `/a\\\"b`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var req Request
			if _, err := parseEvent(map[string]interface{}{"message": tc.log}, &req); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if req.UserAgent != tc.wantUA {
				t.Errorf("UserAgent = %q, want %q", req.UserAgent, tc.wantUA)
			}
			if req.URI != tc.wantURI {
				t.Errorf("URI = %q, want %q", req.URI, tc.wantURI)
			}
		})
	}
}

// BenchmarkParseEvent guards the AUDIT-08 hot-path performance constraint: the
// escape-aware field walk must stay a single O(n) pass with no extra allocation
// on the common (no-escape) line, and the escape slow path must only cost extra
// when a backslash actually precedes a candidate close quote. "clean" is the
// dominant case (the demo log has zero escaped quotes); "escaped" exercises the
// slow path. Report allocs/op to catch any accidental allocation regression.
func BenchmarkParseEvent(b *testing.B) {
	clean := `1.2.3.4 - - [12/Mar/2024:15:04:05 -0700] "GET /api/users HTTP/1.1" 200 1024 "https://example.com/" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"`
	escaped := `1.2.3.4 - - [12/Mar/2024:15:04:05 -0700] "GET /a\"b HTTP/1.1" 200 1024 "ref\"erer" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"`
	for _, tc := range []struct {
		name string
		log  string
	}{
		{"clean", clean},
		{"escaped", escaped},
	} {
		evt := map[string]interface{}{"message": tc.log}
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			var req Request
			for i := 0; i < b.N; i++ {
				if _, err := parseEvent(evt, &req); err != nil {
					b.Fatalf("unexpected error: %v", err)
				}
			}
		})
	}
}

func makeBatch(events ...interface{}) *lj.Batch {
	return &lj.Batch{
		Events: events,
	}
}

func TestReadBatch_EmptyChannel(t *testing.T) {
	ing := &TCPIngestor{
		events: make(chan *lj.Batch),
	}
	// Channel is empty, should return empty slice
	got, err := ing.ReadBatch()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty result, got %v", got)
	}
}

func TestReadBatch_ClosedChannel(t *testing.T) {
	ing := &TCPIngestor{
		events: make(chan *lj.Batch),
	}
	close(ing.events)
	got, err := ing.ReadBatch()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty result, got %v", got)
	}
}

func TestReadBatch_ValidEvents(t *testing.T) {
	ing := &TCPIngestor{
		events: make(chan *lj.Batch, 1),
	}
	log := `127.0.0.1 - - [12/Mar/2024:15:04:05 -0700] "GET /foo HTTP/1.1" 200 123 "-" "TestUA"`
	evt := map[string]interface{}{"message": log}
	ing.events <- makeBatch(evt)
	got, err := ing.ReadBatch()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 result, got %d", len(got))
	}
	wantIP := net.ParseIP("127.0.0.1")
	if !got[0].IP.Equal(wantIP) {
		t.Errorf("expected IP %v, got %v", wantIP, got[0].IP)
	}
	if got[0].Method != GET {
		t.Errorf("expected GET method, got %v", got[0].Method)
	}
	if got[0].URI != "/foo" {
		t.Errorf("expected URI /foo, got %v", got[0].URI)
	}
	if got[0].Status != 200 {
		t.Errorf("expected status 200, got %v", got[0].Status)
	}
	if got[0].Bytes != 123 {
		t.Errorf("expected bytes 123, got %v", got[0].Bytes)
	}
	if got[0].UserAgent != "TestUA" {
		t.Errorf("expected UserAgent TestUA, got %v", got[0].UserAgent)
	}
}

func TestReadBatch_MultipleEventsAndBatches(t *testing.T) {
	ing := &TCPIngestor{
		events: make(chan *lj.Batch, 2),
	}
	log1 := `10.0.0.1 - - [12/Mar/2024:15:04:05 -0700] "POST /bar HTTP/1.1" 201 10 "-" "UA1"`
	log2 := `10.0.0.2 - - [12/Mar/2024:15:05:05 -0700] "GET /baz HTTP/1.1" 404 0 "-" "UA2"`
	evt1 := map[string]interface{}{"message": log1}
	evt2 := map[string]interface{}{"message": log2}
	ing.events <- makeBatch(evt1)
	ing.events <- makeBatch(evt2)
	got, err := ing.ReadBatch()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 results, got %d", len(got))
	}
	if got[0].IP.String() != "10.0.0.1" || got[1].IP.String() != "10.0.0.2" {
		t.Errorf("unexpected IPs: %v, %v", got[0].IP, got[1].IP)
	}
	if got[0].Method != POST || got[1].Method != GET {
		t.Errorf("unexpected methods: %v, %v", got[0].Method, got[1].Method)
	}
}

func TestReadBatch_SkipsInvalidEvents(t *testing.T) {
	ing := &TCPIngestor{
		events: make(chan *lj.Batch, 1),
	}
	// First event is invalid (missing message), second is valid
	evt1 := map[string]interface{}{}
	log := `127.0.0.1 - - [12/Mar/2024:15:04:05 -0700] "GET /ok HTTP/1.1" 200 1 "-" "UA"`
	evt2 := map[string]interface{}{"message": log}
	ing.events <- makeBatch(evt1, evt2)
	got, err := ing.ReadBatch()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 valid result, got %d", len(got))
	}
	if got[0].URI != "/ok" {
		t.Errorf("expected URI /ok, got %v", got[0].URI)
	}
}

func TestReadBatch_NonMapEventsAreIgnored(t *testing.T) {
	ing := &TCPIngestor{
		events: make(chan *lj.Batch, 1),
	}
	ing.events <- makeBatch("not a map", 123, nil)
	got, err := ing.ReadBatch()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected 0 results, got %d", len(got))
	}
}
