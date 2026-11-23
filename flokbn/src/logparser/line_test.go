package logparser

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ChristianF88/flokbn/accesslog"
)

func mustLineParser(t testing.TB, format string) *LineParser {
	t.Helper()
	lp, err := NewLineParser(format)
	if err != nil {
		t.Fatalf("NewLineParser(%q): %v", format, err)
	}
	return lp
}

func TestLineParser_DefaultLiveFormat(t *testing.T) {
	lp := mustLineParser(t, DefaultLiveLogFormat)
	if lp.Format() != DefaultLiveLogFormat {
		t.Errorf("Format() = %q, want %q", lp.Format(), DefaultLiveLogFormat)
	}

	line := `192.168.1.100 - frank [12/Mar/2024:15:04:05 -0700] "POST /api/items?page=2 HTTP/1.1" 201 5123 "https://example.com/a b" "Mozilla/5.0 (X11; Linux x86_64)"`
	var req accesslog.Request
	if err := lp.ParseLine(line, &req); err != nil {
		t.Fatalf("ParseLine: %v", err)
	}
	if want := uint32(192)<<24 | 168<<16 | 1<<8 | 100; req.IPUint32 != want {
		t.Errorf("IPUint32 = %d, want %d", req.IPUint32, want)
	}
	if want := time.Date(2024, 3, 12, 15, 4, 5, 0, time.FixedZone("", -7*3600)); !req.Timestamp.Equal(want) {
		t.Errorf("Timestamp = %v, want %v", req.Timestamp, want)
	}
	if req.Method != accesslog.POST || req.URI != "/api/items?page=2" || req.Status != 201 || req.Bytes != 5123 {
		t.Errorf("request fields misparsed: %+v", req)
	}
	if req.UserAgent != "Mozilla/5.0 (X11; Linux x86_64)" {
		t.Errorf("UserAgent = %q", req.UserAgent)
	}
	if req.IP != nil {
		t.Errorf("legacy IP field set: %v", req.IP)
	}
}

// The format is honoured, not assumed: the same parser type reads the client
// IP from wherever %h is.
func TestLineParser_CustomFormats(t *testing.T) {
	cases := []struct {
		name, format, line string
		wantIP             uint32
		wantURI, wantUA    string
	}{
		{
			name:    "static default, IP last",
			format:  DefaultLogFormat,
			line:    `10.0.0.1 - - [12/Mar/2024:15:04:05 +0000] "GET /x HTTP/1.1" 200 10 "-" "UA" "203.0.113.7"`,
			wantIP:  203<<24 | 113<<8 | 7,
			wantURI: "/x", wantUA: "UA",
		},
		{
			name:    "forwarded list in the first field takes the rightmost address",
			format:  DefaultLiveLogFormat,
			line:    `"198.51.100.1, 203.0.113.7" - - [12/Mar/2024:15:04:05 +0000] "GET /x HTTP/1.1" 200 10 "-" "UA"`,
			wantIP:  203<<24 | 113<<8 | 7,
			wantURI: "/x", wantUA: "UA",
		},
		{
			name:    "no ident and user fields",
			format:  `%h [%t] "%r" %s %b "%^" "%u"`,
			line:    `203.0.113.7 [12/Mar/2024:15:04:05 +0000] "GET /x HTTP/1.1" 200 10 "-" "UA"`,
			wantIP:  203<<24 | 113<<8 | 7,
			wantURI: "/x", wantUA: "UA",
		},
		{
			name:   "format without a timestamp accepts a line without one",
			format: `%h %U`,
			line:   `203.0.113.7 /x`,
			wantIP: 203<<24 | 113<<8 | 7, wantURI: "/x",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lp := mustLineParser(t, tc.format)
			var req accesslog.Request
			if err := lp.ParseLine(tc.line, &req); err != nil {
				t.Fatalf("ParseLine: %v", err)
			}
			if req.IPUint32 != tc.wantIP || req.URI != tc.wantURI || req.UserAgent != tc.wantUA {
				t.Errorf("got IP=%s URI=%q UA=%q, want IP=%s URI=%q UA=%q",
					accesslog.Uint32ToIPString(req.IPUint32), req.URI, req.UserAgent,
					accesslog.Uint32ToIPString(tc.wantIP), tc.wantURI, tc.wantUA)
			}
		})
	}
}

func TestLineParser_Rejects(t *testing.T) {
	lp := mustLineParser(t, DefaultLiveLogFormat)
	cases := []struct {
		name, line string
		want       error
	}{
		{"empty line", ``, ErrInvalidIP},
		{"only spaces", `   `, ErrInvalidIP},
		{"not an address", `notanip - - [12/Mar/2024:15:04:05 +0000] "GET / HTTP/1.1" 200 1 "-" "UA"`, ErrInvalidIP},
		{"IPv6", `2001:db8::1 - - [12/Mar/2024:15:04:05 +0000] "GET / HTTP/1.1" 200 1 "-" "UA"`, ErrInvalidIP},
		{"IPv4-mapped IPv6", `::ffff:192.168.1.1 - - [12/Mar/2024:15:04:05 +0000] "GET / HTTP/1.1" 200 1 "-" "UA"`, ErrInvalidIP},
		{"zero address", `0.0.0.0 - - [12/Mar/2024:15:04:05 +0000] "GET / HTTP/1.1" 200 1 "-" "UA"`, ErrInvalidIP},
		{"octet out of range", `1.2.3.256 - - [12/Mar/2024:15:04:05 +0000] "GET / HTTP/1.1" 200 1 "-" "UA"`, ErrInvalidIP},
		{"garbage timestamp", `1.2.3.4 - - [badtime] "GET / HTTP/1.1" 200 1 "-" "UA"`, ErrInvalidTimestamp},
		{"impossible date", `1.2.3.4 - - [31/Feb/2024:15:04:05 +0000] "GET / HTTP/1.1" 200 1 "-" "UA"`, ErrInvalidTimestamp},
		{"hour out of range", `1.2.3.4 - - [12/Mar/2024:25:04:05 +0000] "GET / HTTP/1.1" 200 1 "-" "UA"`, ErrInvalidTimestamp},
		{"line ends after the address", `1.2.3.4`, ErrInvalidTimestamp},
		{"line ends before the timestamp", `1.2.3.4 - - `, ErrInvalidTimestamp},
		{"an invalid address wins over an invalid timestamp", `nope - - [badtime]`, ErrInvalidIP},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var req accesslog.Request
			if err := lp.ParseLine(tc.line, &req); !errors.Is(err, tc.want) {
				t.Errorf("ParseLine(%q) = %v, want %v", tc.line, err, tc.want)
			}
		})
	}

	if _, err := NewLineParser(`%t "%r"`); err == nil {
		t.Error("NewLineParser accepted a format without %h")
	}
}

// A reused Request must not carry fields of the previous line into the next
// one; a stale timestamp would also defeat the invalid-timestamp check.
func TestLineParser_OverwritesRequest(t *testing.T) {
	lp := mustLineParser(t, DefaultLiveLogFormat)
	var req accesslog.Request
	full := `1.2.3.4 - - [12/Mar/2024:15:04:05 +0000] "GET /first HTTP/1.1" 200 10 "-" "FirstUA"`
	if err := lp.ParseLine(full, &req); err != nil {
		t.Fatalf("ParseLine: %v", err)
	}

	if err := lp.ParseLine(`5.6.7.8 - - [badtime] "GET /second HTTP/1.1" 200 10 "-" "UA"`, &req); !errors.Is(err, ErrInvalidTimestamp) {
		t.Errorf("stale timestamp hid a bad one: err = %v", err)
	}

	short := `5.6.7.8 - - [12/Mar/2024:15:04:06 +0000]`
	if err := lp.ParseLine(short, &req); err != nil {
		t.Fatalf("ParseLine: %v", err)
	}
	if req.URI != "" || req.UserAgent != "" || req.Status != 0 || req.Bytes != 0 {
		t.Errorf("fields of the previous line survived: %+v", req)
	}
}

// A free-text field in front of the timestamp that holds a space (the user
// name is whatever the client sent as its basic-auth name), or a log with more
// or fewer such fields than the format, must not get the line dropped: the
// line is re-aligned on its bracketed timestamp.
func TestLineParser_RealignsOnTimestamp(t *testing.T) {
	want := time.Date(2024, 3, 12, 15, 4, 5, 0, time.UTC)
	ip := uint32(203)<<24 | 113<<8 | 7
	cases := []struct {
		name, format, line string
	}{
		{"user with a space", DefaultLiveLogFormat,
			`203.0.113.7 - john doe [12/Mar/2024:15:04:05 +0000] "GET /x HTTP/1.1" 200 10 "-" "UA"`},
		{"user with several spaces", DefaultLiveLogFormat,
			`203.0.113.7 - a b c d [12/Mar/2024:15:04:05 +0000] "GET /x HTTP/1.1" 200 10 "-" "UA"`},
		{"user with a space and an open bracket", DefaultLiveLogFormat,
			`203.0.113.7 - x [y [12/Mar/2024:15:04:05 +0000] "GET /x HTTP/1.1" 200 10 "-" "UA"`},
		{"user that looks like an invalid timestamp", DefaultLiveLogFormat,
			`203.0.113.7 - [31/Feb/2024:15:04:05 +0000] x [12/Mar/2024:15:04:05 +0000] "GET /x HTTP/1.1" 200 10 "-" "UA"`},
		{"no ident and user fields", DefaultLiveLogFormat,
			`203.0.113.7 [12/Mar/2024:15:04:05 +0000] "GET /x HTTP/1.1" 200 10 "-" "UA"`},
		{"one field before the timestamp", DefaultLiveLogFormat,
			`203.0.113.7 - [12/Mar/2024:15:04:05 +0000] "GET /x HTTP/1.1" 200 10 "-" "UA"`},
		{"three fields before the timestamp", DefaultLiveLogFormat,
			`203.0.113.7 - - - [12/Mar/2024:15:04:05 +0000] "GET /x HTTP/1.1" 200 10 "-" "UA"`},
		{"zone-less timestamp", DefaultLiveLogFormat,
			`203.0.113.7 - john doe [12/Mar/2024:15:04:05] "GET /x HTTP/1.1" 200 10 "-" "UA"`},
		{"client address behind the timestamp", DefaultLogFormat,
			`10.0.0.1 - john doe [12/Mar/2024:15:04:05 +0000] "GET /x HTTP/1.1" 200 10 "-" "UA" "203.0.113.7"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lp := mustLineParser(t, tc.format)
			var req accesslog.Request
			if err := lp.ParseLine(tc.line, &req); err != nil {
				t.Fatalf("line dropped: %v", err)
			}
			if req.IPUint32 != ip || !req.Timestamp.Equal(want) {
				t.Errorf("IP = %s, Timestamp = %v; want %s, %v",
					accesslog.Uint32ToIPString(req.IPUint32), req.Timestamp, accesslog.Uint32ToIPString(ip), want)
			}
			if req.Method != accesslog.GET || req.URI != "/x" || req.Status != 200 || req.Bytes != 10 || req.UserAgent != "UA" {
				t.Errorf("fields behind the timestamp misparsed: %+v", req)
			}
			// The misread first pass must not leave anything in the counters.
			if got := lp.Stats(); got != (ParseStats{}) {
				t.Errorf("Stats() = %+v after a clean re-aligned line, want zero", got)
			}
		})
	}

	t.Run("malformed fields of the re-aligned line are counted once", func(t *testing.T) {
		lp := mustLineParser(t, DefaultLiveLogFormat)
		var req accesslog.Request
		line := `203.0.113.7 - john doe [12/Mar/2024:15:04:05 +0000] "GET /x HTTP/1.1" oops 12x4 "-" "UA"`
		if err := lp.ParseLine(line, &req); err != nil {
			t.Fatalf("line dropped: %v", err)
		}
		if got, want := lp.Stats(), (ParseStats{MalformedStatus: 1, MalformedBytes: 1}); got != want {
			t.Errorf("Stats() = %+v, want %+v", got, want)
		}
	})

	t.Run("no bracket holds a timestamp", func(t *testing.T) {
		lp := mustLineParser(t, DefaultLiveLogFormat)
		var req accesslog.Request
		for _, line := range []string{
			`203.0.113.7 - john doe [badtime] "GET /x[1] HTTP/1.1" 200 10 "-" "UA"`,
			`203.0.113.7 - john doe 12/Mar/2024:15:04:05 "GET /x HTTP/1.1" 200 10 "-" "UA"`,
			`203.0.113.7 - john doe [12/Mar/2024:15:04:05 +0000`,
			`203.0.113.7 - ` + strings.Repeat("[", 5000) + ` "GET /x HTTP/1.1" 200 10 "-" "UA"`,
			// The closing bracket is too far away to belong to a timestamp.
			`203.0.113.7 - john doe [12/Mar/2024:15:04:05 +0000` + strings.Repeat(" ", 80) + `] "GET /x HTTP/1.1" 200 10 "-" "UA"`,
		} {
			if err := lp.ParseLine(line, &req); !errors.Is(err, ErrInvalidTimestamp) {
				t.Errorf("ParseLine(%.60q...) = %v, want %v", line, err, ErrInvalidTimestamp)
			}
		}
	})

	t.Run("only a bracketed timestamp is searched for", func(t *testing.T) {
		lp := mustLineParser(t, `%h %^ %t "%r"`)
		var req accesslog.Request
		line := `203.0.113.7 john doe [12/Mar/2024:15:04:05 +0000] "GET /x HTTP/1.1"`
		if err := lp.ParseLine(line, &req); !errors.Is(err, ErrInvalidTimestamp) {
			t.Errorf("ParseLine = %v, want %v", err, ErrInvalidTimestamp)
		}
	})
}

func TestLineParser_Stats(t *testing.T) {
	lp := mustLineParser(t, DefaultLiveLogFormat)
	var req accesslog.Request
	for _, line := range []string{
		`1.2.3.4 - - [12/Mar/2024:15:04:05 +0000] "GET / HTTP/1.1" 200 10 "-" "UA"`,
		`1.2.3.4 - - [12/Mar/2024:15:04:05 +0000] "GET / HTTP/1.1" oops 10 "-" "UA"`,
		`1.2.3.4 - - [12/Mar/2024:15:04:05 +0000] "GET / HTTP/1.1" 200 12x4 "-" "UA"`,
		`1.2.3.4 - - [12/Mar/2024:15:04:05 +0000] "GET / HTTP/1.1" - - "-" "UA"`,
		// Rejected lines are counted too: the fields are scanned in one pass.
		`nope - - [12/Mar/2024:15:04:05 +0000] "GET / HTTP/1.1" oops 10 "-" "UA"`,
	} {
		_ = lp.ParseLine(line, &req)
	}
	if got, want := lp.Stats(), (ParseStats{MalformedStatus: 2, MalformedBytes: 1}); got != want {
		t.Errorf("Stats() = %+v, want %+v", got, want)
	}
}

func TestLineParser_DoesNotAllocate(t *testing.T) {
	lp := mustLineParser(t, DefaultLiveLogFormat)
	lines := []string{
		`1.2.3.4 - - [12/Mar/2024:15:04:05 -0700] "GET /api/users HTTP/1.1" 200 1024 "https://example.com/" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"`,
		`1.2.3.4 - - [12/Mar/2024:15:04:05 +0000] "GET /a\"b HTTP/1.1" 200 1024 "ref\"erer" "Mozilla/5.0"`,
		`2001:db8::1 - - [12/Mar/2024:15:04:05 +0000] "GET / HTTP/1.1" 200 1 "-" "UA"`,
		`1.2.3.4 - - [badtime] "GET / HTTP/1.1" 200 1 "-" "UA"`,
		`1.2.3.4 - john doe [12/Mar/2024:15:04:05 -0700] "GET / HTTP/1.1" oops 1 "-" "UA"`, // re-aligned
	}
	var req accesslog.Request
	for _, line := range lines {
		_ = lp.ParseLine(line, &req) // warm the zone-offset cache
	}
	allocs := testing.AllocsPerRun(200, func() {
		for _, line := range lines {
			_ = lp.ParseLine(line, &req)
		}
	})
	if allocs != 0 {
		t.Errorf("ParseLine allocated %.1f times per run, want 0", allocs)
	}
}

func BenchmarkLineParser(b *testing.B) {
	lp := mustLineParser(b, DefaultLiveLogFormat)
	line := `1.2.3.4 - - [12/Mar/2024:15:04:05 -0700] "GET /api/users HTTP/1.1" 200 1024 "https://example.com/" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"`
	var req accesslog.Request
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if err := lp.ParseLine(line, &req); err != nil {
			b.Fatal(err)
		}
	}
}
