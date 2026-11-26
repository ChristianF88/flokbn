package logparser

import (
	"testing"

	"github.com/ChristianF88/flokbn/accesslog"
)

// TestIPField_ForwardedForList: a %h field that holds an X-Forwarded-For style
// comma list yields its RIGHTMOST element - the address appended by the
// nearest proxy. Elements further left are supplied by the client and must
// never be used, not even as a fallback when the rightmost one is unusable.
func TestIPField_ForwardedForList(t *testing.T) {
	const prefix = `10.0.0.1 - - [23/Nov/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 123 "-" "curl/8" `

	tests := []struct {
		name  string
		field string // the raw trailing field, quotes included
		want  string // "" = invalid (IP 0)
	}{
		{"single address", `"203.0.113.7"`, "203.0.113.7"},
		{"two elements, comma space", `"198.51.100.1, 203.0.113.7"`, "203.0.113.7"},
		{"two elements, no space", `"198.51.100.1,203.0.113.7"`, "203.0.113.7"},
		{"three elements", `"1.1.1.1, 198.51.100.1, 203.0.113.7"`, "203.0.113.7"},
		{"short list within 15 bytes", `"1.1.1.1,2.2.2.2"`, "2.2.2.2"},
		{"padding around the last element", "\"198.51.100.1,  \t203.0.113.7 \"", "203.0.113.7"},
		{"spoofed junk on the left", `"unknown, <script>, 203.0.113.7"`, "203.0.113.7"},
		{"client-supplied address on the left of a bad tail", `"8.8.8.8, unknown"`, ""},
		{"trailing comma", `"8.8.8.8,"`, ""},
		{"IPv6 tail", `"8.8.8.8, 2001:db8::1"`, ""},
		{"out-of-range tail", `"8.8.8.8, 300.1.1.1"`, ""},
		{"only commas", `",,,"`, ""},
		{"absent", `"-"`, ""},
		{"bare token list", `198.51.100.1,203.0.113.7`, "203.0.113.7"},
	}

	p := mustNewParser(t, DefaultLogFormat)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			line := []byte(prefix + tt.field)
			var want uint32
			if tt.want != "" {
				want = ipStringToUint32(tt.want)
			}

			req, err := parseLineForTest(p, line)
			if err != nil {
				t.Fatal(err)
			}
			if req.IPUint32 != want {
				t.Errorf("full parse: IP = %s, want %s", accesslog.Uint32ToIPString(req.IPUint32), accesslog.Uint32ToIPString(want))
			}
			if got := p.compiled.extractIPOnly(line); got != want {
				t.Errorf("IP-only parse: IP = %s, want %s", accesslog.Uint32ToIPString(got), accesslog.Uint32ToIPString(want))
			}
		})
	}
}

// TestIPField_ExplicitCommaDelimiterUnchanged: a format that itself splits the
// list (`%h, %^`) keeps selecting the element the format names.
func TestIPField_ExplicitCommaDelimiterUnchanged(t *testing.T) {
	p := mustNewParser(t, `%h, %^ [%t]`)
	line := []byte(`189.115.84.87, 198.51.10.21 [18/Jul/2025:15:30:00 +0200]`)
	if got := accesslog.Uint32ToIPString(p.compiled.extractIPOnly(line)); got != "189.115.84.87" {
		t.Errorf("IP = %s, want 189.115.84.87", got)
	}

	p = mustNewParser(t, `%^, %h [%t]`)
	if got := accesslog.Uint32ToIPString(p.compiled.extractIPOnly(line)); got != "198.51.10.21" {
		t.Errorf("IP = %s, want 198.51.10.21", got)
	}
}

// TestForwardedTailIP_Bounds exercises the slow-path helper directly.
func TestForwardedTailIP_Bounds(t *testing.T) {
	line := []byte(`xx1.1.1.1, 2.2.2.2yy`)
	if got := forwardedTailIP(line, 2, 18); got != ipStringToUint32("2.2.2.2") {
		t.Errorf("got %s, want 2.2.2.2", accesslog.Uint32ToIPString(got))
	}
	for _, r := range [][2]int{{-1, 5}, {0, len(line) + 1}, {5, 5}, {9, 3}} {
		if got := forwardedTailIP(line, r[0], r[1]); got != 0 {
			t.Errorf("forwardedTailIP(%d,%d) = %d, want 0", r[0], r[1], got)
		}
	}
}
