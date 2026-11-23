package ingestor

import (
	"testing"
	"time"
)

// The timestamp used to be located by the first '[' and first ']' anywhere in
// the line. A bracket in the ident or user field (the user is whatever the
// client sent as its HTTP basic-auth name) was then taken for the timestamp
// and the event was dropped. The timestamp is the fourth field; brackets in
// the fields before it must not matter.
func TestParseLine_TimestampLocatedByPosition(t *testing.T) {
	want := time.Date(2024, 3, 12, 15, 4, 5, 0, time.FixedZone("", -7*3600))
	cases := map[string]string{
		"bracketed user":        `192.168.1.1 - [admin] [12/Mar/2024:15:04:05 -0700] "GET /x HTTP/1.1" 200 10 "-" "UA"`,
		"bracketed ident":       `192.168.1.1 [id] bob [12/Mar/2024:15:04:05 -0700] "GET /x HTTP/1.1" 200 10 "-" "UA"`,
		"open bracket in user":  `192.168.1.1 - a[b [12/Mar/2024:15:04:05 -0700] "GET /x HTTP/1.1" 200 10 "-" "UA"`,
		"close bracket in user": `192.168.1.1 - a]b [12/Mar/2024:15:04:05 -0700] "GET /x HTTP/1.1" 200 10 "-" "UA"`,
		"brackets in both":      `192.168.1.1 ][ [] [12/Mar/2024:15:04:05 -0700] "GET /x HTTP/1.1" 200 10 "-" "UA"`,
		"plain":                 `192.168.1.1 - - [12/Mar/2024:15:04:05 -0700] "GET /x HTTP/1.1" 200 10 "-" "UA"`,
		"brackets in request":   `192.168.1.1 - - [12/Mar/2024:15:04:05 -0700] "GET /x HTTP/1.1" 200 10 "http://r/?a[0]=1" "UA"`,
	}
	for name, line := range cases {
		t.Run(name, func(t *testing.T) {
			var req Request
			malformed, err := parseLine(line, &req)
			if err != nil {
				t.Fatalf("event dropped: %v", err)
			}
			if !req.Timestamp.Equal(want) {
				t.Errorf("Timestamp = %v, want %v", req.Timestamp, want)
			}
			// Everything after the timestamp is located relative to it, so
			// the rest of the line must still line up.
			if req.Method != GET || req.URI != "/x" || req.Status != 200 || req.Bytes != 10 || req.UserAgent != "UA" {
				t.Errorf("fields after the timestamp misparsed: %+v", req)
			}
			if malformed != 0 {
				t.Errorf("malformed = %d, want 0", malformed)
			}
		})
	}
}

// Layouts that do not carry the timestamp in fourth position were accepted
// before (first bracketed field after the IP) and still are: the line is
// re-aligned on the first bracket that holds a timestamp.
//
// One case of the hardcoded parser is gone from this list: a line with further
// bracketed fields BEHIND an out-of-position timestamp
// (`ip [time] x [y] "request" ...`). Address and timestamp are still read, but
// the fields behind the timestamp follow the format now; that layout needs its
// own logFormat. It is pinned in liveParserDivergences.
func TestParseLine_TimestampFallbackForOtherLayouts(t *testing.T) {
	want := time.Date(2024, 3, 12, 15, 4, 5, 0, time.UTC)
	cases := map[string]string{
		"no ident/user, offset":    `192.168.1.1 [12/Mar/2024:15:04:05 +0000] "GET /x HTTP/1.1" 200 10 "-" "UA"`,
		"no ident/user, zone-less": `192.168.1.1 [12/Mar/2024:15:04:05] "GET /x HTTP/1.1" 200 10 "-" "UA"`,
		"one field before":         `192.168.1.1 - [12/Mar/2024:15:04:05 +0000] "GET /x HTTP/1.1" 200 10 "-" "UA"`,
		"three fields before":      `192.168.1.1 - - - [12/Mar/2024:15:04:05 +0000] "GET /x HTTP/1.1" 200 10 "-" "UA"`,
		"user with a space":        `192.168.1.1 - john doe [12/Mar/2024:15:04:05 +0000] "GET /x HTTP/1.1" 200 10 "-" "UA"`,
	}
	for name, line := range cases {
		t.Run(name, func(t *testing.T) {
			var req Request
			if _, err := parseLine(line, &req); err != nil {
				t.Fatalf("event dropped: %v", err)
			}
			if !req.Timestamp.Equal(want) {
				t.Errorf("Timestamp = %v, want %v", req.Timestamp, want)
			}
			if req.URI != "/x" || req.Status != 200 {
				t.Errorf("fields after the timestamp misparsed: %+v", req)
			}
		})
	}
}

// Two lines the hardcoded parser rejected are accepted now and therefore no
// longer listed here: a valid timestamp without brackets, and one whose
// closing bracket is missing. Both carry a usable timestamp; they are pinned in
// liveParserDivergences.
func TestParseLine_TimestampStillRejected(t *testing.T) {
	for name, line := range map[string]string{
		"garbage in 4th field": `192.168.1.1 - - [badtime] "GET / HTTP/1.1" 200 10 "-" "UA"`,
		"no timestamp at all":  `192.168.1.1 - - 12-03-2024 "GET / HTTP/1.1" 200 10 "-" "UA"`,
		"only brackets before": `192.168.1.1 - [admin] 12/Mar/2024 "GET / HTTP/1.1" 200 10 "-" "UA"`,
		"line ends after IP":   `192.168.1.1 `,
		"line ends after user": `192.168.1.1 - - `,
	} {
		t.Run(name, func(t *testing.T) {
			var req Request
			if _, err := parseLine(line, &req); err == nil {
				t.Errorf("line accepted with timestamp %v, want an error", req.Timestamp)
			}
		})
	}
}
