package ingestor

import (
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ChristianF88/flokbn/logparser"
)

// An ingestor built without a log format reads the client IP from the first
// field, as live mode always did.
func TestTCPIngestor_DefaultLogFormat(t *testing.T) {
	ing, err := NewTCPIngestor("127.0.0.1:0", time.Second)
	if err != nil {
		t.Fatalf("NewTCPIngestor: %v", err)
	}
	defer ing.Close()
	if got := ing.LogFormat(); got != logparser.DefaultLiveLogFormat {
		t.Errorf("LogFormat() = %q, want the default live format %q", got, logparser.DefaultLiveLogFormat)
	}
	if got := newQueueIngestor(0).LogFormat(); got != logparser.DefaultLiveLogFormat {
		t.Errorf("queue ingestor LogFormat() = %q, want %q", got, logparser.DefaultLiveLogFormat)
	}
}

// Options.LogFormat decides where each field is read from. The line below has
// a proxy address first and the client in a trailing X-Forwarded-For field:
// the default format bans the proxy, the static default format finds the
// client.
func TestTCPIngestor_LogFormatIsHonoured(t *testing.T) {
	line := `10.0.0.1 - - [12/Mar/2024:15:04:05 +0000] "GET /x HTTP/1.1" 200 5 "-" "UA" "198.51.100.1, 203.0.113.7"`

	cases := []struct {
		name, format, wantIP string
	}{
		{"default: first field", "", "10.0.0.1"},
		{"static default: trailing forwarded field, rightmost address", logparser.DefaultLogFormat, "203.0.113.7"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ing, err := NewTCPIngestorWithOptions("127.0.0.1:0", Options{LogFormat: tc.format})
			if err != nil {
				t.Fatalf("NewTCPIngestorWithOptions: %v", err)
			}
			defer ing.Close()
			ing.events <- makeBatch(map[string]interface{}{"message": line})

			got, err := ing.ReadBatch()
			if err != nil || len(got) != 1 {
				t.Fatalf("ReadBatch = %d requests, err %v; want 1 request", len(got), err)
			}
			if ip := got[0].GetIPNet().String(); ip != tc.wantIP {
				t.Errorf("client IP = %s, want %s", ip, tc.wantIP)
			}
			if got[0].URI != "/x" || got[0].UserAgent != "UA" || got[0].Timestamp.IsZero() {
				t.Errorf("other fields misparsed: %+v", got[0])
			}
		})
	}
}

// A format that does not compile is refused before the address is bound.
func TestTCPIngestor_InvalidLogFormat(t *testing.T) {
	// Hold a port, then ask for the same one with a bad format: the format
	// error must win, i.e. the listen is never attempted.
	held, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer held.Close()

	for _, format := range []string{`%t "%r"`, `%h %h`, `%h %q`} {
		ing, err := NewTCPIngestorWithOptions(held.Addr().String(), Options{LogFormat: format})
		if err == nil {
			ing.Close()
			t.Errorf("format %q accepted, want an error", format)
			continue
		}
		if !strings.Contains(err.Error(), "invalid log format "+strconv.Quote(format)) {
			t.Errorf("format %q: error %q does not name the format", format, err)
		}
	}
}

// A malformed status or bytes field is counted on every parsed line, also on
// one that is then dropped for its address (the fields are scanned in a single
// pass, as in static mode).
func TestReadBatch_MalformedFieldsOnDroppedLine(t *testing.T) {
	ing := newQueueIngestor(1)
	ing.events <- makeBatch(
		map[string]interface{}{"message": `2001:db8::1 - - [12/Mar/2024:15:04:05 +0000] "GET / HTTP/1.1" oops 5 "-" "UA"`},
		map[string]interface{}{"message": `10.0.0.1 - - [12/Mar/2024:15:04:05 +0000] "GET / HTTP/1.1" 200 12x4 "-" "UA"`},
	)
	got, err := ing.ReadBatch()
	if err != nil || len(got) != 1 {
		t.Fatalf("ReadBatch = %d requests, err %v; want 1 request", len(got), err)
	}
	st := ing.Stats()
	if st.ParseErrorsTotal != 1 || st.RequestsTotal != 1 {
		t.Errorf("ParseErrorsTotal = %d, RequestsTotal = %d; want 1, 1", st.ParseErrorsTotal, st.RequestsTotal)
	}
	if st.MalformedFieldsTotal != 2 {
		t.Errorf("MalformedFieldsTotal = %d, want 2 (one on the dropped line, one on the kept line)", st.MalformedFieldsTotal)
	}
}

// The line comes from the network: a panic while parsing it must surface as a
// parse error, not take the live loop down.
func TestParseLine_RecoversFromPanic(t *testing.T) {
	ing := &TCPIngestor{} // no parser: ParseLine dereferences nil
	var req Request
	if err := ing.parseLine(`10.0.0.1 - - [12/Mar/2024:15:04:05 +0000] "GET / HTTP/1.1" 200 5 "-" "UA"`, &req); err == nil {
		t.Fatal("parseLine returned nil after a panic in the parser")
	}
}
