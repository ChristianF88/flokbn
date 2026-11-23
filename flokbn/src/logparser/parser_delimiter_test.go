package logparser

import (
	"testing"
	"time"

	"github.com/ChristianF88/flokbn/ingestor"
)

// TestDelimiter_AfterBracketedAndQuotedFields: a non-space delimiter that
// follows a bracketed or quoted field is consumed with the field. It used to be
// left in place, so the next field started ON the delimiter, parsed as empty,
// and every later field was off by one - the documented pipe format
// `%h|[%t]|%m|%U|%s` put the method into the URI and the URI into the status.
func TestDelimiter_AfterBracketedAndQuotedFields(t *testing.T) {
	type want struct {
		ip     string
		method ingestor.HTTPMethod
		uri    string
		status uint16
		bytes  uint32
		ua     string
		ts     bool
	}
	tests := []struct {
		name   string
		format string
		line   string
		want   want
	}{
		{
			name:   "documented pipe format",
			format: `%h|[%t]|%m|%U|%s`,
			line:   `192.0.2.1|[09/Oct/2025:10:15:23 +0000]|POST|/index.html|404`,
			want:   want{ip: "192.0.2.1", method: ingestor.POST, uri: "/index.html", status: 404, ts: true},
		},
		{
			name:   "pipes around quoted fields",
			format: `%h|"%r"|%s|"%u"|%b`,
			line:   `192.0.2.1|"POST /a b HTTP/1.1"|404|"Mozilla/5.0 (X11; Linux)"|1234`,
			want:   want{ip: "192.0.2.1", method: ingestor.POST, uri: "/a", status: 404, ua: "Mozilla/5.0 (X11; Linux)", bytes: 1234},
		},
		{
			name:   "CSV with a comma inside a quoted field",
			format: `%^,"%u",%h,%s`,
			line:   `x,"Mozilla, 5.0",192.0.2.1,404`,
			want:   want{ip: "192.0.2.1", status: 404, ua: "Mozilla, 5.0"},
		},
		{
			name:   "bracket then quote then bare, semicolons",
			format: `[%t];"%u";%h;%s`,
			line:   `[09/Oct/2025:10:15:23 +0000];"curl/8";192.0.2.1;404`,
			want:   want{ip: "192.0.2.1", status: 404, ua: "curl/8", ts: true},
		},
		{
			name:   "quoted value in a bare pipe slot",
			format: `%h|%^|%s`,
			line:   `192.0.2.1|"a|b c"|404`,
			want:   want{ip: "192.0.2.1", status: 404},
		},
		{
			name:   "empty bare field between pipes is still one field",
			format: `%h|%^|%U|%s`,
			line:   `192.0.2.1||/x|404`,
			want:   want{ip: "192.0.2.1", uri: "/x", status: 404},
		},
		{
			name:   "empty field right after a quoted field",
			format: `%h|"%u"|%^|%s`,
			line:   `192.0.2.1|"curl/8"||404`,
			want:   want{ip: "192.0.2.1", ua: "curl/8", status: 404},
		},
		{
			name:   "empty quoted field",
			format: `%h|"%u"|%s`,
			line:   `192.0.2.1|""|404`,
			want:   want{ip: "192.0.2.1", status: 404},
		},
		{
			name:   "IP last, after quoted and bracketed fields",
			format: `[%t]|"%u"|%h`,
			line:   `[09/Oct/2025:10:15:23 +0000]|"curl/8"|192.0.2.1`,
			want:   want{ip: "192.0.2.1", ua: "curl/8", ts: true},
		},
		{
			name:   "space-separated default is unaffected",
			format: DefaultLogFormat,
			line:   `10.0.0.1 - - [09/Oct/2025:10:15:23 +0000] "POST /x HTTP/1.1" 404 1234 "-" "curl/8" "192.0.2.1"`,
			want:   want{ip: "192.0.2.1", method: ingestor.POST, uri: "/x", status: 404, bytes: 1234, ua: "curl/8", ts: true},
		},
	}

	wantTime := time.Date(2025, time.October, 9, 10, 15, 23, 0, time.UTC)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := mustNewParser(t, tt.format)
			line := []byte(tt.line)
			req, err := parseLineForTest(p, line)
			if err != nil {
				t.Fatal(err)
			}
			if got := ingestor.Uint32ToIPString(req.IPUint32); got != tt.want.ip {
				t.Errorf("IP = %s, want %s", got, tt.want.ip)
			}
			if got := ingestor.Uint32ToIPString(p.compiled.extractIPOnly(line)); got != tt.want.ip {
				t.Errorf("IP-only parse: IP = %s, want %s", got, tt.want.ip)
			}
			if req.Method != tt.want.method {
				t.Errorf("Method = %v, want %v", req.Method, tt.want.method)
			}
			if req.URI != tt.want.uri {
				t.Errorf("URI = %q, want %q", req.URI, tt.want.uri)
			}
			if req.Status != tt.want.status {
				t.Errorf("Status = %d, want %d", req.Status, tt.want.status)
			}
			if req.Bytes != tt.want.bytes {
				t.Errorf("Bytes = %d, want %d", req.Bytes, tt.want.bytes)
			}
			if req.UserAgent != tt.want.ua {
				t.Errorf("UserAgent = %q, want %q", req.UserAgent, tt.want.ua)
			}
			if tt.want.ts && !req.Timestamp.Equal(wantTime) {
				t.Errorf("Timestamp = %v, want %v", req.Timestamp, wantTime)
			}
			if st := p.Stats(); st.MalformedStatus != 0 || st.MalformedBytes != 0 {
				t.Errorf("malformed counters = %+v, want none (fields are aligned)", st)
			}
		})
	}
}

// TestDelimiter_QuotedGroupNeedsSpace: a quoted GROUP ("%^ %U %^") is closed by
// a bare token scan, not by a quoted scan, and that scan cannot also consume a
// following non-space delimiter without slowing every bare field. Such a format
// is rejected at compile time instead of misparsing every line.
func TestDelimiter_QuotedGroupNeedsSpace(t *testing.T) {
	rejected := []string{
		`%h|"%^ %U %^"|%s`,
		`%h,"%^ %U %^",%s`,
		`%h "%^ %U %^";%s`,
	}
	for _, f := range rejected {
		err := ValidateFormat(f)
		if err == nil {
			t.Errorf("ValidateFormat(%q) = nil, want an error about the delimiter after the quoted group", f)
			continue
		}
		if _, cerr := compileFormat(f); cerr == nil {
			t.Errorf("compileFormat(%q) succeeded although ValidateFormat rejects it", f)
		}
	}

	accepted := []string{
		drupalLogFormat,
		`%h "%^ %U %^" %s`,
		`%h "%^ %U %^"`,
		`%h|"%r"|%s`,
		`%h|[%t]|%m|%U|%s`,
		`%h [%t] "%m %U %^" %s`,
	}
	for _, f := range accepted {
		if err := ValidateFormat(f); err != nil {
			t.Errorf("ValidateFormat(%q) = %v, want nil", f, err)
		}
	}

	// The space-separated group keeps working.
	p := mustNewParser(t, `%h "%^ %U %^" %s`)
	req, _ := parseLineForTest(p, []byte(`192.0.2.1 "GET /x HTTP/1.1" 404`))
	if req.URI != "/x" || req.Status != 404 {
		t.Errorf("URI/status = %q/%d, want /x/404", req.URI, req.Status)
	}
}
