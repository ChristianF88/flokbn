package logparser

import (
	"math/rand"
	"os"
	"sort"
	"testing"

	"github.com/ChristianF88/flokbn/ingestor"
	"github.com/ChristianF88/flokbn/testutil"
)

// parseIPv4ToUint32_ref is a VERBATIM copy of the original parseIPv4ToUint32
// implementation (before the branch-light rewrite). The differential tests
// assert the new implementation returns the identical uint32 for every input.
func parseIPv4ToUint32_ref(line []byte, start, end int) uint32 {
	if end-start < 7 || end-start > 15 {
		return 0
	}
	if end > len(line) {
		return 0
	}

	dots := 0
	partIdx := 0
	current := 0
	var result uint32

	for i := start; i < end; i++ {
		b := line[i]
		if b == '.' {
			if current > 255 || partIdx >= 3 {
				return 0
			}
			result |= uint32(current) << (24 - 8*partIdx)
			partIdx++
			current = 0
			dots++
		} else if b >= '0' && b <= '9' {
			current = current*10 + int(b&0x0F)
		} else {
			return 0
		}
	}

	if dots != 3 || current > 255 || partIdx != 3 {
		return 0
	}
	result |= uint32(current)

	return result
}

// ---------------------------------------------------------------------------
// TASK 1: differential test for parseIPv4ToUint32 vs reference.
// ---------------------------------------------------------------------------

func TestDiffParseIPv4_HandPickedEdges(t *testing.T) {
	edges := []string{
		"",
		"0.0.0.0",
		"255.255.255.255",
		"256.0.0.1",
		"1.2.3",
		"1.2.3.4.5",
		"1..2.3",
		"01.02.03.04",
		"999.1.1.1",
		" 1.2.3.4",
		"1.2.3.4 ",
		".1.2.3",
		"1.2.3.",
		"....",
		"...",
		".",
		"1.2.3.4",
		"12.34.56.78",
		"100.100.100.100",
		"255.255.255.256",
		"1.2.3.4567",
		"0000.0.0.0",
		"1.2.3.4.",
		"a.b.c.d",
		"1.2.3.4a",
		"1234567",         // 7 chars, no dots
		"123456789012345", // 15 chars
		"1.1.1.1.1.1.1.1",
	}
	for _, s := range edges {
		b := []byte(s)
		got := parseIPv4ToUint32(b, 0, len(b))
		want := parseIPv4ToUint32_ref(b, 0, len(b))
		if got != want {
			t.Fatalf("edge %q: got=%d want=%d", s, got, want)
		}
	}

	// Also test with non-zero start offsets / sub-slices in a larger buffer.
	buf := []byte("xxx192.168.1.1yyy")
	for start := 0; start <= len(buf); start++ {
		for end := start; end <= len(buf); end++ {
			got := parseIPv4ToUint32(buf, start, end)
			want := parseIPv4ToUint32_ref(buf, start, end)
			if got != want {
				t.Fatalf("offset start=%d end=%d on %q: got=%d want=%d", start, end, buf, got, want)
			}
		}
	}
}

func TestDiffParseIPv4_RandomValid(t *testing.T) {
	rng := rand.New(rand.NewSource(0xC1D2))
	for i := 0; i < 100_000; i++ {
		a, b1, c, d := rng.Intn(256), rng.Intn(256), rng.Intn(256), rng.Intn(256)
		// formatIPv4 may produce leading zeros via random width to exercise that path.
		s := formatOctet(rng, a) + "." + formatOctet(rng, b1) + "." + formatOctet(rng, c) + "." + formatOctet(rng, d)
		bs := []byte(s)
		got := parseIPv4ToUint32(bs, 0, len(bs))
		want := parseIPv4ToUint32_ref(bs, 0, len(bs))
		if got != want {
			t.Fatalf("valid %q: got=%d want=%d", s, got, want)
		}
	}
}

// formatOctet renders an octet, sometimes with random leading zeros (still <=15
// total length is not guaranteed; that's fine — both impls share the length gate).
func formatOctet(rng *rand.Rand, v int) string {
	s := itoa(v)
	if rng.Intn(4) == 0 {
		// add 0..2 leading zeros
		z := rng.Intn(3)
		for i := 0; i < z; i++ {
			s = "0" + s
		}
	}
	return s
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var buf [4]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}

func TestDiffParseIPv4_RandomBytes(t *testing.T) {
	rng := rand.New(rand.NewSource(0xBEEF))
	charset := []byte("0123456789.")
	junk := []byte{' ', 'a', 'x', '/', '-', ':', 0, 255}
	all := append(append([]byte{}, charset...), junk...)

	for i := 0; i < 1_000_000; i++ {
		n := rng.Intn(21) // length 0..20
		b := make([]byte, n)
		for j := 0; j < n; j++ {
			b[j] = all[rng.Intn(len(all))]
		}
		got := parseIPv4ToUint32(b, 0, n)
		want := parseIPv4ToUint32_ref(b, 0, n)
		if got != want {
			t.Fatalf("random bytes %q (len %d): got=%d want=%d", b, n, got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// TASK 2: differential test for extractIPOnly vs full skip-parse IPUint32.
// ---------------------------------------------------------------------------

func TestDiffExtractIPOnly(t *testing.T) {
	formats := []string{
		// IP first (the bench format shape)
		`%h %^ %^ [%t] "%r" %s %b %^ "%u"`,
		// IP last
		`%^ %^ %^ [%t] "%r" %s %b %^ "%u" "%h"`,
		// IP in the middle
		`%^ %h [%t] "%r" %s`,
		// minimal: just IP
		`%h`,
		// IP then bracket then quote
		`%h [%t] "%u"`,
	}

	lines := []string{
		`192.168.1.100 - - [01/Jan/2025:10:15:30 +0000] "GET /api/users HTTP/1.1" 200 1024 "-" "Mozilla/5.0"`,
		`172.16.45.67 - - [01/Jan/2025:10:15:31 +0000] "POST /api/login HTTP/1.1" 401 512 "-" "curl/7.68.0"`,
		`10.20.30.40 - - [01/Jan/2025:10:15:32 +0000] "GET /static/logo.png HTTP/1.1" 200 8192 "https://example.com/" "Mozilla/5.0 (X11; Linux x86_64)"`,
		`- - - [01/Jan/2025:10:15:33 +0000] "DELETE /api/cache HTTP/1.1" 204 0 "-" "AdminTool/2.0"`, // missing IP
		`999.1.1.1 - - [01/Jan/2025:10:15:34 +0000] "GET / HTTP/1.1" 200 1 "-" "x"`,                 // invalid IP
		`256.256.256.256 x [t] "r" 200 0 "-" "u"`,                                                   // invalid IP
		`1.2.3.4 x [t] "r" 200 0 "-" "u"`,
		`8.8.8.8 - - [01/Jan/2025:10:15:34 +0000] "GET / HTTP/1.1" 200 1 "-" "Mozilla/5.0 (Android)"`,
		``,                  // empty line
		`notanip`,           // junk
		`1.2.3.4`,           // bare IP
		`  10.0.0.1   foo`,  // leading spaces
		`"5.6.7.8" rest`,    // quoted ip (only matters for formats where %h quoted; here %h unquoted -> tests boundary)
		`1.2.3.4.5 - - [t]`, // 5-part
	}

	// IP-last and IP-last-quoted lines: build lines that end with a quoted IP.
	ipLastLines := []string{
		`- - - [01/Jan/2025:10:15:30 +0000] "GET /a HTTP/1.1" 200 1024 "-" "Mozilla/5.0" "192.168.1.100"`,
		`- - - [01/Jan/2025:10:15:31 +0000] "POST /b HTTP/1.1" 401 512 "-" "curl" "10.0.0.1"`,
		`- - - [01/Jan/2025:10:15:32 +0000] "GET /c HTTP/1.1" 200 0 "-" "x" "999.1.1.1"`,
		`- - - [01/Jan/2025:10:15:32 +0000] "GET /c HTTP/1.1" 200 0 "-" "x" "-"`,
	}

	check := func(t *testing.T, format string, ls []string) {
		cf, err := compileFormat(format)
		if err != nil {
			// Some format/line combos may be invalid formats; skip those.
			t.Fatalf("compileFormat(%q): %v", format, err)
		}
		var req ingestor.Request
		for _, line := range ls {
			b := []byte(line)
			req = ingestor.Request{}
			_ = cf.parseUsingCompiledFormatOpt(b, &req, true, true)
			want := req.IPUint32
			got := cf.extractIPOnly(b)
			if got != want {
				t.Fatalf("format %q line %q: extractIPOnly=%d full-skip IPUint32=%d", format, line, got, want)
			}
		}
	}

	for _, f := range formats {
		check(t, f, lines)
	}
	// IP-last formats validated against the IP-last lines.
	check(t, `%^ %^ %^ [%t] "%r" %s %b %^ "%u" "%h"`, ipLastLines)
}

// ---------------------------------------------------------------------------
// TASK 3: differential test for ParseFileIPs vs ParseFile.
// ---------------------------------------------------------------------------

func TestDiffParseFileIPs(t *testing.T) {
	testFile, cleanup := testutil.GenerateTestLogFile(t, 50_000)
	defer cleanup()

	// testutil lines are Apache-combined-ish ending with a quoted IP; use the
	// format used elsewhere in the suite (%h first).
	format := `%h %^ %^ [%t] "%r" %s %b %^ "%u"`
	parser, err := NewParser(format)
	if err != nil {
		t.Fatalf("NewParser: %v", err)
	}
	parser.SkipStringFields = true
	parser.SkipNonIPFields = true

	reqs, err := parser.ParseFile(testFile)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	var wantNonzero []uint32
	wantInvalid := 0
	for i := range reqs {
		if reqs[i].IPUint32 != 0 {
			wantNonzero = append(wantNonzero, reqs[i].IPUint32)
		} else {
			wantInvalid++
		}
	}
	// ParseFile drops nothing for these lines (parseLineReuseOpt returns nil
	// always), so zero-IP lines are present as IPUint32==0. But note: ParseFile
	// only appends reqs for which parse returned nil err; parseLineReuseOpt
	// never errors, so every line yields a req. Invalid lines therefore appear
	// as IPUint32==0 in reqs.

	gotIPs, gotInvalid, err := parser.ParseFileIPs(testFile)
	if err != nil {
		t.Fatalf("ParseFileIPs: %v", err)
	}

	if gotInvalid != wantInvalid {
		t.Fatalf("invalidCount mismatch: got=%d want=%d", gotInvalid, wantInvalid)
	}
	if len(gotIPs) != len(wantNonzero) {
		t.Fatalf("nonzero IP count mismatch: got=%d want=%d", len(gotIPs), len(wantNonzero))
	}

	sort.Slice(gotIPs, func(i, j int) bool { return gotIPs[i] < gotIPs[j] })
	sort.Slice(wantNonzero, func(i, j int) bool { return wantNonzero[i] < wantNonzero[j] })
	for i := range gotIPs {
		if gotIPs[i] != wantNonzero[i] {
			t.Fatalf("IP multiset mismatch at %d: got=%d want=%d", i, gotIPs[i], wantNonzero[i])
		}
	}
}

// TestDiffParseFileIPsWithInvalids ensures the invalid-count semantics match on
// a file that contains lines with missing/invalid IPs.
func TestDiffParseFileIPsWithInvalids(t *testing.T) {
	content := "" +
		`192.168.1.1 - - [01/Jan/2025:10:15:30 +0000] "GET / HTTP/1.1" 200 1 "-" "u"` + "\n" +
		`- - - [01/Jan/2025:10:15:30 +0000] "GET / HTTP/1.1" 200 1 "-" "u"` + "\n" + // missing IP
		`999.1.1.1 - - [01/Jan/2025:10:15:30 +0000] "GET / HTTP/1.1" 200 1 "-" "u"` + "\n" + // invalid
		`10.0.0.1 - - [01/Jan/2025:10:15:30 +0000] "GET / HTTP/1.1" 200 1 "-" "u"` + "\n"

	f, err := os.CreateTemp("", "ip_invalid_*.log")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	f.Close()

	parser, err := NewParser(`%h %^ %^ [%t] "%r" %s %b %^ "%u"`)
	if err != nil {
		t.Fatal(err)
	}
	parser.SkipStringFields = true
	parser.SkipNonIPFields = true

	reqs, err := parser.ParseFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	var wantNonzero []uint32
	wantInvalid := 0
	for i := range reqs {
		if reqs[i].IPUint32 != 0 {
			wantNonzero = append(wantNonzero, reqs[i].IPUint32)
		} else {
			wantInvalid++
		}
	}

	gotIPs, gotInvalid, err := parser.ParseFileIPs(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	if gotInvalid != wantInvalid {
		t.Fatalf("invalidCount: got=%d want=%d", gotInvalid, wantInvalid)
	}
	sort.Slice(gotIPs, func(i, j int) bool { return gotIPs[i] < gotIPs[j] })
	sort.Slice(wantNonzero, func(i, j int) bool { return wantNonzero[i] < wantNonzero[j] })
	if len(gotIPs) != len(wantNonzero) {
		t.Fatalf("nonzero count: got=%d want=%d", len(gotIPs), len(wantNonzero))
	}
	for i := range gotIPs {
		if gotIPs[i] != wantNonzero[i] {
			t.Fatalf("multiset mismatch at %d", i)
		}
	}
}
