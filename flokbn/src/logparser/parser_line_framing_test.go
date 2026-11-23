package logparser

import (
	"fmt"
	"io"
	"math/rand"
	"sort"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/ChristianF88/flokbn/ingestor"
)

// framingResult is what one I/O path made of a file, in a form two paths can
// be compared on: the multiset of parsed IPs, the invalid-line count and the
// oversized-line count.
type framingResult struct {
	ips       []uint32
	invalid   int
	oversized uint64
}

func (r framingResult) String() string {
	return fmt.Sprintf("%d ips, %d invalid, %d oversized", len(r.ips), r.invalid, r.oversized)
}

func sortedIPs(ips []uint32) []uint32 {
	out := append([]uint32(nil), ips...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func sameIPs(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	a, b = sortedIPs(a), sortedIPs(b)
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// framingAllPaths runs content through the four I/O paths (streaming and
// chunked, IP-only and full) with a fresh Parser each, so the oversized
// counter is per path. chunkSize drives the chunked paths.
func framingAllPaths(t *testing.T, format, content string, chunkSize int64) map[string]framingResult {
	t.Helper()
	path := writeTempLog(t, content)
	out := make(map[string]framingResult, 4)

	p := mustNewParser(t, format)
	ips, invalid := parseStreamingIPs(t, p, path)
	out["streaming/ips"] = framingResult{ips, invalid, p.Stats().OversizedLines}

	p = mustNewParser(t, format)
	ips, invalid = parseConcurrentIPs(t, p, path, chunkSize)
	out["chunked/ips"] = framingResult{ips, invalid, p.Stats().OversizedLines}

	fromRequests := func(reqs []ingestor.Request) ([]uint32, int) {
		var ips []uint32
		invalid := 0
		for _, r := range reqs {
			if r.IPUint32 != 0 {
				ips = append(ips, r.IPUint32)
			} else {
				invalid++
			}
		}
		return ips, invalid
	}

	p = mustNewParser(t, format)
	ips, invalid = fromRequests(parseStreamingFull(t, p, path))
	out["streaming/full"] = framingResult{ips, invalid, p.Stats().OversizedLines}

	p = mustNewParser(t, format)
	ips, invalid = fromRequests(parseConcurrentFull(t, p, path, chunkSize))
	out["chunked/full"] = framingResult{ips, invalid, p.Stats().OversizedLines}

	return out
}

func assertFraming(t *testing.T, label string, got map[string]framingResult, wantIPs []uint32, wantInvalid int, wantOversized uint64) {
	t.Helper()
	for _, name := range []string{"streaming/ips", "chunked/ips", "streaming/full", "chunked/full"} {
		r := got[name]
		if !sameIPs(r.ips, wantIPs) || r.invalid != wantInvalid || r.oversized != wantOversized {
			t.Errorf("%s %s: got %v, want %d ips, %d invalid, %d oversized",
				label, name, r, len(wantIPs), wantInvalid, wantOversized)
		}
	}
}

// TestFraming_BlankLinesSkippedOnBothPaths: blank lines (LF or CRLF) are not
// requests. The streaming reader used to hand them to the parser, which
// counted each one as a line with an invalid IP, while the chunked reader
// skipped them - so the same file reported different totals depending on
// whether it was above or below the 500MB switch.
func TestFraming_BlankLinesSkippedOnBothPaths(t *testing.T) {
	content := "\n" +
		"1.1.1.1 a\n" +
		"\n\n" +
		"2.2.2.2 b\r\n" +
		"\r\n" +
		"not-an-ip c\n" + // a real line with an invalid IP still counts
		"3.3.3.3 d\n" +
		"\n"
	want := []uint32{ipStringToUint32("1.1.1.1"), ipStringToUint32("2.2.2.2"), ipStringToUint32("3.3.3.3")}

	for _, cs := range []int64{4, 16, 64, 1 << 20} {
		got := framingAllPaths(t, `%h %^`, content, cs)
		assertFraming(t, fmt.Sprintf("chunk=%d", cs), got, want, 1, 0)
	}

	// No trailing newline, and a file that is nothing but blank lines.
	got := framingAllPaths(t, `%h %^`, "\n\n1.1.1.1 a", 8)
	assertFraming(t, "no trailing newline", got, want[:1], 0, 0)
	got = framingAllPaths(t, `%h %^`, "\n\r\n\n", 2)
	assertFraming(t, "only blank lines", got, nil, 0, 0)
}

// oversizedLine returns a syntactically valid line of exactly n bytes (no
// terminator) whose IP is ip.
func oversizedLine(ip string, n int) string {
	prefix := ip + " "
	return prefix + strings.Repeat("x", n-len(prefix))
}

// TestFraming_OversizedLineSkippedAndCounted: a line longer than MaxLineLen is
// skipped and counted on every path, and the rest of the file is parsed. The
// streaming reader used to abort the whole parse with a bare
// "bufio.Scanner: token too long"; the chunked reader silently dropped the
// line when it crossed a chunk boundary and parsed it when it did not.
func TestFraming_OversizedLineSkippedAndCounted(t *testing.T) {
	before := "1.1.1.1 a\n2.2.2.2 b\n"
	after := "3.3.3.3 c\n4.4.4.4 d\n"
	want := []uint32{
		ipStringToUint32("1.1.1.1"), ipStringToUint32("2.2.2.2"),
		ipStringToUint32("3.3.3.3"), ipStringToUint32("4.4.4.4"),
	}

	big := oversizedLine("9.9.9.9", MaxLineLen+1)
	huge := oversizedLine("9.9.9.9", 3*MaxLineLen+12345)

	cases := []struct {
		name          string
		content       string
		wantIPs       []uint32
		wantOversized uint64
	}{
		{"one byte over the limit, mid-file", before + big + "\n" + after, want, 1},
		{"one byte over the limit, CRLF", before + big[:len(big)-1] + "\r\n" + after, want, 1},
		{"several times the limit, mid-file", before + huge + "\n" + after, want, 1},
		{"first line", huge + "\n" + after, want[2:], 1},
		{"last line with newline", before + huge + "\n", want[:2], 1},
		{"last line without newline", before + huge, want[:2], 1},
		{"two oversized lines back to back", before + big + "\n" + huge + "\n" + after, want, 2},
		{"the whole file is one oversized line", huge, nil, 1},
	}

	// Chunk sizes: far smaller than the line (it spans many chunks), around
	// the limit, and larger than the whole file (the line sits inside a chunk).
	chunkSizes := []int64{64 * 1024, MaxLineLen - 7, MaxLineLen + 4096, 64 * 1024 * 1024}

	for _, tc := range cases {
		for _, cs := range chunkSizes {
			got := framingAllPaths(t, `%h %^`, tc.content, cs)
			assertFraming(t, fmt.Sprintf("%s chunk=%d", tc.name, cs), got, tc.wantIPs, 0, tc.wantOversized)
		}
	}
}

// TestFraming_LineAtTheLimitIsKept: MaxLineLen itself is still a valid line on
// every path, with LF, CRLF and no terminator.
func TestFraming_LineAtTheLimitIsKept(t *testing.T) {
	atLimit := oversizedLine("9.9.9.9", MaxLineLen)
	want := []uint32{ipStringToUint32("1.1.1.1"), ipStringToUint32("9.9.9.9"), ipStringToUint32("3.3.3.3")}

	cases := map[string]string{
		"LF":            "1.1.1.1 a\n" + atLimit + "\n3.3.3.3 c\n",
		"CRLF":          "1.1.1.1 a\n" + atLimit[:len(atLimit)-1] + "\r\n3.3.3.3 c\n",
		"no terminator": "1.1.1.1 a\n3.3.3.3 c\n" + atLimit,
	}
	for name, content := range cases {
		for _, cs := range []int64{64 * 1024, MaxLineLen - 7, MaxLineLen + 4096, 64 * 1024 * 1024} {
			got := framingAllPaths(t, `%h %^`, content, cs)
			assertFraming(t, fmt.Sprintf("%s chunk=%d", name, cs), got, want, 0, 0)
		}
	}
}

// TestFraming_OversizedLineThroughParseFile: the public entry points no longer
// fail on an oversized line.
func TestFraming_OversizedLineThroughParseFile(t *testing.T) {
	content := "1.1.1.1 a\n" + oversizedLine("9.9.9.9", MaxLineLen+100) + "\n3.3.3.3 c\n"
	path := writeTempLog(t, content)

	p := mustNewParser(t, `%h %^`)
	reqs, err := p.ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	if len(reqs) != 2 {
		t.Errorf("ParseFile returned %d requests, want 2", len(reqs))
	}
	if got := p.Stats().OversizedLines; got != 1 {
		t.Errorf("OversizedLines = %d, want 1", got)
	}

	p = mustNewParser(t, `%h %^`)
	ips, invalid, err := p.ParseFileIPs(path)
	if err != nil {
		t.Fatalf("ParseFileIPs: %v", err)
	}
	if len(ips) != 2 || invalid != 0 {
		t.Errorf("ParseFileIPs returned %d ips, %d invalid; want 2, 0", len(ips), invalid)
	}
	if got := p.Stats().OversizedLines; got != 1 {
		t.Errorf("OversizedLines = %d, want 1", got)
	}
}

// oneByteReader hands out a single byte per Read, so every line boundary,
// blank line and CR/LF pair is split across Scanner refills.
type oneByteReader struct{ r io.Reader }

func (o oneByteReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	return o.r.Read(p[:1])
}

// scanLines collects what newLineScanner yields from r.
func scanLines(r io.Reader) (lines []string, oversized uint64, err error) {
	scanner, splitter := newLineScanner(r)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, splitter.oversized, scanner.Err()
}

// TestLineSplitter_RandomAgainstReference frames random content (blank lines,
// CRLF, lone CRs, with and without a final newline) and compares the streaming
// splitter with a plain strings.Split reference, both when the whole input is
// buffered before EOF and when it trickles in one byte at a time. The first
// mode is the one where a skipped line used to end the scan early.
func TestLineSplitter_RandomAgainstReference(t *testing.T) {
	rng := rand.New(rand.NewSource(20261123))
	pieces := []string{"\n", "\n", "\r\n", "\r", "a", "bc", "1.2.3.4 x", " ", "\n\n", "\r\r\n"}

	for iter := 0; iter < 3000; iter++ {
		var b strings.Builder
		for n := rng.Intn(14); n > 0; n-- {
			b.WriteString(pieces[rng.Intn(len(pieces))])
		}
		content := b.String()

		var want []string
		for _, line := range strings.Split(content, "\n") {
			line = strings.TrimSuffix(line, "\r")
			if line != "" {
				want = append(want, line)
			}
		}

		readers := map[string]io.Reader{
			"buffered": strings.NewReader(content),
			"trickle":  oneByteReader{strings.NewReader(content)},
		}
		for name, r := range readers {
			got, oversized, err := scanLines(r)
			if err != nil || oversized != 0 {
				t.Fatalf("%s %q: err=%v oversized=%d", name, content, err, oversized)
			}
			if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
				t.Fatalf("%s %q:\n got  %q\n want %q", name, content, got, want)
			}
		}
	}
}

// TestLineSplitter_OversizedTrickle: an oversized line is skipped and counted
// once however the input is delivered, and the lines around it survive.
func TestLineSplitter_OversizedTrickle(t *testing.T) {
	content := "a\n\n" + strings.Repeat("x", 2*MaxLineLen+3) + "\r\n\nb\n" + strings.Repeat("y", MaxLineLen+1)
	got, oversized, err := scanLines(iotest.OneByteReader(strings.NewReader("")))
	if err != nil || len(got) != 0 || oversized != 0 {
		t.Fatalf("empty input: got %q oversized=%d err=%v", got, oversized, err)
	}

	for _, chunk := range []int{1 << 10, 1 << 16, 1 << 22, len(content)} {
		got, oversized, err := scanLines(&chunkReader{s: content, n: chunk})
		if err != nil {
			t.Fatalf("chunk=%d: %v", chunk, err)
		}
		if strings.Join(got, ",") != "a,b" || oversized != 2 {
			t.Errorf("chunk=%d: got %d lines (%.20q...), %d oversized; want [a b], 2", chunk, len(got), got, oversized)
		}
	}
}

// chunkReader returns at most n bytes per Read.
type chunkReader struct {
	s string
	n int
}

func (c *chunkReader) Read(p []byte) (int, error) {
	if len(c.s) == 0 {
		return 0, io.EOF
	}
	n := c.n
	if n > len(p) {
		n = len(p)
	}
	if n > len(c.s) {
		n = len(c.s)
	}
	copy(p, c.s[:n])
	c.s = c.s[n:]
	return n, nil
}
