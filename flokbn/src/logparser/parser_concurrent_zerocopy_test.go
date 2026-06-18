package logparser

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/ChristianF88/flokbn/ingestor"
)

// concurrentZeroCopyFormat is the standard Apache combined-style format with the
// IP at the end (matches the real-world example in the repo instructions).
const concurrentZeroCopyFormat = `%^ %^ %^ [%t] "%r" %s %b %^ "%u" "%h"`

// genConcurrentTestLog produces a representative, deterministic Apache-style log
// of n "interesting" lines plus injected edge cases:
//   - valid IPs (varied octet widths so line lengths differ and straddle chunks),
//   - invalid / missing IP lines (kept-but-zero-IP in full mode, counted invalid
//     in IP mode — both paths agree),
//   - quoted UA/URI fields containing spaces.
//
// Line endings: the chunked reader now strips a trailing '\r' exactly like the
// streaming path's bufio.Scanner, so CRLF inputs parse identically on both
// paths (see TestConcurrentCRLF_ParityWithStreaming). The lineEnding parameter
// of genConcurrentTestLogLE selects "\n" or "\r\n".
//
// No blank lines are emitted either: the concurrent reader skips empty lines
// (continue), whereas the streaming reader hands them to the parser which treats
// "" as a (zero-IP) Request. That divergence is a long-standing, pre-existing
// property of the two readers and is orthogonal to the zero-copy change under
// test (both the old slab-copy and the new zero-copy concurrent code skip empty
// lines identically). Real Apache logs contain no blank lines, so excluding them
// keeps the differential comparison faithful to the change being validated.
//
// withTrailingNewline controls whether the file ends in '\n'. The no-trailing
// case specifically exercises readChunkBatched's EOF trailing-line handling.
func genConcurrentTestLog(n int, withTrailingNewline bool) string {
	return genConcurrentTestLogLE(n, withTrailingNewline, "\n")
}

// genConcurrentTestLogLE is genConcurrentTestLog with a selectable line ending
// ("\n" or "\r\n"). withTrailingNewline=false strips the final lineEnding.
func genConcurrentTestLogLE(n int, withTrailingNewline bool, lineEnding string) string {
	var b strings.Builder
	uas := []string{
		"Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/123.0",
		"curl/8.5.0",
		"Googlebot/2.1 (+http://www.google.com/bot.html)",
		"-",
	}
	uris := []string{
		"GET /index.html HTTP/1.1",
		"POST /api/v1/login?next=/dashboard HTTP/1.1",
		"GET /a/very/long/path/segment/that/pads/the/line/out/further HTTP/1.1",
		"HEAD / HTTP/1.0",
	}
	for i := 0; i < n; i++ {
		switch i % 11 {
		case 3:
			// Invalid/missing IP — both paths agree: zero-IP Request in full mode,
			// counted invalid in IP mode.
			b.WriteString(fmt.Sprintf(
				`- - - [10/Oct/2024:13:55:%02d +0000] "%s" 200 1234 "x" "%s" "not-an-ip"`,
				i%60, uris[i%len(uris)], uas[i%len(uas)]))
			b.WriteString(lineEnding)
		default:
			// Valid line. Vary IP octet widths and byte counts so line lengths
			// differ widely, forcing many lines to straddle small-chunk boundaries.
			ip := fmt.Sprintf("%d.%d.%d.%d", 1+(i%223), (i*7)%256, (i*13)%256, (i*29)%256)
			status := 200 + (i % 5)
			bytesN := (i * 37) % 100000
			b.WriteString(fmt.Sprintf(
				`- - - [10/Oct/2024:13:55:%02d +0000] "%s" %d %d "x" "%s" "%s"`,
				i%60, uris[i%len(uris)], status, bytesN, uas[i%len(uas)], ip))
			b.WriteString(lineEnding)
		}
	}
	s := b.String()
	if !withTrailingNewline {
		s = strings.TrimSuffix(s, lineEnding)
	}
	return s
}

func writeTempLog(t testing.TB, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "concurrent_zerocopy_*.log")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("WriteString: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return f.Name()
}

// reqKey is a fully-comparable projection of a Request used to sort and compare
// the multisets produced by the two parsing paths.
type reqKey struct {
	IP        uint32
	Status    uint16
	Method    ingestor.HTTPMethod
	Bytes     uint32
	TimeUnix  int64
	URI       string
	UserAgent string
}

func toReqKey(r ingestor.Request) reqKey {
	return reqKey{
		IP:        r.IPUint32,
		Status:    r.Status,
		Method:    r.Method,
		Bytes:     r.Bytes,
		TimeUnix:  r.Timestamp.UnixNano(),
		URI:       r.URI,
		UserAgent: r.UserAgent,
	}
}

func sortReqKeys(ks []reqKey) {
	sort.Slice(ks, func(i, j int) bool {
		a, b := ks[i], ks[j]
		if a.IP != b.IP {
			return a.IP < b.IP
		}
		if a.Status != b.Status {
			return a.Status < b.Status
		}
		if a.Bytes != b.Bytes {
			return a.Bytes < b.Bytes
		}
		if a.TimeUnix != b.TimeUnix {
			return a.TimeUnix < b.TimeUnix
		}
		if a.URI != b.URI {
			return a.URI < b.URI
		}
		if a.UserAgent != b.UserAgent {
			return a.UserAgent < b.UserAgent
		}
		return a.Method < b.Method
	})
}

// parseConcurrentFull drives the concurrent path directly with an overridden
// chunkSize so the >=500MB gate is bypassed and small files produce many chunks.
func parseConcurrentFull(t *testing.T, pp *Parser, path string, chunkSize int64) []ingestor.Request {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	reqs, err := pp.parseFileConcurrentIOChunked(f, f.Name(), st.Size(), chunkSize)
	if err != nil {
		t.Fatalf("parseFileConcurrentIOChunked: %v", err)
	}
	return reqs
}

func parseConcurrentIPs(t *testing.T, pp *Parser, path string, chunkSize int64) ([]uint32, int) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	ips, invalid, err := pp.parseFileIPsConcurrentIOChunked(f, f.Name(), st.Size(), chunkSize)
	if err != nil {
		t.Fatalf("parseFileIPsConcurrentIOChunked: %v", err)
	}
	return ips, invalid
}

// parseStreamingFull drives the streaming full-Request path. The streaming
// helpers now take the already-open *os.File and its size (so ParseFile opens
// the file only once), so the test opens/stats/closes here.
func parseStreamingFull(t *testing.T, pp *Parser, path string) []ingestor.Request {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	reqs, err := pp.parseFileWithStreamingIO(f, st.Size())
	if err != nil {
		t.Fatalf("parseFileWithStreamingIO: %v", err)
	}
	return reqs
}

// parseStreamingIPs drives the streaming IP-only path with the same open/stat
// ownership as parseStreamingFull.
func parseStreamingIPs(t *testing.T, pp *Parser, path string) ([]uint32, int) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	ips, invalid, err := pp.parseFileIPsStreamingIO(f, st.Size())
	if err != nil {
		t.Fatalf("parseFileIPsStreamingIO: %v", err)
	}
	return ips, invalid
}

// TestConcurrentZeroCopy_DiffFullMode asserts that the zero-copy concurrent path
// produces the identical multiset of Requests (every field) as the streaming
// path, across small chunk sizes (forcing many boundary crossings) and both with
// and without a trailing newline.
func TestConcurrentZeroCopy_DiffFullMode(t *testing.T) {
	const nLines = 5000
	// Includes a very small chunk (256B) so nearly every line straddles or aligns
	// to a boundary, plus 1023/4097 (coprime-ish to line lengths) to exercise
	// lines starting exactly at a boundary (the sentinel-byte path).
	chunkSizes := []int64{256, 1023, 4 * 1024, 4097, 64 * 1024}

	for _, trailing := range []bool{true, false} {
		content := genConcurrentTestLog(nLines, trailing)
		path := writeTempLog(t, content)

		pp, err := NewParser(concurrentZeroCopyFormat)
		if err != nil {
			t.Fatalf("NewParser: %v", err)
		}

		streamReqs := parseStreamingFull(t, pp, path)
		streamKeys := make([]reqKey, len(streamReqs))
		for i, r := range streamReqs {
			streamKeys[i] = toReqKey(r)
		}
		sortReqKeys(streamKeys)

		for _, cs := range chunkSizes {
			concReqs := parseConcurrentFull(t, pp, path, cs)

			if len(concReqs) != len(streamReqs) {
				t.Fatalf("trailing=%v chunk=%d: count mismatch: concurrent=%d streaming=%d (lost/dup line)",
					trailing, cs, len(concReqs), len(streamReqs))
			}

			concKeys := make([]reqKey, len(concReqs))
			for i, r := range concReqs {
				concKeys[i] = toReqKey(r)
			}
			sortReqKeys(concKeys)

			for i := range streamKeys {
				if concKeys[i] != streamKeys[i] {
					t.Fatalf("trailing=%v chunk=%d: field mismatch at sorted index %d:\n concurrent=%+v\n streaming=%+v",
						trailing, cs, i, concKeys[i], streamKeys[i])
				}
			}
		}
	}
}

// TestConcurrentZeroCopy_DiffIPMode asserts the IP-only concurrent path yields
// the identical multiset of IPs and identical invalid count as the streaming
// IP path, across small chunks and trailing-newline variants.
func TestConcurrentZeroCopy_DiffIPMode(t *testing.T) {
	const nLines = 5000
	// Includes a very small chunk (256B) so nearly every line straddles or aligns
	// to a boundary, plus 1023/4097 (coprime-ish to line lengths) to exercise
	// lines starting exactly at a boundary (the sentinel-byte path).
	chunkSizes := []int64{256, 1023, 4 * 1024, 4097, 64 * 1024}

	for _, trailing := range []bool{true, false} {
		content := genConcurrentTestLog(nLines, trailing)
		path := writeTempLog(t, content)

		pp, err := NewParser(concurrentZeroCopyFormat)
		if err != nil {
			t.Fatalf("NewParser: %v", err)
		}
		pp.SkipNonIPFields = true

		streamIPs, streamInvalid := parseStreamingIPs(t, pp, path)
		sortedStream := append([]uint32(nil), streamIPs...)
		sort.Slice(sortedStream, func(i, j int) bool { return sortedStream[i] < sortedStream[j] })

		for _, cs := range chunkSizes {
			concIPs, concInvalid := parseConcurrentIPs(t, pp, path, cs)

			if len(concIPs) != len(streamIPs) {
				t.Fatalf("trailing=%v chunk=%d: IP count mismatch: concurrent=%d streaming=%d",
					trailing, cs, len(concIPs), len(streamIPs))
			}
			if concInvalid != streamInvalid {
				t.Fatalf("trailing=%v chunk=%d: invalid count mismatch: concurrent=%d streaming=%d",
					trailing, cs, concInvalid, streamInvalid)
			}

			sortedConc := append([]uint32(nil), concIPs...)
			sort.Slice(sortedConc, func(i, j int) bool { return sortedConc[i] < sortedConc[j] })
			for i := range sortedStream {
				if sortedConc[i] != sortedStream[i] {
					t.Fatalf("trailing=%v chunk=%d: IP multiset mismatch at index %d: concurrent=%d streaming=%d",
						trailing, cs, i, sortedConc[i], sortedStream[i])
				}
			}
		}
	}
}

// TestConcurrentCRLF_ParityWithStreaming asserts that CRLF-terminated logs
// parse identically on the streaming path (bufio.Scanner strips '\r') and the
// chunked path (readChunkBatched now strips '\r' too), across chunk sizes and
// trailing-newline variants, including a file whose last byte is '\r' with no
// final '\n' (exercises the EOF emission site).
func TestConcurrentCRLF_ParityWithStreaming(t *testing.T) {
	const nLines = 3000
	chunkSizes := []int64{256, 1023, 4096, 64 * 1024}

	variants := []struct {
		name    string
		content string
	}{
		{"crlf_trailing_newline", genConcurrentTestLogLE(nLines, true, "\r\n")},
		{"crlf_no_trailing_newline", genConcurrentTestLogLE(nLines, false, "\r\n")},
		// File ends in "...\r" with NO final '\n': the trailing-line EOF path in
		// readChunkBatched must strip that '\r'.
		{"crlf_final_cr_no_lf", strings.TrimSuffix(genConcurrentTestLogLE(nLines, true, "\r\n"), "\n")},
	}

	for _, v := range variants {
		t.Run(v.name, func(t *testing.T) {
			path := writeTempLog(t, v.content)

			pp, err := NewParser(concurrentZeroCopyFormat)
			if err != nil {
				t.Fatalf("NewParser: %v", err)
			}

			streamReqs := parseStreamingFull(t, pp, path)
			for _, r := range streamReqs {
				if strings.ContainsRune(r.URI, '\r') || strings.ContainsRune(r.UserAgent, '\r') {
					t.Fatalf("streaming: parsed string field contains '\\r': URI=%q UA=%q", r.URI, r.UserAgent)
				}
			}
			streamKeys := make([]reqKey, len(streamReqs))
			for i, r := range streamReqs {
				streamKeys[i] = toReqKey(r)
			}
			sortReqKeys(streamKeys)

			for _, cs := range chunkSizes {
				concReqs := parseConcurrentFull(t, pp, path, cs)

				if len(concReqs) != len(streamReqs) {
					t.Fatalf("chunk=%d: count mismatch: concurrent=%d streaming=%d",
						cs, len(concReqs), len(streamReqs))
				}
				for _, r := range concReqs {
					if strings.ContainsRune(r.URI, '\r') || strings.ContainsRune(r.UserAgent, '\r') {
						t.Fatalf("chunk=%d: parsed string field contains '\\r': URI=%q UA=%q", cs, r.URI, r.UserAgent)
					}
				}

				concKeys := make([]reqKey, len(concReqs))
				for i, r := range concReqs {
					concKeys[i] = toReqKey(r)
				}
				sortReqKeys(concKeys)

				for i := range streamKeys {
					if concKeys[i] != streamKeys[i] {
						t.Fatalf("chunk=%d: field mismatch at sorted index %d:\n concurrent=%+v\n streaming=%+v",
							cs, i, concKeys[i], streamKeys[i])
					}
				}
			}
		})
	}
}

// TestConcurrentCRLF_IPModeParity is the IP-only variant: with CRLF endings the
// trailing quoted "%h" field must not absorb the '\r', and the chunked IP path
// must agree with the streaming IP path on both the IP multiset and the
// invalid count.
func TestConcurrentCRLF_IPModeParity(t *testing.T) {
	const nLines = 3000
	chunkSizes := []int64{256, 1023, 4096, 64 * 1024}

	for _, trailing := range []bool{true, false} {
		content := genConcurrentTestLogLE(nLines, trailing, "\r\n")
		path := writeTempLog(t, content)

		pp, err := NewParser(concurrentZeroCopyFormat)
		if err != nil {
			t.Fatalf("NewParser: %v", err)
		}
		pp.SkipNonIPFields = true

		streamIPs, streamInvalid := parseStreamingIPs(t, pp, path)
		sortedStream := append([]uint32(nil), streamIPs...)
		sort.Slice(sortedStream, func(i, j int) bool { return sortedStream[i] < sortedStream[j] })

		for _, cs := range chunkSizes {
			concIPs, concInvalid := parseConcurrentIPs(t, pp, path, cs)

			if len(concIPs) != len(streamIPs) {
				t.Fatalf("trailing=%v chunk=%d: IP count mismatch: concurrent=%d streaming=%d",
					trailing, cs, len(concIPs), len(streamIPs))
			}
			if concInvalid != streamInvalid {
				t.Fatalf("trailing=%v chunk=%d: invalid count mismatch: concurrent=%d streaming=%d",
					trailing, cs, concInvalid, streamInvalid)
			}

			sortedConc := append([]uint32(nil), concIPs...)
			sort.Slice(sortedConc, func(i, j int) bool { return sortedConc[i] < sortedConc[j] })
			for i := range sortedStream {
				if sortedConc[i] != sortedStream[i] {
					t.Fatalf("trailing=%v chunk=%d: IP multiset mismatch at index %d: concurrent=%d streaming=%d",
						trailing, cs, i, sortedConc[i], sortedStream[i])
				}
			}
		}
	}
}

// genLongLineLog builds a log of short valid lines with ONE valid line whose URI
// is padded with `pad` filler bytes (so the whole line is well over the 8192-byte
// overlap), inserted at index longIdx. The long line carries a distinctive IP so
// the test can assert it survived. Returns the content and that distinctive IP.
//
// The padding is placed inside the URI's path (no spaces, no quotes), so the line
// stays a single valid Apache record that BOTH the streaming bufio.Scanner and the
// chunked reader frame as one line. The long URI is parsed as a full-regex-free
// field (this fix is purely line framing; regex filters are untouched).
func genLongLineLog(nShort, longIdx, pad int, longIPStr string) string {
	var b strings.Builder
	filler := strings.Repeat("a", pad)
	uas := []string{
		"Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/123.0",
		"curl/8.5.0",
	}
	for i := 0; i < nShort; i++ {
		if i == longIdx {
			// One very long but valid line (URI padded > overlap).
			b.WriteString(fmt.Sprintf(
				`- - - [10/Oct/2024:13:55:%02d +0000] "GET /pad/%s/end HTTP/1.1" 200 1234 "x" "%s" "%s"`,
				i%60, filler, uas[i%len(uas)], longIPStr))
			b.WriteString("\n")
			continue
		}
		ip := fmt.Sprintf("%d.%d.%d.%d", 1+(i%223), (i*7)%256, (i*13)%256, (i*29)%256)
		b.WriteString(fmt.Sprintf(
			`- - - [10/Oct/2024:13:55:%02d +0000] "GET /p/%d HTTP/1.1" 200 %d "x" "%s" "%s"`,
			i%60, i, (i*37)%100000, uas[i%len(uas)], ip))
		b.WriteString("\n")
	}
	return b.String()
}

// TestConcurrentLongLine_DiffFullMode is the AUDIT-11 regression test: a single
// valid line whose URI is padded far beyond the 8192-byte overlap (32KB here)
// must be emitted EXACTLY ONCE on the chunked path and the full Request multiset
// must equal the streaming path's, across chunk sizes that place the long line
// across a boundary (small chunks << line length, and a chunk near the line's
// midpoint). Before the fix the long line was silently dropped by the chunked
// path on every chunk size smaller than the long line, diverging from streaming.
func TestConcurrentLongLine_DiffFullMode(t *testing.T) {
	const nShort = 400
	const pad = 32 * 1024 // line >> 8192 overlap
	const longIPStr = "203.0.113.207"
	var longIP uint32 = 203<<24 | 0<<16 | 113<<8 | 207

	// longIdx chosen so the long line is roughly in the middle of the file.
	content := genLongLineLog(nShort, nShort/2, pad, longIPStr)
	path := writeTempLog(t, content)

	pp, err := NewParser(concurrentZeroCopyFormat)
	if err != nil {
		t.Fatalf("NewParser: %v", err)
	}

	streamReqs := parseStreamingFull(t, pp, path)
	streamKeys := make([]reqKey, len(streamReqs))
	for i, r := range streamReqs {
		streamKeys[i] = toReqKey(r)
	}
	sortReqKeys(streamKeys)

	// Chunk sizes: much smaller than the 32KB line (so it straddles boundaries),
	// one ~half the line length (long line midpoint near a boundary), and the
	// default-ish 64KB (line wholly inside one chunk's window — control).
	chunkSizes := []int64{256, 1024, 4096, 8192, 16 * 1024, 17 * 1024, 64 * 1024}

	for _, cs := range chunkSizes {
		concReqs := parseConcurrentFull(t, pp, path, cs)

		if len(concReqs) != len(streamReqs) {
			t.Fatalf("chunk=%d: count mismatch: concurrent=%d streaming=%d (long line lost/dup)",
				cs, len(concReqs), len(streamReqs))
		}

		// The long line must appear exactly once on the chunked path.
		longCount := 0
		for _, r := range concReqs {
			if r.IPUint32 == longIP {
				longCount++
				if !strings.HasPrefix(r.URI, "/pad/") || len(r.URI) < pad {
					t.Fatalf("chunk=%d: long line URI corrupted: len=%d prefix-ok=%v",
						cs, len(r.URI), strings.HasPrefix(r.URI, "/pad/"))
				}
			}
		}
		if longCount != 1 {
			t.Fatalf("chunk=%d: long line emitted %d times, want exactly 1", cs, longCount)
		}

		concKeys := make([]reqKey, len(concReqs))
		for i, r := range concReqs {
			concKeys[i] = toReqKey(r)
		}
		sortReqKeys(concKeys)
		for i := range streamKeys {
			if concKeys[i] != streamKeys[i] {
				t.Fatalf("chunk=%d: field mismatch at sorted index %d:\n concurrent=%+v\n streaming=%+v",
					cs, i, concKeys[i], streamKeys[i])
			}
		}
	}
}

// TestConcurrentLongLine_DiffIPMode is the IP-only counterpart: the long line's IP
// must be counted exactly once on the chunked IP path and the IP multiset +
// invalid count must equal the streaming IP path's, across boundary-straddling
// chunk sizes. ParseFileIPs reuses readChunkBatched verbatim, so the recovery
// must work identically here.
func TestConcurrentLongLine_DiffIPMode(t *testing.T) {
	const nShort = 400
	const pad = 32 * 1024
	const longIPStr = "203.0.113.207"
	var longIP uint32 = 203<<24 | 0<<16 | 113<<8 | 207

	content := genLongLineLog(nShort, nShort/2, pad, longIPStr)
	path := writeTempLog(t, content)

	pp, err := NewParser(concurrentZeroCopyFormat)
	if err != nil {
		t.Fatalf("NewParser: %v", err)
	}
	pp.SkipNonIPFields = true

	streamIPs, streamInvalid := parseStreamingIPs(t, pp, path)
	sortedStream := append([]uint32(nil), streamIPs...)
	sort.Slice(sortedStream, func(i, j int) bool { return sortedStream[i] < sortedStream[j] })

	chunkSizes := []int64{256, 1024, 4096, 8192, 16 * 1024, 17 * 1024, 64 * 1024}

	for _, cs := range chunkSizes {
		concIPs, concInvalid := parseConcurrentIPs(t, pp, path, cs)

		if len(concIPs) != len(streamIPs) {
			t.Fatalf("chunk=%d: IP count mismatch: concurrent=%d streaming=%d",
				cs, len(concIPs), len(streamIPs))
		}
		if concInvalid != streamInvalid {
			t.Fatalf("chunk=%d: invalid count mismatch: concurrent=%d streaming=%d",
				cs, concInvalid, streamInvalid)
		}

		longCount := 0
		for _, ip := range concIPs {
			if ip == longIP {
				longCount++
			}
		}
		if longCount != 1 {
			t.Fatalf("chunk=%d: long line IP counted %d times, want exactly 1", cs, longCount)
		}

		sortedConc := append([]uint32(nil), concIPs...)
		sort.Slice(sortedConc, func(i, j int) bool { return sortedConc[i] < sortedConc[j] })
		for i := range sortedStream {
			if sortedConc[i] != sortedStream[i] {
				t.Fatalf("chunk=%d: IP multiset mismatch at index %d: concurrent=%d streaming=%d",
					cs, i, sortedConc[i], sortedStream[i])
			}
		}
	}
}

// TestConcurrentLongLine_StartAtBoundaryAndEOF covers two ownership branches for
// long lines: (a) a long line whose start is positioned so chunk sizes make it
// straddle, and (b) a long line that is the FINAL line of the file with NO
// trailing newline (the long line's tail reaches EOF during recovery). Both must
// match the streaming path exactly.
func TestConcurrentLongLine_StartAtBoundaryAndEOF(t *testing.T) {
	const nShort = 200
	const pad = 24 * 1024
	const longIPStr = "198.51.100.42"
	var longIP uint32 = 198<<24 | 51<<16 | 100<<8 | 42

	// Long line is the LAST line; strip the final '\n' so it terminates at EOF.
	content := genLongLineLog(nShort, nShort-1, pad, longIPStr)
	content = strings.TrimSuffix(content, "\n")
	path := writeTempLog(t, content)

	pp, err := NewParser(concurrentZeroCopyFormat)
	if err != nil {
		t.Fatalf("NewParser: %v", err)
	}

	streamReqs := parseStreamingFull(t, pp, path)
	streamKeys := make([]reqKey, len(streamReqs))
	for i, r := range streamReqs {
		streamKeys[i] = toReqKey(r)
	}
	sortReqKeys(streamKeys)

	chunkSizes := []int64{256, 1024, 4096, 8192, 16 * 1024, 64 * 1024}
	for _, cs := range chunkSizes {
		concReqs := parseConcurrentFull(t, pp, path, cs)
		if len(concReqs) != len(streamReqs) {
			t.Fatalf("chunk=%d: count mismatch: concurrent=%d streaming=%d",
				cs, len(concReqs), len(streamReqs))
		}
		longCount := 0
		for _, r := range concReqs {
			if r.IPUint32 == longIP {
				longCount++
			}
		}
		if longCount != 1 {
			t.Fatalf("chunk=%d: EOF long line emitted %d times, want exactly 1", cs, longCount)
		}
		concKeys := make([]reqKey, len(concReqs))
		for i, r := range concReqs {
			concKeys[i] = toReqKey(r)
		}
		sortReqKeys(concKeys)
		for i := range streamKeys {
			if concKeys[i] != streamKeys[i] {
				t.Fatalf("chunk=%d: field mismatch at sorted index %d:\n concurrent=%+v\n streaming=%+v",
					cs, i, concKeys[i], streamKeys[i])
			}
		}
	}
}

// BenchmarkConcurrentZeroCopy_Full exercises the zero-copy concurrent full-Request
// path with a small chunk size on a multi-thousand-line file (many chunks,
// boundary crossings). With ReportAllocs the per-line slab copy that used to be
// performed in readChunkBatched is gone: there is now a single allocation per
// chunk (the ReadAt buffer) shared by all of that chunk's line sub-slices, rather
// than an additional full-chunk slab memcpy plus per-batch slab allocations.
func BenchmarkConcurrentZeroCopy_Full(b *testing.B) {
	content := genConcurrentTestLog(50000, true)
	path := writeTempLog(b, content)
	pp, err := NewParser(concurrentZeroCopyFormat)
	if err != nil {
		b.Fatalf("NewParser: %v", err)
	}
	const chunkSize = 64 * 1024

	f, err := os.Open(path)
	if err != nil {
		b.Fatalf("Open: %v", err)
	}
	defer f.Close()
	st, _ := f.Stat()
	size := st.Size()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reqs, err := pp.parseFileConcurrentIOChunked(f, f.Name(), size, chunkSize)
		if err != nil {
			b.Fatalf("parse: %v", err)
		}
		if len(reqs) == 0 {
			b.Fatal("no requests parsed")
		}
	}
}

// BenchmarkConcurrentZeroCopy_IPOnly exercises the zero-copy concurrent IP-only
// path. Here nothing aliases the line bytes, so each chunk buffer is freed right
// after its lines are parsed; the slab memcpy is likewise eliminated.
func BenchmarkConcurrentZeroCopy_IPOnly(b *testing.B) {
	content := genConcurrentTestLog(50000, true)
	path := writeTempLog(b, content)
	pp, err := NewParser(concurrentZeroCopyFormat)
	if err != nil {
		b.Fatalf("NewParser: %v", err)
	}
	pp.SkipNonIPFields = true
	const chunkSize = 64 * 1024

	f, err := os.Open(path)
	if err != nil {
		b.Fatalf("Open: %v", err)
	}
	defer f.Close()
	st, _ := f.Stat()
	size := st.Size()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ips, _, err := pp.parseFileIPsConcurrentIOChunked(f, f.Name(), size, chunkSize)
		if err != nil {
			b.Fatalf("parse: %v", err)
		}
		if len(ips) == 0 {
			b.Fatal("no ips parsed")
		}
	}
}
