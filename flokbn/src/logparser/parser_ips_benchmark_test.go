package logparser

import (
	"testing"

	"github.com/ChristianF88/flokbn/ingestor"
	"github.com/ChristianF88/flokbn/testutil"
)

// The format used by the generated test corpus (testutil) — IP first, IP also
// repeated last in the real Apache combined line; we mirror the shape used by
// the rest of the suite.
const ipsBenchFormat = `%h %^ %^ [%t] "%r" %s %b %^ "%u"`

// BenchmarkParseOnly measures the existing full-Request parse path (ParseFile)
// over a 500k-line corpus with skip flags on (clustering/static workload).
func BenchmarkParseOnly(b *testing.B) {
	tempFile, cleanup := testutil.GenerateTestLogFile(&testing.T{}, 500000)
	defer cleanup()

	parser, err := NewParser(ipsBenchFormat)
	if err != nil {
		b.Fatal(err)
	}
	parser.SkipStringFields = true
	parser.SkipNonIPFields = true

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reqs, err := parser.ParseFile(tempFile)
		if err != nil {
			b.Fatal(err)
		}
		_ = reqs
	}
}

// BenchmarkParseFileIPs measures the new IP-only fast path over the same corpus.
func BenchmarkParseFileIPs(b *testing.B) {
	tempFile, cleanup := testutil.GenerateTestLogFile(&testing.T{}, 500000)
	defer cleanup()

	parser, err := NewParser(ipsBenchFormat)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ips, _, err := parser.ParseFileIPs(tempFile)
		if err != nil {
			b.Fatal(err)
		}
		_ = ips
	}
}

var ipSink uint32

// BenchmarkParseIPv4Old benchmarks the verbatim reference implementation.
func BenchmarkParseIPv4Old(b *testing.B) {
	line := []byte("192.168.123.231")
	b.ReportAllocs()
	b.ResetTimer()
	var s uint32
	for i := 0; i < b.N; i++ {
		s = parseIPv4ToUint32_ref(line, 0, len(line))
	}
	ipSink = s
}

// BenchmarkParseIPv4New benchmarks the new branch-light implementation.
func BenchmarkParseIPv4New(b *testing.B) {
	line := []byte("192.168.123.231")
	b.ReportAllocs()
	b.ResetTimer()
	var s uint32
	for i := 0; i < b.N; i++ {
		s = parseIPv4ToUint32(line, 0, len(line))
	}
	ipSink = s
}

var benchLine = []byte(`192.168.1.100 - - [01/Jan/2025:10:15:30 +0000] "GET /api/users HTTP/1.1" 200 1024 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" "192.168.1.100"`)

// BenchmarkExtractIPOnly benchmarks the IP-only line extractor.
func BenchmarkExtractIPOnly(b *testing.B) {
	cf, err := compileFormat(ipsBenchFormat)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	var s uint32
	for i := 0; i < b.N; i++ {
		s = cf.extractIPOnly(benchLine)
	}
	ipSink = s
}

// BenchmarkParseLineIsolated benchmarks the full skip-mode line parse (the path
// extractIPOnly replaces) so the two can be compared directly.
func BenchmarkParseLineIsolated(b *testing.B) {
	cf, err := compileFormat(ipsBenchFormat)
	if err != nil {
		b.Fatal(err)
	}
	var req ingestor.Request
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req = ingestor.Request{}
		_ = cf.parseUsingCompiledFormatOpt(benchLine, &req, true, true)
	}
	ipSink = req.IPUint32
}
