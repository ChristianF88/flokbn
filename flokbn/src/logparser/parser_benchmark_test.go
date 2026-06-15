package logparser

import (
	"fmt"
	"os"
	"testing"

	"github.com/ChristianF88/flokbn/ingestor"
	"github.com/ChristianF88/flokbn/testutil"
)

// BenchmarkFileIO measures file I/O performance for chunk processing
func BenchmarkFileIO(b *testing.B) {
	// Create a temporary large file for testing
	tempFile, cleanup := testutil.GenerateTestLogFile(&testing.T{}, 1000000) // 1M lines
	defer cleanup()

	sizes := []int{1000, 5000, 10000, 50000}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("ParseConcurrent_%d_lines", size), func(b *testing.B) {
			parser, err := NewParser("%h %^ %^ [%t] \"%r\" %s %b %^ \"%u\"")
			if err != nil {
				b.Fatal(err)
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _ = parser.ParseFile(tempFile)
			}
		})
	}
}

// BenchmarkFileOpenOperations measures the cost of file opening operations
func BenchmarkFileOpenOperations(b *testing.B) {
	tempFile, cleanup := testutil.GenerateTestLogFile(&testing.T{}, 10000) // 10K lines
	defer cleanup()

	b.Run("SingleFileHandle", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			file, err := os.Open(tempFile)
			if err != nil {
				b.Fatal(err)
			}
			file.Close()
		}
	})

	b.Run("MultipleFileHandles", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			// Simulate opening multiple handles like chunk processing does
			handles := make([]*os.File, 8)
			for j := 0; j < 8; j++ {
				handle, err := os.Open(tempFile)
				if err != nil {
					b.Fatal(err)
				}
				handles[j] = handle
			}
			for _, handle := range handles {
				handle.Close()
			}
		}
	})
}

// BenchmarkChunkProcessing measures chunk processing performance
func BenchmarkChunkProcessing(b *testing.B) {
	tempFile, cleanup := testutil.GenerateTestLogFile(&testing.T{}, 100000) // 100K lines
	defer cleanup()

	parser, err := NewParser("%h %^ %^ [%t] \"%r\" %s %b %^ \"%u\"")
	if err != nil {
		b.Fatal(err)
	}

	b.Run("ChunkProcessing", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = parser.ParseFile(tempFile)
		}
	})
}

// BenchmarkParseLineReuseOpt benchmarks single-line parsing through the
// compiled-format path used by the production file workers
// (parseLineReuseOpt), isolating per-line allocation costs. It replaces the
// removed root-package BenchmarkParseLineIsolated with the same corpus/format.
func BenchmarkParseLineReuseOpt(b *testing.B) {
	parser, err := NewParser("%h %^ %^ [%t] \"%r\" %s %b %^ \"%u\"")
	if err != nil {
		b.Fatal(err)
	}

	line := []byte(`192.168.1.100 - - [01/Jan/2025:10:15:30 +0000] "GET /api/users HTTP/1.1" 200 1024 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"`)

	b.Run("FreshRequest", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			req := &ingestor.Request{}
			if err := parser.compiled.parseLineReuseOpt(line, req, false, false); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("ReusedRequest", func(b *testing.B) {
		b.ReportAllocs()
		req := &ingestor.Request{}
		for i := 0; i < b.N; i++ {
			if err := parser.compiled.parseLineReuseOpt(line, req, false, false); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("ReusedRequest_SkipStrings", func(b *testing.B) {
		b.ReportAllocs()
		req := &ingestor.Request{}
		for i := 0; i < b.N; i++ {
			if err := parser.compiled.parseLineReuseOpt(line, req, true, false); err != nil {
				b.Fatal(err)
			}
		}
	})
}
