package main

import (
	"fmt"
	"math/rand"
	"testing"

	"github.com/ChristianF88/cidrx/ingestor"
	"github.com/ChristianF88/cidrx/iputils"
	"github.com/ChristianF88/cidrx/logparser"
	"github.com/ChristianF88/cidrx/testutil"
	"github.com/ChristianF88/cidrx/trie"
)

// BenchmarkFullPipelineProfile profiles the complete static analysis pipeline:
// parse log file → extract IPs → convert to uint32 → sort → trie insertion → clustering
func BenchmarkFullPipelineProfile(b *testing.B) {
	// Generate a 500K line test log file
	tempFile, cleanup := testutil.GenerateTestLogFile(&testing.T{}, 500000)
	defer cleanup()

	parser, err := logparser.NewParallelParser("%h %^ %^ [%t] \"%r\" %s %b %^ \"%u\"")
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Phase 1: Parse log file (SkipStringFields is set, IPUint32 populated directly)
		requests, err := parser.ParseFile(tempFile)
		if err != nil {
			b.Fatal(err)
		}

		// Phase 2: Extract IPUint32 (no conversion needed - already uint32)
		ipUints := make([]uint32, len(requests))
		for j := range requests {
			ipUints[j] = requests[j].IPUint32
		}

		// Phase 3: Radix sort (O(n) vs sort.Slice O(n log n))
		iputils.RadixSortUint32(ipUints)

		// Phase 4: Trie insertion
		tr := trie.NewTrie()
		tr.BatchInsertSortedUint32(ipUints)

		// Phase 5: Clustering
		_ = tr.CollectCIDRsNumeric(1000, 16, 24, 0.1)

		_ = requests
	}
}

// BenchmarkParseOnly isolates parsing cost
func BenchmarkParseOnly(b *testing.B) {
	tempFile, cleanup := testutil.GenerateTestLogFile(&testing.T{}, 500000)
	defer cleanup()

	parser, err := logparser.NewParallelParser("%h %^ %^ [%t] \"%r\" %s %b %^ \"%u\"")
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		requests, err := parser.ParseFile(tempFile)
		if err != nil {
			b.Fatal(err)
		}
		_ = requests
	}
}

// BenchmarkIPConversionAndSort isolates IP conversion + sort cost
func BenchmarkIPConversionAndSort(b *testing.B) {
	sizes := []int{100000, 500000, 1000000}

	for _, size := range sizes {
		// Pre-generate requests with IPUint32 set directly
		rng := rand.New(rand.NewSource(42))
		requests := make([]ingestor.Request, size)
		for i := range requests {
			requests[i].IPUint32 = rng.Uint32()
		}

		b.Run(fmt.Sprintf("ExtractAndRadixSort_%d", size), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				ipUints := make([]uint32, len(requests))
				for j := range requests {
					ipUints[j] = requests[j].IPUint32
				}
				iputils.RadixSortUint32(ipUints)
				_ = ipUints
			}
		})

		b.Run(fmt.Sprintf("ExtractOnly_%d", size), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				ipUints := make([]uint32, len(requests))
				for j := range requests {
					ipUints[j] = requests[j].IPUint32
				}
				_ = ipUints
			}
		})
	}
}

// BenchmarkTrieInsertionOnly isolates trie insertion cost
func BenchmarkTrieInsertionOnly(b *testing.B) {
	sizes := []int{100000, 500000, 1000000}

	for _, size := range sizes {
		// Pre-generate sorted uint32 IPs
		rng := rand.New(rand.NewSource(42))
		ipUints := make([]uint32, size)
		for i := range ipUints {
			ipUints[i] = rng.Uint32()
		}
		iputils.RadixSortUint32(ipUints)

		b.Run(fmt.Sprintf("BatchSorted_%d", size), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				tr := trie.NewTrie()
				tr.BatchInsertSortedUint32(ipUints)
			}
		})

		b.Run(fmt.Sprintf("BatchUnsorted_%d", size), func(b *testing.B) {
			// Shuffle for unsorted benchmark
			unsorted := make([]uint32, len(ipUints))
			copy(unsorted, ipUints)
			rng := rand.New(rand.NewSource(99))
			rng.Shuffle(len(unsorted), func(i, j int) {
				unsorted[i], unsorted[j] = unsorted[j], unsorted[i]
			})

			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				tr := trie.NewTrie()
				for _, v := range unsorted {
					tr.InsertUint32(v)
				}
			}
		})
	}
}
