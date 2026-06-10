package main

import (
	"fmt"
	"testing"

	"github.com/ChristianF88/cidrx/ingestor"
	"github.com/ChristianF88/cidrx/iputils"
	"github.com/ChristianF88/cidrx/trie"
)

// BenchmarkEndToEndOptimization compares old vs new data flow
func BenchmarkEndToEndOptimization(b *testing.B) {
	sizes := []int{1000, 10000, 100000}

	for _, size := range sizes {
		// Generate test IPs
		ips, err := iputils.RandomIPsFromRange("10.0.0.0/8", size)
		if err != nil {
			b.Fatalf("Failed to generate IPs: %v", err)
		}

		// Pre-convert to uint32 for optimized path
		uint32IPs := make([]uint32, len(ips))
		for i, ip := range ips {
			uint32IPs[i] = iputils.IPToUint32(ip)
		}

		b.Run(fmt.Sprintf("OldPath_%d_IPs", size), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				// Old path: net.IP -> Trie -> string CIDRs
				tr := trie.NewTrie()
				for _, ip := range ips {
					tr.Insert(ip) // This does net.IP -> uint32 conversion every time
				}
				_ = tr.CollectCIDRs(10, 8, 24, 0.5) // This does uint32 -> string conversion
			}
		})

		b.Run(fmt.Sprintf("NewPath_%d_IPs", size), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				// New path: uint32 -> Trie -> numeric CIDRs -> strings only at end
				tr := trie.NewTrie()
				for _, v := range uint32IPs { // Direct uint32 insertion
					tr.InsertUint32(v)
				}
				numericCIDRs := tr.CollectCIDRsNumeric(10, 8, 24, 0.5) // No string allocations

				// Convert to strings only at the very end
				result := make([]string, len(numericCIDRs))
				for j, nc := range numericCIDRs {
					result[j] = nc.String()
				}
				_ = result
			}
		})

		b.Run(fmt.Sprintf("OptimizedRequest_%d_IPs", size), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				// Simulate parsing log entries directly to OptimizedRequest
				requests := make([]ingestor.OptimizedRequest, len(uint32IPs))
				for j, ip := range uint32IPs {
					requests[j] = ingestor.OptimizedRequest{
						IP: ip, // Direct uint32 assignment - no conversion!
					}
				}

				// Insert directly from OptimizedRequest
				tr := trie.NewTrie()
				for _, req := range requests {
					tr.InsertUint32(req.IP) // Direct uint32 insertion
				}

				// Collect numeric CIDRs
				numericCIDRs := tr.CollectCIDRsNumeric(10, 8, 24, 0.5)

				// Convert to strings only for final output
				result := make([]string, len(numericCIDRs))
				for j, nc := range numericCIDRs {
					result[j] = nc.String()
				}
				_ = result
			}
		})
	}
}

// BenchmarkIPConversionElimination tests pure IP conversion overhead
func BenchmarkIPConversionElimination(b *testing.B) {
	// Generate test data
	ips, err := iputils.RandomIPsFromRange("192.168.0.0/16", 10000)
	if err != nil {
		b.Fatalf("Failed to generate IPs: %v", err)
	}

	uint32IPs := make([]uint32, len(ips))
	for i, ip := range ips {
		uint32IPs[i] = iputils.IPToUint32(ip)
	}

	b.Run("OldTrieInsert", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			tr := trie.NewTrie()
			for _, ip := range ips {
				tr.Insert(ip) // net.IP -> uint32 conversion on every insert
			}
		}
	})

	b.Run("NewTrieInsertUint32", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			tr := trie.NewTrie()
			for _, v := range uint32IPs { // Direct uint32 insertion
				tr.InsertUint32(v)
			}
		}
	})

	b.Run("OldCIDRCollection", func(b *testing.B) {
		tr := trie.NewTrie()
		for _, v := range uint32IPs {
			tr.InsertUint32(v)
		}

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = tr.CollectCIDRs(10, 8, 24, 0.5) // String-based collection
		}
	})

	b.Run("NewCIDRCollection", func(b *testing.B) {
		tr := trie.NewTrie()
		for _, v := range uint32IPs {
			tr.InsertUint32(v)
		}

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			numericCIDRs := tr.CollectCIDRsNumeric(10, 8, 24, 0.5) // Numeric collection
			// Only convert to strings when needed
			result := make([]string, len(numericCIDRs))
			for j, nc := range numericCIDRs {
				result[j] = nc.String()
			}
			_ = result
		}
	})
}

// BenchmarkIPStringConversion tests IP to string conversion performance
func BenchmarkIPStringConversion(b *testing.B) {
	ip := uint32(0xC0A80001) // 192.168.0.1

	b.Run("StandardConversion", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			// Standard library approach
			netIP := iputils.Uint32ToIP(ip)
			_ = netIP.String()
		}
	})

	b.Run("OptimizedConversion", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			// Direct uint32 to string conversion
			_ = ingestor.Uint32ToIPString(ip)
		}
	})
}

// BenchmarkSliceTrieComparison compares trie implementations
func BenchmarkSliceTrieComparison(b *testing.B) {
	size := 100000
	uint32IPs, err := generateUint32IPs(size)
	if err != nil {
		b.Fatalf("Failed to generate IPs: %v", err)
	}

	b.Run("OriginalTrie", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			tr := trie.NewTrie()
			for _, v := range uint32IPs {
				tr.InsertUint32(v)
			}
		}
	})

}

// Helper function to generate uint32 IPs
func generateUint32IPs(count int) ([]uint32, error) {
	ips, err := iputils.RandomIPsFromRange("10.0.0.0/8", count)
	if err != nil {
		return nil, err
	}

	uint32IPs := make([]uint32, len(ips))
	for i, ip := range ips {
		uint32IPs[i] = iputils.IPToUint32(ip)
	}
	return uint32IPs, nil
}
