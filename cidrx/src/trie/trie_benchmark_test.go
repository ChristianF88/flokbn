package trie

import (
	"fmt"
	"net"
	"testing"

	"github.com/ChristianF88/cidrx/iputils"
)

// ============================================================================
// INSERT BENCHMARKS (from trie_insert_benchmark_test.go)
// ============================================================================

// BenchmarkInsertPerformance tests current insert performance
func BenchmarkInsertPerformance(b *testing.B) {
	sizes := []int{1000, 10000, 100000}

	for _, size := range sizes {
		// Pre-generate IPs to avoid IP generation overhead in benchmark
		ips, err := iputils.RandomIPsFromRange("10.0.0.0/8", size)
		if err != nil {
			b.Fatalf("Failed to generate IPs: %v", err)
		}

		b.Run(fmt.Sprintf("Insert_%d_IPs", size), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				trie := NewTrie()
				for _, ip := range ips {
					trie.Insert(ip)
				}
			}
		})
	}
}

// BenchmarkTrieVsSlice compares trie insertion vs slice append for same data
func BenchmarkTrieVsSlice(b *testing.B) {
	sizes := []int{1000, 10000, 100000}

	for _, size := range sizes {
		ips, _ := iputils.RandomIPsFromRange("192.168.1.0/24", size)

		b.Run(fmt.Sprintf("Trie_%d", size), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				trie := NewTrie()
				for _, ip := range ips {
					trie.Insert(ip)
				}
			}
		})

		b.Run(fmt.Sprintf("Slice_%d", size), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				slice := make([]net.IP, 0, size)
				slice = append(slice, ips...)
				_ = slice // Prevent unused variable warning
			}
		})
	}
}

// BenchmarkIPConversion tests different IP conversion strategies
func BenchmarkIPConversion(b *testing.B) {
	testIPs := []net.IP{
		net.ParseIP("192.168.1.1"),
		net.ParseIP("10.0.0.1"),
		net.ParseIP("172.16.0.1"),
		net.ParseIP("8.8.8.8"),
	}

	b.Run("IPToUint32", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			for _, ip := range testIPs {
				_ = iputils.IPToUint32(ip)
			}
		}
	})

	b.Run("DirectBytes", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			for _, ip := range testIPs {
				ip4 := ip.To4()
				if ip4 != nil {
					_ = uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])
				}
			}
		}
	})
}

// BenchmarkInsertWithPreconvertedIPs tests performance when IPs are pre-converted
func BenchmarkInsertWithPreconvertedIPs(b *testing.B) {
	sizes := []int{1000, 10000, 100000}

	for _, size := range sizes {
		ips, _ := iputils.RandomIPsFromRange("10.0.0.0/8", size)

		// Pre-convert IPs to uint32
		uint32IPs := make([]uint32, len(ips))
		for i, ip := range ips {
			uint32IPs[i] = iputils.IPToUint32(ip)
		}

		b.Run(fmt.Sprintf("PreconvertedInsert_%d", size), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				trie := NewTrie()
				for _, ip := range ips { // Still use net.IP for Insert interface
					trie.Insert(ip)
				}
			}
		})

		b.Run(fmt.Sprintf("StandardInsert_%d", size), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				trie := NewTrie()
				for _, ip := range ips {
					trie.Insert(ip)
				}
			}
		})
	}
}

// BenchmarkStandardIPConversion tests standard net.IP operations
func BenchmarkStandardIPConversion(b *testing.B) {
	testIPStrings := []string{
		"192.168.1.1",
		"10.0.0.1",
		"172.16.0.1",
		"8.8.8.8",
	}

	b.Run("ParseIP", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			for _, ipStr := range testIPStrings {
				_ = net.ParseIP(ipStr)
			}
		}
	})

	b.Run("ParseIP_To4", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			for _, ipStr := range testIPStrings {
				ip := net.ParseIP(ipStr)
				_ = ip.To4()
			}
		}
	})
}

// ============================================================================
// COLLECT BENCHMARKS (from trie_collect_benchmark_test.go)
// ============================================================================

// BenchmarkCollectCIDRs benchmarks the optimized parallel implementation (now default)
func BenchmarkCollectCIDRs(b *testing.B) {
	sizes := []int{1000, 10000, 100000, 1000000}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("size_%d", size), func(b *testing.B) {
			// Create a trie with random IPs
			trie := NewTrie()
			ips, err := iputils.RandomIPsFromRange("10.0.0.0/8", size)
			if err != nil {
				b.Fatalf("Failed to generate IPs: %v", err)
			}

			for _, ip := range ips {
				trie.Insert(ip)
			}

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				_ = trie.CollectCIDRs(10, 8, 24, 0.5)
			}
		})
	}
}

// BenchmarkCollectCIDRsSequential benchmarks the sequential numeric implementation
func BenchmarkCollectCIDRsSequential(b *testing.B) {
	sizes := []int{1000, 10000, 100000, 1000000}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("size_%d", size), func(b *testing.B) {
			trie := NewTrie()
			ips, err := iputils.RandomIPsFromRange("10.0.0.0/8", size)
			if err != nil {
				b.Fatalf("Failed to generate IPs: %v", err)
			}

			for _, ip := range ips {
				trie.Insert(ip)
			}

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				_ = trie.collectCIDRsSequentialNumeric(10, 8, 24, 500)
			}
		})
	}
}

// BenchmarkCollectCIDRsStringVsNumeric compares string vs numeric CIDR collection
func BenchmarkCollectCIDRsStringVsNumeric(b *testing.B) {
	sizes := []int{1000, 10000, 50000}

	for _, size := range sizes {
		// Create test trie
		trie := NewTrie()
		ips, err := iputils.RandomIPsFromRange("10.0.0.0/8", size)
		if err != nil {
			b.Fatalf("Failed to generate IPs: %v", err)
		}
		for _, ip := range ips {
			trie.Insert(ip)
		}

		b.Run(fmt.Sprintf("String_size_%d", size), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = trie.CollectCIDRs(10, 8, 24, 0.5)
			}
		})

		b.Run(fmt.Sprintf("Numeric_size_%d", size), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = trie.CollectCIDRsNumeric(10, 8, 24, 0.5)
			}
		})
	}
}

// ============================================================================
// COUNT-IN-RANGE BENCHMARKS (CIDRX-003 /0 guard)
// ============================================================================

// BenchmarkCountInRange confirms the /0 guard adds no measurable cost to the
// non-/0 path by comparing the /0 fast path against a representative /24 query
// on a pre-built trie of realistic size.
func BenchmarkCountInRange(b *testing.B) {
	trie := NewTrie()
	ips, err := iputils.RandomIPsFromRange("10.0.0.0/8", 100000)
	if err != nil {
		b.Fatalf("Failed to generate IPs: %v", err)
	}
	for _, ip := range ips {
		trie.Insert(ip)
	}

	_, zeroNet, _ := net.ParseCIDR("0.0.0.0/0")
	_, slash24Net, _ := net.ParseCIDR("10.0.0.0/24")

	b.Run("SlashZero", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = trie.CountInRangeIPNet(zeroNet)
		}
	})

	b.Run("Slash24", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = trie.CountInRangeIPNet(slash24Net)
		}
	})
}

// ============================================================================
// SORTED INSERTION BENCHMARKS (from sorted_insertion_benchmark_test.go)
// ============================================================================

// BenchmarkSortedInsertion compares sorted vs random insertion performance
func BenchmarkSortedInsertion(b *testing.B) {
	sizes := []int{1000, 10000, 100000}

	for _, size := range sizes {
		// Generate IPs
		ips, err := iputils.RandomIPsFromRange("10.0.0.0/8", size)
		if err != nil {
			b.Fatalf("Failed to generate IPs: %v", err)
		}

		// Create sorted version by converting to uint32, sorting, then back
		uint32IPs := make([]uint32, len(ips))
		for i, ip := range ips {
			uint32IPs[i] = iputils.IPToUint32(ip)
		}

		// Simple insertion sort for uint32 values
		for i := 1; i < len(uint32IPs); i++ {
			for j := i; j > 0 && uint32IPs[j] < uint32IPs[j-1]; j-- {
				uint32IPs[j], uint32IPs[j-1] = uint32IPs[j-1], uint32IPs[j]
			}
		}

		// Convert back to net.IP
		sortedIPs := make([]net.IP, len(uint32IPs))
		for i, ipVal := range uint32IPs {
			sortedIPs[i] = iputils.Uint32ToIP(ipVal)
		}

		b.Run(fmt.Sprintf("Random_%d", size), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				trie := NewTrie()
				for _, ip := range ips { // Original random order
					trie.Insert(ip)
				}
			}
		})

		b.Run(fmt.Sprintf("Sorted_%d", size), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				trie := NewTrie()
				for _, ip := range sortedIPs { // Sorted order
					trie.Insert(ip)
				}
			}
		})
	}
}

// ============================================================================
// HELPER FUNCTIONS (consolidated from various files)
// ============================================================================

// Non-pooled TrieNode for comparison
type TrieNodeClassic struct {
	Children [2]*TrieNodeClassic
	Count    uint32
}

type TrieClassic struct {
	Root *TrieNodeClassic
}

func NewTrieClassic() *TrieClassic {
	return &TrieClassic{Root: &TrieNodeClassic{}}
}

func (t *TrieClassic) Insert(ip net.IP) {
	node := t.Root
	val := iputils.IPToUint32(ip)
	for i := 31; i >= 0; i-- {
		bit := (val >> i) & 1
		if node.Children[bit] == nil {
			node.Children[bit] = &TrieNodeClassic{}
		}
		node = node.Children[bit]
		node.Count++
	}
}

func (t *TrieClassic) Count(ip net.IP) uint32 {
	node := t.Root
	val := iputils.IPToUint32(ip)
	for i := 31; i >= 0; i-- {
		bit := (val >> i) & 1
		if node.Children[bit] == nil {
			return 0
		}
		node = node.Children[bit]
	}
	return node.Count
}

func (t *TrieClassic) Delete(ip net.IP) {
	node := t.Root
	val := iputils.IPToUint32(ip)
	var stack []*TrieNodeClassic

	for i := 31; i >= 0; i-- {
		bit := (val >> i) & 1
		if node.Children[bit] == nil {
			return
		}
		node = node.Children[bit]
		stack = append(stack, node)
	}

	for i := len(stack) - 1; i >= 0; i-- {
		if stack[i].Count == 0 {
			return
		}
		stack[i].Count--
	}
}
