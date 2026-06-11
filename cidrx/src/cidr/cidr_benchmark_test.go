package cidr

import (
	"fmt"
	"net"
	"strconv"
	"testing"
)

// ============================================================================
// CIDR MERGING BENCHMARKS (from cidr_merge_benchmark_test.go)
// ============================================================================

// BenchmarkCIDRMerging benchmarks CIDR merging operations
func BenchmarkCIDRMerging(b *testing.B) {
	sizes := []int{100, 500, 1000, 2000, 5000}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("Merge_%d_CIDRs", size), func(b *testing.B) {
			// Generate overlapping and adjacent CIDRs for worst-case merging,
			// pre-parsed outside the timer so only MergeIPNets is measured.
			ipNets := mustParseCIDRs(b, generateOverlappingCIDRs(size))

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = MergeIPNets(ipNets)
			}
		})
	}
}

// BenchmarkRemoveContained benchmarks the removeContained function specifically
func BenchmarkRemoveContained(b *testing.B) {
	sizes := []int{100, 500, 1000, 2000, 5000}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("RemoveContained_%d_CIDRs", size), func(b *testing.B) {
			// Generate nested CIDRs for worst-case containment checking
			nets := generateNestedCIDRs(size)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = removeContained(nets)
			}
		})
	}
}

// BenchmarkMergeIPNets benchmarks the lower-level MergeIPNets function
func BenchmarkMergeIPNets(b *testing.B) {
	sizes := []int{100, 500, 1000, 2000, 5000}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("MergeIPNets_%d", size), func(b *testing.B) {
			nets := generateNestedCIDRs(size)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = MergeIPNets(nets)
			}
		})
	}
}

// ============================================================================
// USER AGENT BENCHMARKS (from cidr_useragent_benchmark_test.go)
// ============================================================================

// BenchmarkUserAgentMatcher_Creation compares creation time of new vs old implementation
func BenchmarkUserAgentMatcher_Creation(b *testing.B) {
	// Create test patterns
	whitelist := make([]string, 100)
	blacklist := make([]string, 100)

	for i := 0; i < 100; i++ {
		whitelist[i] = "Mozilla/5.0 Agent " + strconv.Itoa(i)
		blacklist[i] = "sqlmap/1." + strconv.Itoa(i)
	}

	b.Run("NewUserAgentMatcher", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			matcher := NewUserAgentMatcher(whitelist, blacklist)
			_ = matcher
		}
	})

}

// BenchmarkUserAgentMatcher_Lookup compares lookup performance
func BenchmarkUserAgentMatcher_Lookup(b *testing.B) {
	// Create test data
	whitelist := make([]string, 1000)
	blacklist := make([]string, 1000)

	for i := 0; i < 1000; i++ {
		whitelist[i] = "Mozilla/5.0 Agent " + strconv.Itoa(i)
		blacklist[i] = "sqlmap/1." + strconv.Itoa(i)
	}

	matcher := NewUserAgentMatcher(whitelist, blacklist)

	testCases := []string{
		"Mozilla/5.0 Agent 500", // Whitelisted
		"sqlmap/1.500",          // Blacklisted
		"Unknown Agent",         // Not listed
		"Mozilla/5.0 Agent 999", // Last whitelist entry
		"sqlmap/1.0",            // First blacklist entry
	}

	b.Run("ExactMatcher_CheckUserAgent", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			userAgent := testCases[i%len(testCases)]
			result := matcher.CheckUserAgent(userAgent)
			_ = result
		}
	})

}

// BenchmarkUserAgentMatcher_ScaleComparison tests performance at different scales
func BenchmarkUserAgentMatcher_ScaleComparison(b *testing.B) {
	scales := []int{10, 100, 1000, 10000}

	for _, scale := range scales {
		// Create test data
		whitelist := make([]string, scale)
		blacklist := make([]string, scale)

		for i := 0; i < scale; i++ {
			whitelist[i] = "Mozilla/5.0 Agent " + strconv.Itoa(i)
			blacklist[i] = "sqlmap/1." + strconv.Itoa(i)
		}

		matcher := NewUserAgentMatcher(whitelist, blacklist)
		testAgent := "Mozilla/5.0 Agent " + strconv.Itoa(scale/2) // Middle entry

		b.Run(fmt.Sprintf("ExactMatcher_Scale_%d", scale), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				result := matcher.CheckUserAgent(testAgent)
				_ = result
			}
		})

	}
}

// BenchmarkUserAgentMatcher_CaseInsensitive tests case-insensitive performance
func BenchmarkUserAgentMatcher_CaseInsensitive(b *testing.B) {
	whitelist := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		"Googlebot/2.1 (+http://www.google.com/bot.html)",
		"facebookexternalhit/1.1",
	}

	blacklist := []string{
		"sqlmap/1.0",
		"nmap scripting engine",
		"Nikto/2.1.6",
	}

	matcher := NewUserAgentMatcher(whitelist, blacklist)

	testCases := []string{
		"mozilla/5.0 (windows nt 10.0; win64; x64) applewebkit/537.36", // lowercase
		"GOOGLEBOT/2.1 (+HTTP://WWW.GOOGLE.COM/BOT.HTML)",              // uppercase
		"FaCeBoOkExTeRnAlHiT/1.1",                                      // mixed case
		"SQLMAP/1.0",                                                   // uppercase blacklist
		"nmap scripting engine",                                        // exact case
		"NIKTO/2.1.6",                                                  // uppercase blacklist
	}

	b.Run("CaseInsensitive_Lookup", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			userAgent := testCases[i%len(testCases)]
			result := matcher.CheckUserAgent(userAgent)
			_ = result
		}
	})
}

// BenchmarkUserAgentMatcher_Memory tests memory efficiency
func BenchmarkUserAgentMatcher_Memory(b *testing.B) {
	// Test with various sizes to measure memory allocation
	sizes := []int{100, 1000, 10000}

	for _, size := range sizes {
		whitelist := make([]string, size)
		blacklist := make([]string, size)

		for i := 0; i < size; i++ {
			whitelist[i] = "Mozilla/5.0 Agent " + strconv.Itoa(i)
			blacklist[i] = "sqlmap/1." + strconv.Itoa(i)
		}

		b.Run(fmt.Sprintf("Memory_Size_%d", size), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				matcher := NewUserAgentMatcher(whitelist, blacklist)

				// Perform some lookups to test runtime allocation
				_ = matcher.CheckUserAgent("Mozilla/5.0 Agent 50")
				_ = matcher.CheckUserAgent("sqlmap/1.50")
				_ = matcher.CheckUserAgent("Unknown Agent")
			}
		})
	}
}

// BenchmarkUserAgentMatcher_ConcurrentAccess tests concurrent performance
func BenchmarkUserAgentMatcher_ConcurrentAccess(b *testing.B) {
	whitelist := make([]string, 1000)
	blacklist := make([]string, 1000)

	for i := 0; i < 1000; i++ {
		whitelist[i] = "Mozilla/5.0 Agent " + strconv.Itoa(i)
		blacklist[i] = "sqlmap/1." + strconv.Itoa(i)
	}

	matcher := NewUserAgentMatcher(whitelist, blacklist)

	testCases := []string{
		"Mozilla/5.0 Agent 100",
		"sqlmap/1.200",
		"Unknown Agent",
		"Mozilla/5.0 Agent 500",
		"sqlmap/1.800",
	}

	b.Run("Sequential_Access", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			userAgent := testCases[i%len(testCases)]
			result := matcher.CheckUserAgent(userAgent)
			_ = result
		}
	})

	b.Run("Concurrent_Access", func(b *testing.B) {
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				userAgent := testCases[i%len(testCases)]
				result := matcher.CheckUserAgent(userAgent)
				_ = result
				i++
			}
		})
	})
}

// BenchmarkUserAgentMatcher_RealWorldPatterns tests with realistic patterns
func BenchmarkUserAgentMatcher_RealWorldPatterns(b *testing.B) {
	// Realistic User-Agent patterns
	whitelist := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
		"facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
		"Twitterbot/1.0",
	}

	blacklist := []string{
		"sqlmap/1.0",
		"Nmap NSE scanner",
		"Nikto/2.1.6",
		"curl/7.68.0",
		"nuclei/2.0",
	}

	matcher := NewUserAgentMatcher(whitelist, blacklist)

	// Mix of real-world test cases
	testCases := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		"sqlmap/1.0",
		"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
		"Nmap NSE scanner",
		"Unknown Bot/1.0",
	}

	b.Run("RealWorld_Patterns", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			userAgent := testCases[i%len(testCases)]
			result := matcher.CheckUserAgent(userAgent)
			_ = result
		}
	})

}

// BenchmarkUserAgentMatcher_StringOperations tests string operation overhead
func BenchmarkUserAgentMatcher_StringOperations(b *testing.B) {
	matcher := NewUserAgentMatcher(
		[]string{"Mozilla/5.0 Test Agent"},
		[]string{"sqlmap/1.0"},
	)

	testAgent := "Mozilla/5.0 Test Agent"

	b.Run("Direct_Lookup", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			result := matcher.CheckUserAgent(testAgent)
			_ = result
		}
	})

	b.Run("With_Case_Conversion", func(b *testing.B) {
		testAgentUpper := "MOZILLA/5.0 TEST AGENT"
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			result := matcher.CheckUserAgent(testAgentUpper)
			_ = result
		}
	})

	b.Run("Raw_Map_Lookup", func(b *testing.B) {
		// Direct map access for comparison
		key := "mozilla/5.0 test agent"
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, exists := matcher.userAgents[key]
			_ = exists
		}
	})
}

// ============================================================================
// HELPER FUNCTIONS (consolidated from both files)
// ============================================================================

// generateOverlappingCIDRs creates overlapping and adjacent CIDRs for testing merging
func generateOverlappingCIDRs(count int) []string {
	cidrs := make([]string, 0, count)

	// Create overlapping /24 networks that can be merged
	for i := 0; i < count; i++ {
		// Create adjacent /24 networks that should merge into larger blocks
		base := 10*256*256 + (i/2)*256
		cidr := fmt.Sprintf("%d.%d.%d.0/24",
			(base>>16)&0xFF, (base>>8)&0xFF, base&0xFF)
		cidrs = append(cidrs, cidr)
	}

	return cidrs
}

// generateNestedCIDRs creates nested CIDRs for testing containment removal
func generateNestedCIDRs(count int) []*net.IPNet {
	nets := make([]*net.IPNet, 0, count)

	// Create nested networks: /16, /17, /18, /19, etc.
	for i := 0; i < count; i++ {
		prefixLen := 16 + (i % 16) // Range from /16 to /31
		base := 10*256*256 + (i/100)*256*256
		cidr := fmt.Sprintf("%d.%d.%d.0/%d",
			(base>>16)&0xFF, (base>>8)&0xFF, base&0xFF, prefixLen)

		_, net, err := net.ParseCIDR(cidr)
		if err == nil {
			nets = append(nets, net)
		}
	}

	return nets
}

// BenchmarkNumericCIDR_String benchmarks the NumericCIDR.String() method
func BenchmarkNumericCIDR_String(b *testing.B) {
	testCases := []NumericCIDR{
		{IP: 0x0A000000, PrefixLen: 8},  // 10.0.0.0/8
		{IP: 0xC0A80100, PrefixLen: 24}, // 192.168.1.0/24
		{IP: 0xFFFFFFFF, PrefixLen: 32}, // 255.255.255.255/32
		{IP: 0x01020304, PrefixLen: 16}, // 1.2.3.4/16
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		nc := testCases[i%len(testCases)]
		s := nc.String()
		_ = s
	}
}

// BenchmarkComposeBanLists measures the publish choke point (cold path: runs
// once per static run / live iteration) with a realistic mix of full drops,
// partial subtractions and untouched entries.
func BenchmarkComposeBanLists(b *testing.B) {
	activeBans := make([]string, 0, 200)
	for i := 0; i < 200; i++ {
		activeBans = append(activeBans, fmt.Sprintf("10.%d.%d.0/24", i/256, i%256))
	}
	manualBlacklist := []string{"203.0.113.0/24", "198.51.100.0/24", "192.0.2.0/24"}
	whitelist := []string{
		"10.0.5.0/24",    // full drop of one active ban
		"10.0.10.0/25",   // subtraction inside an active ban
		"203.0.113.0/26", // subtraction inside the manual blacklist
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ComposeBanLists(activeBans, manualBlacklist, whitelist)
	}
}
