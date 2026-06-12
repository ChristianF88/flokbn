package trie

import (
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/ChristianF88/cidrx/iputils"
	"github.com/ChristianF88/cidrx/logparser"
	"github.com/ChristianF88/cidrx/testutil"
)

func TestTrieGetCount(t *testing.T) {
	tests := []struct {
		name          string
		insertIPs     []string
		queryIP       string
		expectedCount uint32
	}{
		{
			name:          "Get count for single inserted IP",
			insertIPs:     []string{"192.168.1.1"},
			queryIP:       "192.168.1.1",
			expectedCount: 1,
		},
		{
			name:          "Get count for duplicate IPs",
			insertIPs:     []string{"192.168.1.1", "192.168.1.1"},
			queryIP:       "192.168.1.1",
			expectedCount: 2,
		},
		{
			name:          "Get count for non-existent IP",
			insertIPs:     []string{"192.168.1.1"},
			queryIP:       "192.168.1.2",
			expectedCount: 0,
		},
		{
			name:          "Get count for one of multiple IPs",
			insertIPs:     []string{"192.168.1.1", "192.168.1.2"},
			queryIP:       "192.168.1.2",
			expectedCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Initialize a new Trie
			trie := NewTrie()

			// Insert IPs into the Trie
			for _, ipStr := range tt.insertIPs {
				ip := net.ParseIP(ipStr)
				if ip == nil {
					t.Fatalf("Failed to parse IP: %s", ipStr)
				}
				trie.Insert(ip)
			}

			// Query the count for the specified IP
			queryIP := net.ParseIP(tt.queryIP)
			if queryIP == nil {
				t.Fatalf("Failed to parse IP: %s", tt.queryIP)
			}
			count := trie.Count(queryIP)

			// Verify the count
			if count != tt.expectedCount {
				t.Errorf("For IP %s, expected count %d, got %d", tt.queryIP, tt.expectedCount, count)
			}
		})
	}
}

func TestTrieGetCountAll(t *testing.T) {
	tests := []struct {
		name          string
		insertIPs     []string
		expectedCount uint32
	}{
		{
			name:          "No IPs inserted",
			insertIPs:     []string{},
			expectedCount: 0,
		},
		{
			name:          "Single IP inserted",
			insertIPs:     []string{"192.168.1.1"},
			expectedCount: 1,
		},
		{
			name:          "Duplicate IPs inserted",
			insertIPs:     []string{"192.168.1.1", "192.168.1.1"},
			expectedCount: 2,
		},
		{
			name:          "Multiple different IPs inserted",
			insertIPs:     []string{"192.168.1.1", "192.168.1.2", "192.168.1.3"},
			expectedCount: 3,
		},
		{
			name:          "Mixed duplicate and unique IPs",
			insertIPs:     []string{"192.168.1.1", "192.168.1.2", "192.168.1.1", "192.168.1.3"},
			expectedCount: 4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Initialize a new Trie
			trie := NewTrie()

			// Insert IPs into the Trie
			for _, ipStr := range tt.insertIPs {
				ip := net.ParseIP(ipStr)
				if ip == nil {
					t.Fatalf("Failed to parse IP: %s", ipStr)
				}
				trie.Insert(ip)
			}

			// Get the total count of all IPs
			count := trie.CountAll()

			// Verify the total count
			if count != tt.expectedCount {
				t.Errorf("Expected total count %d, got %d", tt.expectedCount, count)
			}
		})
	}
}

func TestTrieInsert(t *testing.T) {
	tests := []struct {
		name     string
		ips      []string
		expected map[string]uint32
	}{
		{
			name:     "Insert single IP",
			ips:      []string{"192.168.1.1"},
			expected: map[string]uint32{"192.168.1.1": 1},
		},
		{
			name:     "Insert duplicate IP",
			ips:      []string{"192.168.1.1", "192.168.1.1"},
			expected: map[string]uint32{"192.168.1.1": 2},
		},
		{
			name:     "Insert multiple different IPs",
			ips:      []string{"192.168.1.1", "192.168.1.2"},
			expected: map[string]uint32{"192.168.1.1": 1, "192.168.1.2": 1},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			trie := NewTrie()

			// Insert all IPs into the Trie
			for _, ipStr := range tt.ips {
				ip := net.ParseIP(ipStr)
				if ip == nil {
					t.Fatalf("Failed to parse IP: %s", ipStr)
				}
				trie.Insert(ip)
			}

			// Verify the counts for each IP using GetCount
			for ipStr, expectedCount := range tt.expected {
				ip := net.ParseIP(ipStr)
				if ip == nil {
					t.Fatalf("Failed to parse IP: %s", ipStr)
				}

				count := trie.Count(ip)
				if count != expectedCount {
					t.Errorf("For IP %s, expected count %d, got %d", ipStr, expectedCount, count)
				}
			}
		})
	}
}

func TestTrieInsertLargeScale(t *testing.T) {
	tests := []struct {
		name     string
		ips      []string
		expedted uint32
	}{
		{
			name: "Insert large number of IPs",
			ips: func() []string {
				ips, err := iputils.RandomIPsFromRange("192.12.1.0/24", 1000000)
				if err != nil {
					t.Fatalf("Failed to generate random IPs: %v", err)
				}
				var ipStrings []string
				for _, ip := range ips {
					ipStrings = append(ipStrings, ip.String())
				}
				return ipStrings
			}(),
			expedted: 1000000,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			trie := NewTrie()

			// Insert all IPs into the Trie
			for _, ipStr := range tt.ips {
				ip := net.ParseIP(ipStr)
				if ip == nil {
					t.Fatalf("Failed to parse IP: %s", ipStr)
				}
				trie.Insert(ip)
			}

			// Verify the total count of all IPs
			count := trie.CountAll()
			if count != tt.expedted {
				t.Errorf("Expected total count %d, got %d", tt.expedted, count)
			}
		})
	}
}

func TestTrieDelete(t *testing.T) {
	tests := []struct {
		name               string
		insertIPs          []string
		deleteIP           string
		expectedCount      uint32
		expectedTotalCount uint32
	}{
		{
			name:               "Delete single IP",
			insertIPs:          []string{"192.168.1.1"},
			deleteIP:           "192.168.1.1",
			expectedCount:      0,
			expectedTotalCount: 0,
		},
		{
			name:               "Delete non-existent IP",
			insertIPs:          []string{"192.168.1.1"},
			deleteIP:           "192.168.1.2",
			expectedCount:      0,
			expectedTotalCount: 1,
		},
		{
			name:               "Delete one of multiple IPs",
			insertIPs:          []string{"192.168.1.1", "192.168.1.2"},
			deleteIP:           "192.168.1.1",
			expectedCount:      0,
			expectedTotalCount: 1,
		},
		{
			name:               "Delete tripet IP",
			insertIPs:          []string{"192.168.1.1", "192.168.1.1", "192.168.1.1", "192.168.1.2"},
			deleteIP:           "192.168.1.1",
			expectedCount:      2,
			expectedTotalCount: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Initialize a new Trie
			trie := NewTrie()

			// Insert IPs into the Trie
			for _, ipStr := range tt.insertIPs {
				ip := net.ParseIP(ipStr)
				if ip == nil {
					t.Fatalf("Failed to parse IP: %s", ipStr)
				}
				trie.Insert(ip)
			}

			// Delete the specified IP
			deleteIP := net.ParseIP(tt.deleteIP)
			if deleteIP == nil {
				t.Fatalf("Failed to parse IP: %s", tt.deleteIP)
			}
			trie.Delete(deleteIP)

			// Verify the count of the deleted IP

			ipCount := trie.Count(deleteIP)
			if ipCount != tt.expectedCount {
				t.Errorf("Expected count %d, got %d", tt.expectedCount, ipCount)
			}
			ipTotalCount := trie.CountAll()
			if ipTotalCount != tt.expectedTotalCount {
				t.Errorf("Expected total count %d, got %d", tt.expectedTotalCount, ipTotalCount)
			}
		})
	}
}

func TestTrieDeleteLargeScale(t *testing.T) {
	tests := []struct {
		name     string
		ips      []string
		expected int
	}{
		{
			name: "Delete large number of IPs",
			ips: func() []string {
				ips, err := iputils.RandomIPsFromRange("192.12.1.0/24", 100000)
				if err != nil {
					t.Fatalf("Failed to generate random IPs: %v", err)
				}
				var ipStrings []string
				for _, ip := range ips {
					ipStrings = append(ipStrings, ip.String())
				}
				return ipStrings
			}(),
			expected: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Initialize a new Trie
			trie := NewTrie()

			// Insert IPs into the Trie
			for _, ipStr := range tt.ips {
				ip := net.ParseIP(ipStr)
				if ip == nil {
					t.Fatalf("Failed to parse IP: %s", ipStr)
				}
				trie.Insert(ip)
			}

			// Delete the specified IP
			for _, ipStr := range tt.ips {
				ip := net.ParseIP(ipStr)
				if ip == nil {
					t.Fatalf("Failed to parse IP: %s", ipStr)
				}
				trie.Delete(ip)
			}

			// Verify the total count of all IPs
			count := trie.CountAll()
			if count != 0 {
				t.Errorf("Expected total count %d, got %d", 0, count)
			}
		})
	}
}

func TestTrieCollectCIDRs(t *testing.T) {
	tests := []struct {
		name                 string
		insertIPs            []string
		minClusterSize       uint32
		minDepth             uint32
		maxDepth             uint32
		meanSubnetDifference float64
		expectedCIDRs        []string
	}{
		{
			name:                 "Single IP, include leaves",
			insertIPs:            []string{"192.168.1.1"},
			minClusterSize:       1,
			minDepth:             16,
			maxDepth:             31,
			meanSubnetDifference: 0.1,
			expectedCIDRs:        []string{"192.168.1.0/31"},
		},
		{
			name:                 "Multiple IPs forming a /31 cluster",
			insertIPs:            []string{"192.168.1.0", "192.168.1.1"},
			minClusterSize:       2,
			minDepth:             24,
			maxDepth:             31,
			meanSubnetDifference: 0.1,
			expectedCIDRs:        []string{"192.168.1.0/31"},
		},
		{
			name:                 "Cluster with mixed depths",
			insertIPs:            []string{"192.168.1.0", "192.168.1.1", "192.168.1.2", "192.168.1.3"},
			minClusterSize:       4,
			minDepth:             24,
			maxDepth:             30,
			meanSubnetDifference: 0.1,
			expectedCIDRs:        []string{"192.168.1.0/30"},
		},
		{
			name:                 "No clusters due to minClusterSize",
			insertIPs:            []string{"192.168.1.0", "192.168.1.1"},
			minClusterSize:       3,
			minDepth:             16,
			maxDepth:             32,
			meanSubnetDifference: 0.1,
			expectedCIDRs:        []string{},
		},
		{
			name:                 "No clusters due to minClusterSize",
			insertIPs:            []string{"192.168.1.1", "192.168.1.1", "192.168.1.1"},
			minClusterSize:       3,
			minDepth:             16,
			maxDepth:             32,
			meanSubnetDifference: 0.1,
			expectedCIDRs:        []string{"192.168.1.1/32"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Initialize a new Trie
			trie := NewTrie()

			// Insert IPs into the Trie
			for _, ipStr := range tt.insertIPs {
				ip := net.ParseIP(ipStr)
				if ip == nil {
					t.Fatalf("Failed to parse IP: %s", ipStr)
				}
				trie.Insert(ip)
			}

			// Collect CIDRs
			cidrs := trie.CollectCIDRs(tt.minClusterSize, tt.minDepth, tt.maxDepth, tt.meanSubnetDifference)

			// Verify the collected CIDRs
			if len(cidrs) != len(tt.expectedCIDRs) {
				t.Errorf("Expected CIDRs %v, got %v", tt.expectedCIDRs, cidrs)
			}

			for _, expectedCIDR := range tt.expectedCIDRs {
				found := false
				for _, cidr := range cidrs {
					if cidr == expectedCIDR {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected CIDR %s not found in result %v", expectedCIDR, cidrs)
				}
			}
		})
	}
}
func TestTrieCollectCIDRsLargeScale(t *testing.T) {
	// Generate a realistic set of IPs using helper functions
	ips := append(
		func() []string {
			ips, err := iputils.RandomIPsFromRange("12.10.30.0/24", 40000)
			if err != nil {
				t.Fatalf("Failed to generate random IPs: %v", err)
			}
			var ipStrings []string
			for _, ip := range ips {
				ipStrings = append(ipStrings, ip.String())
			}
			return ipStrings
		}(), // Cluster /30
		func() []string {
			ips, err := iputils.RandomIPsFromRange("192.168.1.0/24", 10000) // Cluster /29
			if err != nil {
				t.Fatalf("Failed to generate random IPs: %v", err)
			}
			var ipStrings []string
			for _, ip := range ips {
				ipStrings = append(ipStrings, ip.String())
			}
			return ipStrings
		}()...,
	)

	// Add outliers
	ips = append(ips, "8.8.8.8", "1.1.1.1")

	expectedCIDRs := []string{
		"12.10.30.0/24",
		"192.168.1.0/24",
	}

	trie := NewTrie()

	// Insert IPs into the Trie
	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			t.Fatalf("Failed to parse IP: %s", ipStr)
		}
		trie.Insert(ip)
	}

	// Collect CIDRs
	cidrs := trie.CollectCIDRs(4, 16, 30, 0.5)

	// Verify the collected CIDRs via iteration and checking if the found cidr ranges are subnets of the expected CIDRs
	for _, expectedCIDR := range expectedCIDRs {
		_, expectedNet, err := net.ParseCIDR(expectedCIDR)
		if err != nil {
			t.Fatalf("Failed to parse expected CIDR: %s", expectedCIDR)
		}

		found := false
		for _, cidr := range cidrs {
			_, foundNet, err := net.ParseCIDR(cidr)
			if err != nil {
				t.Fatalf("Failed to parse found CIDR: %s", cidr)
			}
			if expectedNet.Contains(foundNet.IP) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected CIDR %s not found in result %v", expectedCIDR, cidrs)
		}
	}
	fmt.Printf("Collected CIDRs: %v\n", cidrs)
	fmt.Printf("Expected CIDRs: %v\n", expectedCIDRs)
}

func TestCollectCIDRs(t *testing.T) {
	tests := []struct {
		name           string
		insertIPs      []string
		minClusterSize uint32
		minDepth       uint32
		maxDepth       uint32
		threshold      float64
		expectedCIDRs  []string
	}{
		{
			name:           "Single IP, include leaves",
			insertIPs:      []string{"192.168.1.1"},
			minClusterSize: 1,
			minDepth:       16,
			maxDepth:       31,
			threshold:      1.0,
			expectedCIDRs:  []string{"192.168.1.0/31"},
		},
		{
			name:           "Multiple IPs forming a /30 cluster",
			insertIPs:      []string{"192.168.1.0", "192.168.1.1", "192.168.1.2", "192.168.1.3"},
			minClusterSize: 4,
			minDepth:       24,
			maxDepth:       30,
			threshold:      1.0,
			expectedCIDRs:  []string{"192.168.1.0/30"},
		},
		{
			name:           "No clusters due to minClusterSize",
			insertIPs:      []string{"192.168.1.0", "192.168.1.1"},
			minClusterSize: 3,
			minDepth:       16,
			maxDepth:       32,
			threshold:      1.0,
			expectedCIDRs:  []string{},
		},
		{
			name:           "Cluster with mixed depths",
			insertIPs:      []string{"192.168.1.0", "192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4"},
			minClusterSize: 5,
			minDepth:       24,
			maxDepth:       30,
			threshold:      2.0,
			expectedCIDRs:  []string{"192.168.1.0/29"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			trie := NewTrie()

			for _, ipStr := range tt.insertIPs {
				ip := net.ParseIP(ipStr)
				if ip == nil {
					t.Fatalf("Failed to parse IP: %s", ipStr)
				}
				trie.Insert(ip)
			}

			results := trie.CollectCIDRs(tt.minClusterSize, tt.minDepth, tt.maxDepth, tt.threshold)

			if len(results) != len(tt.expectedCIDRs) {
				t.Errorf("Expected CIDRs %v, got %v", tt.expectedCIDRs, results)
			}

			for _, expectedCIDR := range tt.expectedCIDRs {
				found := false
				for _, cidr := range results {
					if cidr == expectedCIDR {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected CIDR %s not found in result %v", expectedCIDR, results)
				}
			}
		})
	}
}

// TestCollectCIDRsThresholdBoundaries pins the exact semantics of the
// meanSubnetDifference -> uint32 threshold conversion and the integer
// cross-multiplication test in collectCIDRsNode:
// appendCluster = (2000*diff) < (threshold*count), strict less-than.
func TestCollectCIDRsThresholdBoundaries(t *testing.T) {
	// insertIPs maps dotted IP -> insert count.
	tests := []struct {
		name           string
		insertIPs      map[string]int
		minClusterSize uint32
		minDepth       uint32
		maxDepth       uint32
		threshold      float64
		expectedCIDRs  []string
	}{
		{
			// threshold=0: unequal child counts never cluster (2000*diff < 0 is
			// false); only the dominant /32 leaf is emitted at maxDepth.
			name:           "threshold_zero_unequal",
			insertIPs:      map[string]int{"192.168.1.0": 2, "192.168.1.1": 1},
			minClusterSize: 2,
			minDepth:       24,
			maxDepth:       32,
			threshold:      0.0,
			expectedCIDRs:  []string{"192.168.1.0/32"},
		},
		{
			// Equal-count fast path (trie.go:366) bypasses the threshold
			// comparison entirely, so even threshold=0 clusters the /31.
			// Pinned intentionally.
			name:           "threshold_zero_equal_counts",
			insertIPs:      map[string]int{"192.168.1.0": 2, "192.168.1.1": 2},
			minClusterSize: 4,
			minDepth:       24,
			maxDepth:       32,
			threshold:      0.0,
			expectedCIDRs:  []string{"192.168.1.0/31"},
		},
		{
			// Exact boundary is excluded: diff=2, count=4, msd=1.0 ->
			// 2000*2=4000 < 1000*4=4000 is false (strict <), so no /31; the
			// count-3 leaf is emitted at maxDepth instead.
			name:           "threshold_exact_boundary_excluded",
			insertIPs:      map[string]int{"192.168.1.0": 3, "192.168.1.1": 1},
			minClusterSize: 3,
			minDepth:       24,
			maxDepth:       32,
			threshold:      1.0,
			expectedCIDRs:  []string{"192.168.1.0/32"},
		},
		{
			// Just below the boundary clusters: diff=1, count=5, msd=1.0 ->
			// 2000*1=2000 < 1000*5=5000 -> /31 emitted.
			name:           "threshold_just_below_clusters",
			insertIPs:      map[string]int{"192.168.1.0": 3, "192.168.1.1": 2},
			minClusterSize: 5,
			minDepth:       24,
			maxDepth:       32,
			threshold:      1.0,
			expectedCIDRs:  []string{"192.168.1.0/31"},
		},
		{
			// Huge threshold makes any imbalance cluster at the shallowest
			// allowed depth: the depth-1 node (0.0.0.0/1, count 3) with
			// children 2 vs 1 passes 2000*1 < 1e9*3 and is emitted as
			// 0.0.0.0/1. Note 0.0.0.0/0 itself is unreachable here: Insert
			// never increments Root.Count (left at 0 by design, see
			// BuildSorted docs), so the depth-0 emission check
			// node.Count >= minClusterSize can never pass for mcs > 0.
			name:           "threshold_huge",
			insertIPs:      map[string]int{"0.0.0.1": 2, "64.0.0.1": 1},
			minClusterSize: 3,
			minDepth:       0,
			maxDepth:       32,
			threshold:      1e6,
			expectedCIDRs:  []string{"0.0.0.0/1"},
		},
		{
			// Negative meanSubnetDifference is clamped to 0 before the
			// float->uint32 conversion (implementation-defined for negative
			// inputs), so this must behave exactly like threshold_zero_unequal.
			name:           "threshold_negative_clamped",
			insertIPs:      map[string]int{"192.168.1.0": 2, "192.168.1.1": 1},
			minClusterSize: 2,
			minDepth:       24,
			maxDepth:       32,
			threshold:      -1.0,
			expectedCIDRs:  []string{"192.168.1.0/32"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			trie := NewTrie()

			for ipStr, n := range tt.insertIPs {
				ip := net.ParseIP(ipStr)
				if ip == nil {
					t.Fatalf("Failed to parse IP: %s", ipStr)
				}
				for i := 0; i < n; i++ {
					trie.Insert(ip)
				}
			}

			results := trie.CollectCIDRs(tt.minClusterSize, tt.minDepth, tt.maxDepth, tt.threshold)

			if len(results) != len(tt.expectedCIDRs) {
				t.Errorf("Expected CIDRs %v, got %v", tt.expectedCIDRs, results)
			}

			for _, expectedCIDR := range tt.expectedCIDRs {
				found := false
				for _, cidr := range results {
					if cidr == expectedCIDR {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected CIDR %s not found in result %v", expectedCIDR, results)
				}
			}
		})
	}
}

func TestTrieCountInRangeCIDR(t *testing.T) {
	tests := []struct {
		name      string
		insertIPs []string
		cidr      string
		expected  uint32
		wantErr   bool
	}{
		{
			name:      "Empty trie returns 0",
			insertIPs: []string{},
			cidr:      "192.168.1.0/24",
			expected:  0,
			wantErr:   false,
		},
		{
			name:      "Single IP in CIDR",
			insertIPs: []string{"192.168.1.1"},
			cidr:      "192.168.1.0/24",
			expected:  1,
			wantErr:   false,
		},
		{
			name:      "Multiple IPs in CIDR",
			insertIPs: []string{"192.168.1.1", "192.168.1.2", "192.168.1.3"},
			cidr:      "192.168.1.0/24",
			expected:  3,
			wantErr:   false,
		},
		{
			name:      "IPs outside CIDR",
			insertIPs: []string{"10.0.0.1", "10.0.0.2"},
			cidr:      "192.168.1.0/24",
			expected:  0,
			wantErr:   false,
		},
		{
			name:      "Duplicate IPs in CIDR",
			insertIPs: []string{"192.168.1.1", "192.168.1.1", "192.168.1.2"},
			cidr:      "192.168.1.0/24",
			expected:  3,
			wantErr:   false,
		},
		{
			name: "Full /24 CIDR",
			insertIPs: func() []string {
				var ips []string
				for i := 0; i < 256; i++ {
					ips = append(ips, fmt.Sprintf("192.168.2.%d", i))
				}
				return ips
			}(),
			cidr:     "192.168.2.0/24",
			expected: 256,
			wantErr:  false,
		},
		{
			name:      "Partial overlap with CIDR",
			insertIPs: []string{"192.168.2.1", "192.168.2.2", "192.168.3.1"},
			cidr:      "192.168.2.0/24",
			expected:  2,
			wantErr:   false,
		},
		{
			name:      "Invalid CIDR format",
			insertIPs: []string{"192.168.1.1"},
			cidr:      "192.168.1.0/33",
			expected:  0,
			wantErr:   true,
		},
		{
			name:      "Single IP /32 CIDR",
			insertIPs: []string{"10.0.0.1"},
			cidr:      "10.0.0.1/32",
			expected:  1,
			wantErr:   false,
		},
		{
			name:      "No IPs in /32 CIDR",
			insertIPs: []string{"10.0.0.2"},
			cidr:      "10.0.0.1/32",
			expected:  0,
			wantErr:   false,
		},
		{
			name: "Large CIDR /16 with sparse insertions",
			insertIPs: []string{
				"192.168.0.1", "192.168.1.1", "192.168.255.254",
			},
			cidr:     "192.168.0.0/16",
			expected: 3,
			wantErr:  false,
		},
		{
			name: "All zeros and broadcast IPs",
			insertIPs: []string{
				"192.168.0.0", "192.168.0.255", // .0 and .255
			},
			cidr:     "192.168.0.0/24",
			expected: 2,
			wantErr:  false,
		},
		{
			name: "Multiple subnets inside a supernet CIDR",
			insertIPs: []string{
				"10.10.1.1", "10.10.2.1", "10.10.3.1",
			},
			cidr:     "10.10.0.0/16",
			expected: 3,
			wantErr:  false,
		},
		{
			name: "Boundary IPs in CIDR range",
			insertIPs: []string{
				"172.16.5.0", "172.16.5.255",
			},
			cidr:     "172.16.5.0/24",
			expected: 2,
			wantErr:  false,
		},
		{
			name: "High duplication inside CIDR",
			insertIPs: func() []string {
				var ips []string
				for i := 0; i < 100; i++ {
					ips = append(ips, "192.0.2.5")
				}
				return ips
			}(),
			cidr:     "192.0.2.0/24",
			expected: 100,
			wantErr:  false,
		},
		{
			name: "Sparse insertion across multiple classes",
			insertIPs: []string{
				"10.0.0.1",    // Class A
				"172.16.0.1",  // Class B
				"192.168.0.1", // Class C
				"224.0.0.1",   // Class D (multicast)
			},
			cidr:     "10.0.0.0/8",
			expected: 1,
			wantErr:  false,
		},
		{
			name: "Overlap at /23 boundary",
			insertIPs: []string{
				"192.168.2.255", "192.168.3.0",
			},
			cidr:     "192.168.2.0/23", // covers .2.0 to .3.255
			expected: 2,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			trie := NewTrie()
			for _, ipStr := range tt.insertIPs {
				ip := net.ParseIP(ipStr)
				if ip == nil {
					t.Fatalf("Failed to parse IP: %s", ipStr)
				}
				trie.Insert(ip)
			}
			got, err := trie.CountInRange(tt.cidr)
			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error for CIDR %q, got none", tt.cidr)
				}
				return
			}
			if err != nil {
				t.Errorf("Unexpected error for CIDR %q: %v", tt.cidr, err)
				return
			}
			if got != tt.expected {
				t.Errorf("CountInRange(%q) = %d, want %d", tt.cidr, got, tt.expected)
			}
		})
	}
}

// TestCountInRangeExtensive tests CountInRange with comprehensive edge cases to ensure correctness
func TestCountInRangeExtensive(t *testing.T) {
	tests := []struct {
		name     string
		setupIPs func() []string
		cidr     string
		expected uint32
	}{
		{
			name: "Adjacent ranges boundary test",
			setupIPs: func() []string {
				return []string{
					"192.168.1.255", // Last IP of 192.168.1.0/24
					"192.168.2.0",   // First IP of 192.168.2.0/24
					"192.168.2.1",   // Second IP of 192.168.2.0/24
				}
			},
			cidr:     "192.168.2.0/24",
			expected: 2, // Should only count 192.168.2.0 and 192.168.2.1
		},
		{
			name: "Large range with sparse data",
			setupIPs: func() []string {
				return []string{
					"10.0.0.1",     // In range 10.0.0.0/16
					"10.0.255.254", // In range 10.0.0.0/16
					"10.0.128.50",  // In range 10.0.0.0/16
					"10.1.128.50",  // Outside range (in 10.1.0.0/16)
					"192.168.1.1",  // Outside range
				}
			},
			cidr:     "10.0.0.0/16",
			expected: 3, // Should count first 3 IPs only
		},
		{
			name: "Subnet edge boundaries",
			setupIPs: func() []string {
				return []string{
					"172.16.0.0",   // Network address
					"172.16.0.255", // Broadcast of /24
					"172.16.1.0",   // Network of next /24
					"172.16.1.255", // Broadcast of next /24
				}
			},
			cidr:     "172.16.0.0/23", // Should include both /24s
			expected: 4,               // All 4 IPs
		},
		{
			name: "Single IP /32 edge case",
			setupIPs: func() []string {
				return []string{
					"203.0.113.42",
					"203.0.113.43",
				}
			},
			cidr:     "203.0.113.42/32",
			expected: 1, // Only exact match
		},
		{
			name: "Very large /8 network with sparse data",
			setupIPs: func() []string {
				ips := []string{
					"10.0.0.1",
					"10.255.255.254",
					"11.0.0.1", // Outside range
				}
				// Add some random IPs in the 10.0.0.0/8 range
				for i := 1; i <= 5; i++ {
					ips = append(ips, fmt.Sprintf("10.%d.%d.%d", i, i*2, i*3))
				}
				return ips
			},
			cidr:     "10.0.0.0/8",
			expected: 7, // 2 + 5 IPs in range
		},
		{
			name: "Cross-boundary test /23",
			setupIPs: func() []string {
				var ips []string
				// Add IPs from 192.168.0.x
				for i := 250; i <= 255; i++ {
					ips = append(ips, fmt.Sprintf("192.168.0.%d", i))
				}
				// Add IPs from 192.168.1.x
				for i := 0; i <= 5; i++ {
					ips = append(ips, fmt.Sprintf("192.168.1.%d", i))
				}
				// Add IP outside range
				ips = append(ips, "192.168.2.1")
				return ips
			},
			cidr:     "192.168.0.0/23", // Includes both .0 and .1 subnets
			expected: 12,               // 6 + 6 IPs in range
		},
		{
			name: "Bit boundary stress test",
			setupIPs: func() []string {
				return []string{
					"128.0.0.1",       // First half of internet
					"127.255.255.255", // Just before
					"128.0.0.0",       // Exactly at boundary
					"255.255.255.255", // End of range
				}
			},
			cidr:     "128.0.0.0/1", // Second half of all IPv4 space
			expected: 3,             // All except 127.255.255.255
		},
		{
			name: "Duplicate IPs in range counting",
			setupIPs: func() []string {
				var ips []string
				// Add same IP multiple times
				for i := 0; i < 10; i++ {
					ips = append(ips, "192.168.100.50")
				}
				// Add different IP
				ips = append(ips, "192.168.100.51")
				return ips
			},
			cidr:     "192.168.100.0/24",
			expected: 11, // 10 + 1
		},
		{
			name: "Empty range test",
			setupIPs: func() []string {
				return []string{
					"10.0.0.1",
					"172.16.0.1",
					"192.168.1.1",
				}
			},
			cidr:     "203.0.113.0/24", // No IPs in this range
			expected: 0,
		},
		{
			name: "Maximum /30 subnet",
			setupIPs: func() []string {
				return []string{
					"192.168.1.0", // Network
					"192.168.1.1", // First host
					"192.168.1.2", // Second host
					"192.168.1.3", // Broadcast
					"192.168.1.4", // Outside range
				}
			},
			cidr:     "192.168.1.0/30",
			expected: 4, // First 4 IPs only
		},
		{
			name: "Class A private network test",
			setupIPs: func() []string {
				return []string{
					"10.0.0.1",
					"10.255.255.254",
					"9.255.255.255", // Just outside
					"11.0.0.1",      // Just outside
					"10.128.64.32",  // Deep inside
				}
			},
			cidr:     "10.0.0.0/8",
			expected: 3, // Only the 10.x.x.x addresses
		},
		{
			name: "Zero network address",
			setupIPs: func() []string {
				return []string{
					"0.0.0.0",
					"0.0.0.1",
					"0.0.1.0",
					"1.0.0.0", // Outside
				}
			},
			cidr:     "0.0.0.0/16",
			expected: 3, // First 3 IPs
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			trie := NewTrie()

			// Insert all IPs
			for _, ipStr := range tt.setupIPs() {
				ip := net.ParseIP(ipStr)
				if ip == nil {
					t.Fatalf("Failed to parse IP: %s", ipStr)
				}
				trie.Insert(ip)
			}

			// Test CountInRange
			got, err := trie.CountInRange(tt.cidr)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if got != tt.expected {
				t.Errorf("CountInRange(%q) = %d, want %d", tt.cidr, got, tt.expected)

				// For debugging: also test with brute force method
				bruteForce := bruteForceCountInRange(trie, tt.cidr)
				t.Errorf("Brute force result: %d", bruteForce)
			}
		})
	}
}

// bruteForceCountInRange implements the original algorithm for comparison
func bruteForceCountInRange(trie *Trie, cidr string) uint32 {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return 0
	}

	var count uint32
	start := iputils.IPToUint32(ipNet.IP)
	maskSize, _ := ipNet.Mask.Size()
	hosts := uint32(1) << (32 - maskSize)

	for i := uint32(0); i < hosts; i++ {
		ip := iputils.Uint32ToIP(start + i)
		count += trie.Count(ip)
	}

	return count
}

// TestCountInRangeConsistency compares optimized vs brute force for various ranges
func TestCountInRangeConsistency(t *testing.T) {
	// Create a trie with diverse data
	trie := NewTrie()
	testIPs := []string{
		"192.168.1.1", "192.168.1.2", "192.168.1.10", "192.168.1.255",
		"192.168.2.1", "192.168.2.50",
		"10.0.0.1", "10.0.1.1", "10.1.0.1",
		"172.16.0.1", "172.16.1.1",
		"203.0.113.1",
	}

	for _, ipStr := range testIPs {
		ip := net.ParseIP(ipStr)
		if ip != nil {
			trie.Insert(ip)
		}
	}

	// Test various CIDR ranges
	testCIDRs := []string{
		"192.168.1.0/24",
		"192.168.0.0/23",
		"192.168.0.0/16",
		"10.0.0.0/16",
		"10.0.0.0/8",
		"172.16.0.0/24",
		"0.0.0.0/0", // Entire IPv4 space
		"203.0.113.0/24",
	}

	for _, cidr := range testCIDRs {
		t.Run(fmt.Sprintf("CIDR_%s", strings.ReplaceAll(cidr, "/", "_")), func(t *testing.T) {
			optimized, err := trie.CountInRange(cidr)
			if err != nil {
				t.Fatalf("Optimized method failed: %v", err)
			}

			// Only compare with brute force for smaller ranges to avoid timeout
			_, ipNet, _ := net.ParseCIDR(cidr)
			maskSize, _ := ipNet.Mask.Size()
			if maskSize >= 16 { // Only test ranges with ≤65536 IPs
				bruteForce := bruteForceCountInRange(trie, cidr)
				if optimized != bruteForce {
					t.Errorf("CIDR %s: optimized=%d, brute_force=%d", cidr, optimized, bruteForce)
				}
			}
		})
	}
}

// TestTrieAllocatorCorrectness verifies that the pooled implementation produces identical results to classic
func TestTrieAllocatorCorrectness(t *testing.T) {
	tests := []struct {
		name string
		size int
		cidr string
	}{
		{"Small dataset", 1000, "10.0.0.0/8"},
		{"Medium dataset", 10000, "192.168.0.0/16"},
		{"Large dataset", 50000, "172.16.0.0/12"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate test IPs
			ips, err := iputils.RandomIPsFromRange(tt.cidr, tt.size)
			if err != nil {
				t.Fatalf("Failed to generate IPs: %v", err)
			}

			// Test with pooled implementation
			pooledTrie := NewTrie()
			for _, ip := range ips {
				pooledTrie.Insert(ip)
			}

			// Test with classic implementation
			classicTrie := NewTrieClassic()
			for _, ip := range ips {
				classicTrie.Insert(ip)
			}

			// Compare counts for all inserted IPs
			for _, ip := range ips {
				pooledCount := pooledTrie.Count(ip)
				classicCount := classicTrie.Count(ip)
				if pooledCount != classicCount {
					t.Errorf("Count mismatch for IP %s: pooled=%d, classic=%d", ip.String(), pooledCount, classicCount)
				}
			}

			// Test delete operations
			for i, ip := range ips {
				if i%3 == 0 { // Delete every 3rd IP
					pooledTrie.Delete(ip)
					classicTrie.Delete(ip)
				}
			}

			// Verify counts after deletion
			for _, ip := range ips {
				pooledCount := pooledTrie.Count(ip)
				classicCount := classicTrie.Count(ip)
				if pooledCount != classicCount {
					t.Errorf("Count mismatch after delete for IP %s: pooled=%d, classic=%d", ip.String(), pooledCount, classicCount)
				}
			}
		})
	}
}

// TestTrieAllocatorStress performs stress testing with many operations
func TestTrieAllocatorStress(t *testing.T) {
	pooledTrie := NewTrie()
	classicTrie := NewTrieClassic()

	// Generate test data
	ips, err := iputils.RandomIPsFromRange("10.0.0.0/8", 10000)
	if err != nil {
		t.Fatalf("Failed to generate IPs: %v", err)
	}

	// Perform mixed operations
	for i, ip := range ips {
		// Insert
		pooledTrie.Insert(ip)
		classicTrie.Insert(ip)

		// Verify count periodically
		if i%1000 == 0 {
			pooledCount := pooledTrie.Count(ip)
			classicCount := classicTrie.Count(ip)
			if pooledCount != classicCount {
				t.Errorf("Insert stress test: count mismatch for IP %s: pooled=%d, classic=%d", ip.String(), pooledCount, classicCount)
			}
		}

		// Delete some IPs
		if i > 0 && i%5 == 0 {
			deleteIP := ips[i-1]
			pooledTrie.Delete(deleteIP)
			classicTrie.Delete(deleteIP)
		}
	}

	// Final verification
	for _, ip := range ips {
		pooledCount := pooledTrie.Count(ip)
		classicCount := classicTrie.Count(ip)
		if pooledCount != classicCount {
			t.Errorf("Final stress test: count mismatch for IP %s: pooled=%d, classic=%d", ip.String(), pooledCount, classicCount)
		}
	}
}

// TestCountInRangeIPNet tests the IPNet-native version for correctness
func TestCountInRangeIPNet(t *testing.T) {
	tests := []struct {
		name      string
		insertIPs []string
		cidr      string
		expected  uint32
	}{
		{
			name:      "Single IP in CIDR",
			insertIPs: []string{"192.168.1.1"},
			cidr:      "192.168.1.0/24",
			expected:  1,
		},
		{
			name:      "Multiple IPs in CIDR",
			insertIPs: []string{"192.168.1.1", "192.168.1.2", "192.168.1.3"},
			cidr:      "192.168.1.0/24",
			expected:  3,
		},
		{
			name:      "IPs outside CIDR",
			insertIPs: []string{"10.0.0.1", "10.0.0.2"},
			cidr:      "192.168.1.0/24",
			expected:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			trie := NewTrie()
			for _, ipStr := range tt.insertIPs {
				ip := net.ParseIP(ipStr)
				if ip == nil {
					t.Fatalf("Failed to parse IP: %s", ipStr)
				}
				trie.Insert(ip)
			}

			// Parse CIDR once
			_, ipNet, err := net.ParseCIDR(tt.cidr)
			if err != nil {
				t.Fatalf("Failed to parse CIDR: %s", tt.cidr)
			}

			// Test IPNet version
			gotIPNet := trie.CountInRangeIPNet(ipNet)
			if gotIPNet != tt.expected {
				t.Errorf("CountInRangeIPNet(%s) = %d, want %d", tt.cidr, gotIPNet, tt.expected)
			}

			// Verify it matches string version
			gotString, err := trie.CountInRange(tt.cidr)
			if err != nil {
				t.Fatalf("CountInRange failed: %v", err)
			}
			if gotIPNet != gotString {
				t.Errorf("CountInRangeIPNet(%d) != CountInRange(%d) for CIDR %s", gotIPNet, gotString, tt.cidr)
			}
		})
	}
}

// TestCountInRangeSlashZero verifies the /0 guard (CIDRX-003): a /0 CIDR spans
// the whole IPv4 space and must return the full trie count (== CountAll), not 0.
// It also checks the non-/0 boundary cases remain unchanged by the guard.
func TestCountInRangeSlashZero(t *testing.T) {
	t.Run("Slash zero returns full count for two IPs", func(t *testing.T) {
		trie := NewTrie()
		for _, ipStr := range []string{"192.168.1.1", "10.0.0.1"} {
			ip := net.ParseIP(ipStr)
			if ip == nil {
				t.Fatalf("Failed to parse IP: %s", ipStr)
			}
			trie.Insert(ip)
		}

		got, err := trie.CountInRange("0.0.0.0/0")
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if got != 2 {
			t.Errorf("CountInRange(0.0.0.0/0) = %d, want 2", got)
		}
		if got != trie.CountAll() {
			t.Errorf("CountInRange(0.0.0.0/0) = %d, want CountAll() = %d", got, trie.CountAll())
		}
	})

	t.Run("Slash zero across multiple slash 8s equals total inserted", func(t *testing.T) {
		trie := NewTrie()
		insertIPs := []string{
			"1.2.3.4",
			"10.0.0.1",
			"10.0.0.2",
			"172.16.5.9",
			"192.168.1.1",
			"255.255.255.255",
		}
		for _, ipStr := range insertIPs {
			ip := net.ParseIP(ipStr)
			if ip == nil {
				t.Fatalf("Failed to parse IP: %s", ipStr)
			}
			trie.Insert(ip)
		}

		got, err := trie.CountInRange("0.0.0.0/0")
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if want := uint32(len(insertIPs)); got != want {
			t.Errorf("CountInRange(0.0.0.0/0) = %d, want %d", got, want)
		}
		if got != trie.CountAll() {
			t.Errorf("CountInRange(0.0.0.0/0) = %d, want CountAll() = %d", got, trie.CountAll())
		}
	})

	t.Run("Slash zero on empty trie returns 0", func(t *testing.T) {
		trie := NewTrie()
		got, err := trie.CountInRange("0.0.0.0/0")
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if got != 0 {
			t.Errorf("CountInRange(0.0.0.0/0) = %d, want 0", got)
		}
	})

	t.Run("exactly one IP", func(t *testing.T) {
		// A trie holding exactly one IP — including the very first and very
		// last address of the space — must report 1 for the full range.
		for _, ipStr := range []string{"0.0.0.0", "203.0.113.7", "255.255.255.255"} {
			trie := NewTrie()
			ip := net.ParseIP(ipStr)
			if ip == nil {
				t.Fatalf("Failed to parse IP: %s", ipStr)
			}
			trie.Insert(ip)

			got, err := trie.CountInRange("0.0.0.0/0")
			if err != nil {
				t.Fatalf("%s: unexpected error: %v", ipStr, err)
			}
			if got != 1 {
				t.Errorf("%s: CountInRange(0.0.0.0/0) = %d, want 1", ipStr, got)
			}
			if got != trie.CountAll() {
				t.Errorf("%s: CountInRange(0.0.0.0/0) = %d, want CountAll() = %d", ipStr, got, trie.CountAll())
			}

			// The same IP inserted twice counts as 2 requests.
			trie.Insert(ip)
			got, err = trie.CountInRange("0.0.0.0/0")
			if err != nil {
				t.Fatalf("%s twice: unexpected error: %v", ipStr, err)
			}
			if got != 2 {
				t.Errorf("%s twice: CountInRange(0.0.0.0/0) = %d, want 2", ipStr, got)
			}
		}
	})

	// Boundary regressions that must be UNCHANGED by the /0 guard.
	t.Run("Boundary cases unchanged by guard", func(t *testing.T) {
		boundaryTests := []struct {
			name      string
			insertIPs []string
			cidr      string
			expected  uint32
		}{
			{
				name:      "/32 exact single IP",
				insertIPs: []string{"203.0.113.42", "203.0.113.43"},
				cidr:      "203.0.113.42/32",
				expected:  1,
			},
			{
				name:      "/31 covering two IPs",
				insertIPs: []string{"192.168.1.0", "192.168.1.1", "192.168.1.2"},
				cidr:      "192.168.1.0/31",
				expected:  2,
			},
			{
				name:      "/24 covering a known subset",
				insertIPs: []string{"192.168.1.1", "192.168.1.250", "192.168.2.1"},
				cidr:      "192.168.1.0/24",
				expected:  2,
			},
			{
				name:      "/32 top of address space",
				insertIPs: []string{"255.255.255.255", "255.255.255.254"},
				cidr:      "255.255.255.255/32",
				expected:  1,
			},
			{
				name:      "/31 top of address space",
				insertIPs: []string{"255.255.255.255", "255.255.255.254", "255.255.255.253"},
				cidr:      "255.255.255.254/31",
				expected:  2,
			},
		}

		for _, bt := range boundaryTests {
			t.Run(bt.name, func(t *testing.T) {
				trie := NewTrie()
				for _, ipStr := range bt.insertIPs {
					ip := net.ParseIP(ipStr)
					if ip == nil {
						t.Fatalf("Failed to parse IP: %s", ipStr)
					}
					trie.Insert(ip)
				}
				got, err := trie.CountInRange(bt.cidr)
				if err != nil {
					t.Fatalf("Unexpected error for CIDR %q: %v", bt.cidr, err)
				}
				if got != bt.expected {
					t.Errorf("CountInRange(%q) = %d, want %d", bt.cidr, got, bt.expected)
				}
			})
		}
	})
}

// BenchmarkCountInRangeComparison compares string vs IPNet performance
func BenchmarkCountInRangeComparison(b *testing.B) {
	// Setup trie with test data
	trie := NewTrie()
	ips, _ := iputils.RandomIPsFromRange("10.0.0.0/8", 10000)
	for _, ip := range ips {
		trie.Insert(ip)
	}

	testCIDR := "10.0.0.0/16"
	_, ipNet, _ := net.ParseCIDR(testCIDR)

	b.Run("CountInRange_String", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, _ = trie.CountInRange(testCIDR)
		}
	})

	b.Run("CountInRangeIPNet", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = trie.CountInRangeIPNet(ipNet)
		}
	})
}

// ============================================================================
// DUPLICATE ANALYSIS TESTS (from analyze_duplicates_test.go)
// ============================================================================

func TestAnalyzeDuplicates(t *testing.T) {
	// Generate test log with 50000 lines for meaningful duplicate analysis
	testFile, cleanup := testutil.GenerateTestLogFile(t, 50000)
	defer cleanup()

	logFormat := "%^ %^ %^ [%t] \"%r\" %s %b %^ \"%u\" \"%h\""
	parser, err := logparser.NewParser(logFormat)
	if err != nil {
		t.Fatalf("Could not create parser: %v", err)
	}

	requests, err := parser.ParseFile(testFile)
	if err != nil {
		t.Fatalf("Could not parse log file: %v", err)
	}

	if len(requests) < 50000 {
		t.Fatalf("Expected at least 50000 requests, got %d", len(requests))
	}

	// Convert to uint32 for analysis
	ipCounts := make(map[uint32]int)
	var totalRequests int

	for _, req := range requests {
		ipUint := req.IPUint32
		ipCounts[ipUint]++
		totalRequests++
	}

	uniqueIPs := len(ipCounts)
	duplicateRequests := totalRequests - uniqueIPs

	fmt.Printf("Total requests: %d\n", totalRequests)
	fmt.Printf("Unique IPs: %d\n", uniqueIPs)
	fmt.Printf("Duplicate requests: %d\n", duplicateRequests)
	fmt.Printf("Duplicate ratio: %.2f%%\n", float64(duplicateRequests)/float64(totalRequests)*100)

	// Analyze distribution of duplicates
	duplicateCounts := make(map[int]int)
	for _, count := range ipCounts {
		duplicateCounts[count]++
	}

	fmt.Printf("\nDuplicate distribution:\n")
	for count := 1; count <= 10; count++ {
		if duplicateCounts[count] > 0 {
			fmt.Printf("IPs appearing %d times: %d\n", count, duplicateCounts[count])
		}
	}

	// Count IPs with more than 10 occurrences
	highDuplicates := 0
	for _, count := range ipCounts {
		if count > 10 {
			highDuplicates++
		}
	}
	fmt.Printf("IPs appearing >10 times: %d\n", highDuplicates)
}

func TestTrie_AllSameIP(t *testing.T) {
	trie := NewTrie()
	ip := net.ParseIP("192.168.1.1")
	if ip == nil {
		t.Fatal("Failed to parse IP")
	}

	for i := 0; i < 10000; i++ {
		trie.Insert(ip)
	}

	count := trie.Count(ip)
	if count != 10000 {
		t.Errorf("Expected Count to be 10000, got %d", count)
	}

	totalCount := trie.CountAll()
	if totalCount != 10000 {
		t.Errorf("Expected CountAll to be 10000, got %d", totalCount)
	}

	cidrs := trie.CollectCIDRs(5000, 24, 32, 0.1)
	if len(cidrs) == 0 {
		t.Fatal("Expected at least one CIDR from CollectCIDRs")
	}

	// Verify the returned CIDR contains 192.168.1.1
	found := false
	for _, cidr := range cidrs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			t.Fatalf("Failed to parse returned CIDR %s: %v", cidr, err)
		}
		if ipNet.Contains(ip) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected a CIDR containing 192.168.1.1, got %v", cidrs)
	}
}

func TestTrie_DeleteNonexistent(t *testing.T) {
	trie := NewTrie()
	ip := net.ParseIP("10.0.0.1")
	if ip == nil {
		t.Fatal("Failed to parse IP")
	}

	// Should not panic
	trie.Delete(ip)

	count := trie.CountAll()
	if count != 0 {
		t.Errorf("Expected CountAll to be 0 after deleting from empty trie, got %d", count)
	}
}
