package cidr

import (
	"fmt"
	"net"
	"testing"
)

func TestRemoveWhitelistedLargeScale(t *testing.T) {
	// Generate large blacklist
	blacklist := make([]string, 0, 10000)
	for i := 0; i < 100; i++ {
		for j := 0; j < 100; j++ {
			blacklist = append(blacklist, fmt.Sprintf("10.%d.%d.0/24", i, j))
		}
	}

	// Generate whitelist that covers some ranges
	whitelist := []string{
		"10.0.0.0/16",  // Covers 10.0.x.x
		"10.50.0.0/16", // Covers 10.50.x.x
	}

	result := RemoveWhitelisted(blacklist, whitelist)

	// Should have removed entries covered by whitelist
	expectedRemoved := 200 // 100 entries for 10.0.x.x + 100 entries for 10.50.x.x
	expectedRemaining := len(blacklist) - expectedRemoved

	if len(result) != expectedRemaining {
		t.Errorf("Expected %d remaining entries, got %d", expectedRemaining, len(result))
	}

	// Verify none of the remaining entries are whitelisted
	for _, cidr := range result {
		if refIsWhitelisted(cidr, whitelist) {
			t.Errorf("Found whitelisted CIDR in result: %s", cidr)
		}
	}

	// Verify that some specific entries were removed
	removedEntries := []string{"10.0.0.0/24", "10.0.50.0/24", "10.50.0.0/24", "10.50.99.0/24"}
	for _, removed := range removedEntries {
		for _, remaining := range result {
			if remaining == removed {
				t.Errorf("Expected CIDR %s to be removed but it's still present", removed)
			}
		}
	}
}

// TestIsWhitelisted exercises refIsWhitelisted, the package-local reference
// oracle that is a verbatim copy of the deleted cidr.IsWhitelisted. The
// differential RemoveWhitelisted test depends on this oracle, so its
// single-entry-coverage semantics must stay correct.
func TestIsWhitelisted(t *testing.T) {
	tests := []struct {
		name      string
		cidr      string
		whitelist []string
		expected  bool
	}{
		{
			name:      "Empty whitelist",
			cidr:      "192.168.1.0/24",
			whitelist: []string{},
			expected:  false,
		},
		{
			name:      "Exact match",
			cidr:      "192.168.1.0/24",
			whitelist: []string{"192.168.1.0/24"},
			expected:  true,
		},
		{
			name:      "Subnet contained in whitelist",
			cidr:      "192.168.1.128/25",
			whitelist: []string{"192.168.1.0/24"},
			expected:  true,
		},
		{
			name:      "Supernet not contained in smaller whitelist",
			cidr:      "192.168.0.0/16",
			whitelist: []string{"192.168.1.0/24"},
			expected:  false,
		},
		{
			name:      "Multiple whitelist entries - first matches",
			cidr:      "10.0.0.0/24",
			whitelist: []string{"10.0.0.0/24", "192.168.1.0/24"},
			expected:  true,
		},
		{
			name:      "Multiple whitelist entries - second matches",
			cidr:      "192.168.1.128/25",
			whitelist: []string{"10.0.0.0/24", "192.168.1.0/24"},
			expected:  true,
		},
		{
			name:      "No match in multiple entries",
			cidr:      "172.16.1.0/24",
			whitelist: []string{"10.0.0.0/24", "192.168.1.0/24"},
			expected:  false,
		},
		{
			name:      "Adjacent but not overlapping",
			cidr:      "192.168.2.0/24",
			whitelist: []string{"192.168.1.0/24"},
			expected:  false,
		},
		{
			name:      "Invalid CIDR in candidate",
			cidr:      "invalid-cidr",
			whitelist: []string{"192.168.1.0/24"},
			expected:  false,
		},
		{
			name:      "Invalid CIDR in whitelist",
			cidr:      "192.168.1.0/24",
			whitelist: []string{"invalid-cidr", "192.168.1.0/24"},
			expected:  true,
		},
		{
			name:      "Large whitelist network contains smaller candidate",
			cidr:      "192.168.100.64/26",
			whitelist: []string{"192.168.0.0/16"},
			expected:  true,
		},
		{
			name:      "Single IP contained in subnet",
			cidr:      "10.0.0.1/32",
			whitelist: []string{"10.0.0.0/24"},
			expected:  true,
		},
		{
			name:      "Single IP not contained",
			cidr:      "10.0.1.1/32",
			whitelist: []string{"10.0.0.0/24"},
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := refIsWhitelisted(tt.cidr, tt.whitelist)
			if result != tt.expected {
				t.Errorf("refIsWhitelisted(%q, %v) = %v, want %v", tt.cidr, tt.whitelist, result, tt.expected)
			}
		})
	}
}

func TestRemoveWhitelisted(t *testing.T) {
	tests := []struct {
		name      string
		blacklist []string
		whitelist []string
		expected  []string
	}{
		{
			name:      "Empty lists",
			blacklist: []string{},
			whitelist: []string{},
			expected:  []string{},
		},
		{
			name:      "Empty whitelist",
			blacklist: []string{"192.168.1.0/24", "10.0.0.0/24"},
			whitelist: []string{},
			expected:  []string{"192.168.1.0/24", "10.0.0.0/24"},
		},
		{
			name:      "Empty blacklist",
			blacklist: []string{},
			whitelist: []string{"192.168.1.0/24"},
			expected:  []string{},
		},
		{
			name:      "No matches",
			blacklist: []string{"172.16.1.0/24", "10.0.0.0/24"},
			whitelist: []string{"192.168.1.0/24"},
			expected:  []string{"172.16.1.0/24", "10.0.0.0/24"},
		},
		{
			name:      "Single exact match removed",
			blacklist: []string{"192.168.1.0/24", "10.0.0.0/24"},
			whitelist: []string{"192.168.1.0/24"},
			expected:  []string{"10.0.0.0/24"},
		},
		{
			name:      "All blacklisted removed",
			blacklist: []string{"192.168.1.0/24", "192.168.2.0/24"},
			whitelist: []string{"192.168.0.0/16"},
			expected:  []string{},
		},
		{
			name:      "Partial removal",
			blacklist: []string{"192.168.1.0/24", "10.0.0.0/24", "172.16.1.0/24"},
			whitelist: []string{"192.168.0.0/16", "172.16.0.0/16"},
			expected:  []string{"10.0.0.0/24"},
		},
		{
			name:      "Subnet removed by larger whitelist",
			blacklist: []string{"192.168.1.128/25", "192.168.1.64/26", "10.0.0.0/24"},
			whitelist: []string{"192.168.1.0/24"},
			expected:  []string{"10.0.0.0/24"},
		},
		{
			name:      "Multiple whitelist entries",
			blacklist: []string{"192.168.1.0/24", "10.0.0.0/24", "172.16.1.0/24", "203.0.113.0/24"},
			whitelist: []string{"192.168.0.0/16", "10.0.0.0/8", "203.0.113.0/24"},
			expected:  []string{"172.16.1.0/24"},
		},
		{
			name:      "Single IP whitelist",
			blacklist: []string{"192.168.1.1/32", "192.168.1.2/32", "10.0.0.1/32"},
			whitelist: []string{"192.168.1.1/32"},
			expected:  []string{"192.168.1.2/32", "10.0.0.1/32"},
		},
		{
			name: "Complex overlapping scenario",
			blacklist: []string{
				"192.168.1.0/25",   // First half of /24
				"192.168.1.128/25", // Second half of /24
				"192.168.2.0/24",   // Different /24
				"10.0.0.0/24",      // Different network
			},
			whitelist: []string{"192.168.0.0/16"}, // Covers both .1.x networks
			expected:  []string{"10.0.0.0/24"},
		},
		{
			name: "Complex overlapping scenario single IP",
			blacklist: []string{
				"192.168.1.0/24", // Whole /24 – we’ll subtract the whitelisted IP
				"10.0.0.0/24",    // Independent network
			},
			whitelist: []string{
				"192.168.1.201/32", // One host we must allow
			},
			expected: []string{
				// 10.0.0.0/24 is unaffected
				"10.0.0.0/24",

				// 192.168.1.0/24 with 192.168.1.201 removed,
				// expressed as the minimal, non-overlapping CIDRs:
				"192.168.1.0/25",   // 192.168.1.0   – 192.168.1.127
				"192.168.1.128/26", // 192.168.1.128 – 192.168.1.191
				"192.168.1.192/29", // 192.168.1.192 – 192.168.1.199
				"192.168.1.200/32", // 192.168.1.200
				"192.168.1.202/31", // 192.168.1.202 – 192.168.1.203
				"192.168.1.204/30", // 192.168.1.204 – 192.168.1.207
				"192.168.1.208/28", // 192.168.1.208 – 192.168.1.223
				"192.168.1.224/27", // 192.168.1.224 – 192.168.1.255
			},
		},
		{
			name:      "Multiple single IP exclusions from same network",
			blacklist: []string{"172.16.1.0/24", "10.0.0.0/8"},
			whitelist: []string{
				"172.16.1.1/32",   // Exclude first host
				"172.16.1.254/32", // Exclude last host
				"172.16.1.128/32", // Exclude middle host
			},
			expected: []string{
				"10.0.0.0/8", // Unchanged network
				// 172.16.1.0/24 with three IPs excluded (.1, .128, .254):
				"172.16.1.0/32",   // Just .0
				"172.16.1.2/31",   // .2-.3
				"172.16.1.4/30",   // .4-.7
				"172.16.1.8/29",   // .8-.15
				"172.16.1.16/28",  // .16-.31
				"172.16.1.32/27",  // .32-.63
				"172.16.1.64/26",  // .64-.127
				"172.16.1.129/32", // Just .129
				"172.16.1.130/31", // .130-.131
				"172.16.1.132/30", // .132-.135
				"172.16.1.136/29", // .136-.143
				"172.16.1.144/28", // .144-.159
				"172.16.1.160/27", // .160-.191
				"172.16.1.192/27", // .192-.223
				"172.16.1.224/28", // .224-.239
				"172.16.1.240/29", // .240-.247
				"172.16.1.248/30", // .248-.251
				"172.16.1.252/31", // .252-.253
				"172.16.1.255/32", // Just .255
			},
		},
		{
			name:      "Exclude /25 subnet from /24 network",
			blacklist: []string{"203.0.113.0/24"},
			whitelist: []string{"203.0.113.128/25"}, // Second half
			expected: []string{
				"203.0.113.0/25", // First half remains
			},
		},
		{
			name:      "Exclude /26 subnet from middle of /24",
			blacklist: []string{"198.51.100.0/24"},
			whitelist: []string{"198.51.100.64/26"}, // .64-.127
			expected: []string{
				"198.51.100.0/26",   // .0-.63
				"198.51.100.128/25", // .128-.255
			},
		},
		{
			name: "Complex multi-network with overlapping exclusions",
			blacklist: []string{
				"10.1.0.0/16", // Large network
				"10.2.0.0/24", // Smaller network
				"192.168.0.0/24",
			},
			whitelist: []string{
				"10.1.1.0/24",    // Hole in large network
				"10.1.2.128/25",  // Another hole in large network
				"10.2.0.100/32",  // Single IP from smaller network
				"192.168.0.0/26", // Quarter of the /24
			},
			expected: []string{
				// 10.1.0.0/16 with holes:
				"10.1.0.0/24",   // .0.x
				"10.1.2.0/25",   // .2.0-.2.127 (excluding .2.128/25)
				"10.1.3.0/24",   // .3.x
				"10.1.4.0/22",   // .4.x - .7.x
				"10.1.8.0/21",   // .8.x - .15.x
				"10.1.16.0/20",  // .16.x - .31.x
				"10.1.32.0/19",  // .32.x - .63.x
				"10.1.64.0/18",  // .64.x - .127.x
				"10.1.128.0/17", // .128.x - .255.x

				// 10.2.0.0/24 with one IP excluded:
				"10.2.0.0/26",   // .0-.63
				"10.2.0.64/27",  // .64-.95
				"10.2.0.96/30",  // .96-.99
				"10.2.0.101/32", // .101
				"10.2.0.102/31", // .102-.103
				"10.2.0.104/29", // .104-.111
				"10.2.0.112/28", // .112-.127
				"10.2.0.128/25", // .128-.255

				// 192.168.0.0/24 with first quarter excluded:
				"192.168.0.64/26",  // .64-.127
				"192.168.0.128/25", // .128-.255
			},
		},
		{
			name:      "Edge case: exclude first and last IP from /30",
			blacklist: []string{"172.20.1.0/30"}, // Just 4 IPs: .0, .1, .2, .3
			whitelist: []string{
				"172.20.1.0/32", // Network address
				"172.20.1.3/32", // Broadcast address
			},
			expected: []string{
				"172.20.1.1/32", // Just .1
				"172.20.1.2/32", // Just .2
			},
		},
		{
			name:      "Exclude middle /28 from /26",
			blacklist: []string{"10.0.100.0/26"},  // .0-.63
			whitelist: []string{"10.0.100.16/28"}, // .16-.31
			expected: []string{
				"10.0.100.0/28",  // .0-.15
				"10.0.100.32/27", // .32-.63
			},
		},
		{
			name:      "Multiple non-contiguous subnet exclusions",
			blacklist: []string{"172.31.0.0/22"}, // .0.0 - .3.255
			whitelist: []string{
				"172.31.1.0/24", // Exclude .1.x
				"172.31.3.0/24", // Exclude .3.x
			},
			expected: []string{
				"172.31.0.0/24", // .0.x remains
				"172.31.2.0/24", // .2.x remains
			},
		},
		{
			name: "Cascading exclusions - whitelist larger than individual blacklist items",
			blacklist: []string{
				"192.168.1.0/25",   // .0-.127
				"192.168.1.128/26", // .128-.191
				"192.168.1.192/27", // .192-.223
			},
			whitelist: []string{
				"192.168.1.0/24", // Covers all blacklist items
			},
			expected: []string{}, // All should be removed
		},
		{
			name:      "Invalid CIDRs handled gracefully",
			blacklist: []string{"invalid-cidr", "192.168.1.0/24", "10.0.0.0/24"},
			whitelist: []string{"192.168.1.0/24"},
			expected:  []string{"invalid-cidr", "10.0.0.0/24"},
		},
		{
			name:      "Whitelist /0 wipes blacklist /0",
			blacklist: []string{"0.0.0.0/0"},
			whitelist: []string{"0.0.0.0/0"},
			expected:  []string{},
		},
		{
			name:      "Whitelist /0 wipes every blacklist entry",
			blacklist: []string{"10.0.0.0/8", "255.255.255.255/32", "0.0.0.0/0"},
			whitelist: []string{"0.0.0.0/0"},
			expected:  []string{},
		},
		{
			name:      "Top-of-space /32 removed by itself",
			blacklist: []string{"255.255.255.255/32"},
			whitelist: []string{"255.255.255.255/32"},
			expected:  []string{},
		},
		{
			name:      "Bottom-of-space /32 whitelist does not touch top-of-space /32",
			blacklist: []string{"255.255.255.255/32"},
			whitelist: []string{"0.0.0.0/32"},
			expected:  []string{"255.255.255.255/32"},
		},
		{
			name:      "Whitelist lower half of /0 leaves upper half",
			blacklist: []string{"0.0.0.0/0"},
			whitelist: []string{"0.0.0.0/1"},
			expected:  []string{"128.0.0.0/1"},
		},
		{
			name:      "Exclude top-of-space /32 from /0 yields descending ladder",
			blacklist: []string{"0.0.0.0/0"},
			whitelist: []string{"255.255.255.255/32"},
			expected: []string{
				"0.0.0.0/1", "128.0.0.0/2", "192.0.0.0/3", "224.0.0.0/4",
				"240.0.0.0/5", "248.0.0.0/6", "252.0.0.0/7", "254.0.0.0/8",
				"255.0.0.0/9", "255.128.0.0/10", "255.192.0.0/11", "255.224.0.0/12",
				"255.240.0.0/13", "255.248.0.0/14", "255.252.0.0/15", "255.254.0.0/16",
				"255.255.0.0/17", "255.255.128.0/18", "255.255.192.0/19", "255.255.224.0/20",
				"255.255.240.0/21", "255.255.248.0/22", "255.255.252.0/23", "255.255.254.0/24",
				"255.255.255.0/25", "255.255.255.128/26", "255.255.255.192/27", "255.255.255.224/28",
				"255.255.255.240/29", "255.255.255.248/30", "255.255.255.252/31", "255.255.255.254/32",
			},
		},
		{
			name:      "Exclude bottom-of-space /32 from /0 yields ascending ladder",
			blacklist: []string{"0.0.0.0/0"},
			whitelist: []string{"0.0.0.0/32"},
			expected: []string{
				"0.0.0.1/32", "0.0.0.2/31", "0.0.0.4/30", "0.0.0.8/29",
				"0.0.0.16/28", "0.0.0.32/27", "0.0.0.64/26", "0.0.0.128/25",
				"0.0.1.0/24", "0.0.2.0/23", "0.0.4.0/22", "0.0.8.0/21",
				"0.0.16.0/20", "0.0.32.0/19", "0.0.64.0/18", "0.0.128.0/17",
				"0.1.0.0/16", "0.2.0.0/15", "0.4.0.0/14", "0.8.0.0/13",
				"0.16.0.0/12", "0.32.0.0/11", "0.64.0.0/10", "0.128.0.0/9",
				"1.0.0.0/8", "2.0.0.0/7", "4.0.0.0/6", "8.0.0.0/5",
				"16.0.0.0/4", "32.0.0.0/3", "64.0.0.0/2", "128.0.0.0/1",
			},
		},
		{
			name:      "Invalid blacklist entry survives whitelist /0",
			blacklist: []string{"invalid-cidr", "10.0.0.0/8"},
			whitelist: []string{"0.0.0.0/0"},
			expected:  []string{"invalid-cidr"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := RemoveWhitelisted(tt.blacklist, tt.whitelist)

			// Check length
			if len(result) != len(tt.expected) {
				t.Errorf("cidr.RemoveWhitelisted() returned %d items, want %d\nGot: %v\nWant: %v",
					len(result), len(tt.expected), result, tt.expected)
				return
			}

			// Check each expected item is present
			for _, expectedCidr := range tt.expected {
				found := false
				for _, resultCidr := range result {
					if resultCidr == expectedCidr {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected CIDR %q not found in result %v", expectedCidr, result)
				}
			}

			// Check no unexpected items are present
			for _, resultCidr := range result {
				found := false
				for _, expectedCidr := range tt.expected {
					if resultCidr == expectedCidr {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Unexpected CIDR %q found in result %v", resultCidr, result)
				}
			}
		})
	}
}

// mustParseCIDRs parses CIDR strings into IPNets, failing the test on error.
func mustParseCIDRs(tb testing.TB, cidrs []string) []*net.IPNet {
	tb.Helper()
	var ipNets []*net.IPNet
	for _, c := range cidrs {
		_, ipNet, err := net.ParseCIDR(c)
		if err != nil {
			tb.Fatalf("invalid CIDR %s: %v", c, err)
		}
		ipNets = append(ipNets, ipNet)
	}
	return ipNets
}

// ipNetsToStrings stringifies merged IPNets for comparison against expected tables.
func ipNetsToStrings(ipNets []*net.IPNet) []string {
	var result []string
	for _, n := range ipNets {
		result = append(result, n.String())
	}
	return result
}

func TestMergeCidrs(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "Empty input",
			input:    []string{},
			expected: []string{},
		},
		{
			name:     "Single CIDR",
			input:    []string{"192.168.1.0/24"},
			expected: []string{"192.168.1.0/24"},
		},
		{
			name: "Non-overlapping CIDRs",
			input: []string{
				"192.168.1.2/32",
				"192.168.1.3/32",
			},
			expected: []string{
				"192.168.1.2/31",
			},
		},
		{
			name: "Overlapping CIDRs",
			input: []string{
				"10.0.0.0/24",
				"10.0.0.128/25",
			},
			expected: []string{
				"10.0.0.0/24",
			},
		},
		{
			name: "Adjacent CIDRs",
			input: []string{
				"172.16.0.0/24",
				"172.16.1.0/24",
			},
			expected: []string{
				"172.16.0.0/23",
			},
		},
		{
			name: "Multiple mergeable CIDRs",
			input: []string{
				"192.168.0.0/24",
				"192.168.1.0/24",
				"192.168.2.0/24",
				"192.168.3.0/24",
			},
			expected: []string{
				"192.168.0.0/22",
			},
		},
		{
			name: "Mixed mergeable and non-mergeable",
			input: []string{
				"10.0.0.0/24",
				"10.0.1.0/24",
				"10.0.2.0/24",
			},
			expected: []string{
				"10.0.0.0/23",
				"10.0.2.0/24",
			},
		},
		{
			name: "Overlapping and adjacent",
			input: []string{
				"192.168.1.0/25",
				"192.168.1.128/25",
				"192.168.2.0/24",
			},
			expected: []string{
				"192.168.1.0/24",
				"192.168.2.0/24",
			},
		},
		{
			name: "Already merged",
			input: []string{
				"10.0.0.0/8",
				"10.0.0.0/9",
			},
			expected: []string{
				"10.0.0.0/8",
			},
		},
	}

	normalize := func(cidrs []string) map[string]struct{} {
		m := make(map[string]struct{})
		for _, c := range cidrs {
			m[c] = struct{}{}
		}
		return m
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ipNetsToStrings(MergeIPNets(mustParseCIDRs(t, tt.input)))
			gotMap := normalize(got)
			expMap := normalize(tt.expected)
			if len(gotMap) != len(expMap) {
				t.Errorf("expected %v, got %v", tt.expected, got)
			}
			for cidr := range expMap {
				if _, ok := gotMap[cidr]; !ok {
					t.Errorf("expected CIDR %s in result, got %v", cidr, got)
				}
			}
		})
	}
}

// TestMergeIPNets tests the IPNet-native merge function
func TestMergeIPNets(t *testing.T) {
	tests := []struct {
		name     string
		cidrs    []string
		expected []string
	}{
		{
			name:     "No merging needed",
			cidrs:    []string{"192.168.1.0/24", "10.0.0.0/24"},
			expected: []string{"10.0.0.0/24", "192.168.1.0/24"},
		},
		{
			name:     "Adjacent networks",
			cidrs:    []string{"192.168.0.0/24", "192.168.1.0/24"},
			expected: []string{"192.168.0.0/23"},
		},
		{
			name:     "Contained networks",
			cidrs:    []string{"192.168.0.0/16", "192.168.1.0/24"},
			expected: []string{"192.168.0.0/16"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test IPNet version against the expected table
			gotStrings := ipNetsToStrings(MergeIPNets(mustParseCIDRs(t, tt.cidrs)))

			normalize := func(cidrs []string) map[string]struct{} {
				m := make(map[string]struct{})
				for _, c := range cidrs {
					m[c] = struct{}{}
				}
				return m
			}
			gotMap := normalize(gotStrings)
			expMap := normalize(tt.expected)

			if len(gotMap) != len(expMap) {
				t.Errorf("MergeIPNets result differs from expected: got %v, expected %v", gotStrings, tt.expected)
			}
			for cidr := range expMap {
				if _, ok := gotMap[cidr]; !ok {
					t.Errorf("Expected CIDR %s in MergeIPNets result, got %v", cidr, gotStrings)
				}
			}
		})
	}
}

// TestIsWhitelistedIPNet tests the IPNet-native whitelist checking
func TestIsWhitelistedIPNet(t *testing.T) {
	tests := []struct {
		name      string
		candidate string
		whitelist []string
		expected  bool
	}{
		{
			name:      "Exact match",
			candidate: "192.168.1.0/24",
			whitelist: []string{"192.168.1.0/24"},
			expected:  true,
		},
		{
			name:      "Contained in larger network",
			candidate: "192.168.1.0/24",
			whitelist: []string{"192.168.0.0/16"},
			expected:  true,
		},
		{
			name:      "Not whitelisted",
			candidate: "10.0.0.0/24",
			whitelist: []string{"192.168.0.0/16"},
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Parse candidate and whitelist to IPNets
			_, candidateNet, err := net.ParseCIDR(tt.candidate)
			if err != nil {
				t.Fatalf("Failed to parse candidate CIDR: %v", err)
			}

			whitelistNets := mustParseCIDRs(t, tt.whitelist)

			// Test IPNet version
			gotIPNet := IsWhitelistedIPNet(candidateNet, whitelistNets)
			if gotIPNet != tt.expected {
				t.Errorf("IsWhitelistedIPNet(%s, %v) = %v, want %v", tt.candidate, tt.whitelist, gotIPNet, tt.expected)
			}

			// Verify it matches the reference string version
			gotString := refIsWhitelisted(tt.candidate, tt.whitelist)
			if gotIPNet != gotString {
				t.Errorf("IsWhitelistedIPNet(%v) != refIsWhitelisted(%v) for candidate %s", gotIPNet, gotString, tt.candidate)
			}
		})
	}
}

// BenchmarkIsWhitelistedComparison compares the parse-per-call string path
// (the reference oracle refIsWhitelisted, a copy of the deleted IsWhitelisted)
// against the production pre-parsed IPNet hot path IsWhitelistedIPNet.
func BenchmarkIsWhitelistedComparison(b *testing.B) {
	candidate := "192.168.50.0/24"
	whitelist := make([]string, 50)
	for i := 0; i < 50; i++ {
		whitelist[i] = fmt.Sprintf("10.%d.0.0/16", i)
	}

	// Pre-parse for IPNet version
	_, candidateNet, _ := net.ParseCIDR(candidate)
	whitelistNets := mustParseCIDRs(b, whitelist)

	b.Run("IsWhitelisted_String", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = refIsWhitelisted(candidate, whitelist)
		}
	})

	b.Run("IsWhitelistedIPNet", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = IsWhitelistedIPNet(candidateNet, whitelistNets)
		}
	})
}

// TestNewUserAgentMatcher tests the creation of a new UserAgentMatcher
func TestNewUserAgentMatcher(t *testing.T) {
	whitelist := []string{"Mozilla/5.0", "Googlebot/2.1", "# comment", "", "  "}
	blacklist := []string{"sqlmap/1.0", "nmap", "# another comment", "", "  "}

	matcher := NewUserAgentMatcher(whitelist, blacklist)

	if matcher == nil {
		t.Fatal("Expected non-nil matcher")
	}

	// Should have 4 entries (2 whitelist + 2 blacklist, comments and empty strings ignored)
	expectedCount := 4
	if matcher.Count() != expectedCount {
		t.Errorf("Expected %d entries, got %d", expectedCount, matcher.Count())
	}

	// Check the two valid whitelist entries are classified as whitelisted
	for _, ua := range []string{"Mozilla/5.0", "Googlebot/2.1"} {
		if matcher.CheckUserAgent(ua) != UserAgentWhitelist {
			t.Errorf("Expected %q to be whitelisted, got %v", ua, matcher.CheckUserAgent(ua))
		}
	}

	// Check the two valid blacklist entries are classified as blacklisted
	for _, ua := range []string{"sqlmap/1.0", "nmap"} {
		if matcher.CheckUserAgent(ua) != UserAgentBlacklist {
			t.Errorf("Expected %q to be blacklisted, got %v", ua, matcher.CheckUserAgent(ua))
		}
	}
}

// TestUserAgentMatcher_WhitelistPrecedence tests that whitelist takes precedence over blacklist
func TestUserAgentMatcher_WhitelistPrecedence(t *testing.T) {
	whitelist := []string{"Mozilla/5.0"}
	blacklist := []string{"Mozilla/5.0"} // Same pattern in both lists

	matcher := NewUserAgentMatcher(whitelist, blacklist)

	// Whitelist should win
	result := matcher.CheckUserAgent("Mozilla/5.0")
	if result != UserAgentWhitelist {
		t.Errorf("Expected UserAgentWhitelist, got %v", result)
	}

	if result == UserAgentBlacklist {
		t.Error("Expected Mozilla/5.0 to not be blacklisted (whitelist should win)")
	}
}

// TestUserAgentMatcher_ExactMatch tests exact string matching
func TestUserAgentMatcher_ExactMatch(t *testing.T) {
	whitelist := []string{"Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
	blacklist := []string{"sqlmap/1.0"}

	matcher := NewUserAgentMatcher(whitelist, blacklist)

	tests := []struct {
		userAgent string
		expected  UserAgentMatchResult
	}{
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64)", UserAgentWhitelist},
		{"mozilla/5.0 (windows nt 10.0; win64; x64)", UserAgentWhitelist},       // Case insensitive
		{"MOZILLA/5.0 (WINDOWS NT 10.0; WIN64; X64)", UserAgentWhitelist},       // Case insensitive
		{"Mozilla/5.0", UserAgentNotListed},                                     // Partial match should not work
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Extra", UserAgentNotListed}, // Extra content should not match
		{"sqlmap/1.0", UserAgentBlacklist},
		{"SQLMAP/1.0", UserAgentBlacklist}, // Case insensitive
		{"sqlmap/1.1", UserAgentNotListed}, // Different version should not match
		{"Unknown Agent", UserAgentNotListed},
	}

	for _, tt := range tests {
		t.Run(tt.userAgent, func(t *testing.T) {
			result := matcher.CheckUserAgent(tt.userAgent)
			if result != tt.expected {
				t.Errorf("CheckUserAgent(%q) = %v, want %v", tt.userAgent, result, tt.expected)
			}

			// Cross-check whitelist/blacklist classification
			if (result == UserAgentWhitelist) != (tt.expected == UserAgentWhitelist) {
				t.Errorf("whitelist classification for %q = %v, want %v", tt.userAgent, result == UserAgentWhitelist, tt.expected == UserAgentWhitelist)
			}

			if (result == UserAgentBlacklist) != (tt.expected == UserAgentBlacklist) {
				t.Errorf("blacklist classification for %q = %v, want %v", tt.userAgent, result == UserAgentBlacklist, tt.expected == UserAgentBlacklist)
			}
		})
	}
}

// TestUserAgentMatcher_EmptyLists tests behavior with empty lists
func TestUserAgentMatcher_EmptyLists(t *testing.T) {
	tests := []struct {
		name      string
		whitelist []string
		blacklist []string
	}{
		{"Both empty", []string{}, []string{}},
		{"Whitelist empty", []string{}, []string{"test"}},
		{"Blacklist empty", []string{"test"}, []string{}},
		{"Both nil", nil, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher := NewUserAgentMatcher(tt.whitelist, tt.blacklist)

			result := matcher.CheckUserAgent("test")
			if len(tt.blacklist) > 0 && tt.blacklist[0] == "test" {
				if result != UserAgentBlacklist {
					t.Errorf("Expected UserAgentBlacklist, got %v", result)
				}
			} else if len(tt.whitelist) > 0 && tt.whitelist[0] == "test" {
				if result != UserAgentWhitelist {
					t.Errorf("Expected UserAgentWhitelist, got %v", result)
				}
			} else {
				if result != UserAgentNotListed {
					t.Errorf("Expected UserAgentNotListed, got %v", result)
				}
			}
		})
	}
}

// TestUserAgentMatcher_NilMatcher tests behavior with nil matcher
func TestUserAgentMatcher_NilMatcher(t *testing.T) {
	var matcher *UserAgentMatcher

	if matcher.CheckUserAgent("test") != UserAgentNotListed {
		t.Error("Nil matcher should return UserAgentNotListed")
	}

	if matcher.Count() != 0 {
		t.Error("Nil matcher should return 0 for Count")
	}
}

// TestUserAgentMatcher_LargeDataset tests performance with a large dataset
func TestUserAgentMatcher_LargeDataset(t *testing.T) {
	// Create large lists
	whitelist := make([]string, 1000)
	blacklist := make([]string, 1000)

	for i := 0; i < 1000; i++ {
		whitelist[i] = fmt.Sprintf("whitelist-agent-%d", i)
		blacklist[i] = fmt.Sprintf("blacklist-agent-%d", i)
	}

	matcher := NewUserAgentMatcher(whitelist, blacklist)

	// Test lookup performance
	testCases := []string{
		"whitelist-agent-500", // Should be whitelisted
		"blacklist-agent-500", // Should be blacklisted
		"unknown-agent",       // Should not be listed
	}

	for _, userAgent := range testCases {
		result := matcher.CheckUserAgent(userAgent)
		// Just make sure it doesn't crash or hang
		if result < UserAgentBlacklist || result > UserAgentWhitelist {
			t.Errorf("Invalid result for %s: %v", userAgent, result)
		}
	}

	// Verify counts
	expectedTotal := 2000
	if matcher.Count() != expectedTotal {
		t.Errorf("Expected %d total entries, got %d", expectedTotal, matcher.Count())
	}
}

// TestUserAgentMatcher_SpecialCharacters tests handling of special characters
func TestUserAgentMatcher_SpecialCharacters(t *testing.T) {
	whitelist := []string{
		"Mozilla/5.0 (compatible; Test+Bot/1.0; +http://example.com)",
		"Agent with spaces and (parentheses)",
		"Agent-with-dashes_and_underscores",
		"Agent.with.dots",
		"Agent,with,commas",
		"Agent;with;semicolons",
		"Agent:with:colons",
		"Agent\"with\"quotes",
		"Agent'with'apostrophes",
		"Agent[with]brackets",
		"Agent{with}braces",
		"Agent=with=equals",
		"Agent?with?questions",
		"Agent&with&ampersands",
		"Agent%20with%20encoded",
		"Agent|with|pipes",
		"Agent\\with\\backslashes",
		"Agent/with/slashes",
		"Agent*with*asterisks",
		"Agent#with#hashes",
		"Agent@with@ats",
		"Agent$with$dollars",
		"Agent^with^carets",
		"Agent~with~tildes",
		"Agent`with`backticks",
	}

	blacklist := []string{
		"sqlmap/1.0; (Attack Tool)",
		"<script>alert('xss')</script>",
		"../../etc/passwd",
		"' OR 1=1 --",
		"SELECT * FROM users",
	}

	matcher := NewUserAgentMatcher(whitelist, blacklist)

	// Test all whitelist entries
	for _, userAgent := range whitelist {
		if matcher.CheckUserAgent(userAgent) != UserAgentWhitelist {
			t.Errorf("Expected %q to be whitelisted", userAgent)
		}
	}

	// Test all blacklist entries
	for _, userAgent := range blacklist {
		if matcher.CheckUserAgent(userAgent) != UserAgentBlacklist {
			t.Errorf("Expected %q to be blacklisted", userAgent)
		}
	}
}

// TestUserAgentMatcher_Unicode tests handling of Unicode characters
func TestUserAgentMatcher_Unicode(t *testing.T) {
	whitelist := []string{
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 测试浏览器",
		"Agent with émojis 🤖🔍",
		"Агент с кириллицей",
		"エージェント with 日本語",
		"Agent with العربية",
	}

	blacklist := []string{
		"恶意代理 malicious",
		"вредоносный агент",
		"악성 에이전트",
	}

	matcher := NewUserAgentMatcher(whitelist, blacklist)

	// Test all entries
	for _, userAgent := range whitelist {
		if matcher.CheckUserAgent(userAgent) != UserAgentWhitelist {
			t.Errorf("Expected %q to be whitelisted", userAgent)
		}
	}

	for _, userAgent := range blacklist {
		if matcher.CheckUserAgent(userAgent) != UserAgentBlacklist {
			t.Errorf("Expected %q to be blacklisted", userAgent)
		}
	}

	// Test case insensitive matching with Unicode
	if matcher.CheckUserAgent("MOZILLA/5.0 (MACINTOSH; INTEL MAC OS X 10_15_7) APPLEWEBKIT/537.36 测试浏览器") != UserAgentWhitelist {
		t.Error("Unicode case insensitive matching failed")
	}
}

// TestUserAgentMatcher_CommentsAndWhitespace tests proper handling of comments and whitespace
func TestUserAgentMatcher_CommentsAndWhitespace(t *testing.T) {
	whitelist := []string{
		"  Mozilla/5.0  ",   // Leading/trailing spaces
		"\tGooglebot/2.1\t", // Leading/trailing tabs
		"# This is a comment",
		"",            // Empty string
		"   ",         // Only whitespace
		"Valid Agent", // Valid entry
		"# Another comment",
		"  # Comment with leading space",
	}

	blacklist := []string{
		"  sqlmap/1.0  ", // Leading/trailing spaces
		"# Comment",
		"",
		"nmap", // Valid entry
	}

	matcher := NewUserAgentMatcher(whitelist, blacklist)

	// Should only have valid entries (3 whitelist + 2 blacklist)
	expectedTotal := 5
	if matcher.Count() != expectedTotal {
		t.Errorf("Expected %d entries, got %d", expectedTotal, matcher.Count())
	}

	// Test that trimmed versions work
	if matcher.CheckUserAgent("Mozilla/5.0") != UserAgentWhitelist {
		t.Error("Expected Mozilla/5.0 to be whitelisted (trimmed)")
	}

	if matcher.CheckUserAgent("Googlebot/2.1") != UserAgentWhitelist {
		t.Error("Expected Googlebot/2.1 to be whitelisted (trimmed)")
	}

	if matcher.CheckUserAgent("Valid Agent") != UserAgentWhitelist {
		t.Error("Expected Valid Agent to be whitelisted")
	}

	if matcher.CheckUserAgent("sqlmap/1.0") != UserAgentBlacklist {
		t.Error("Expected sqlmap/1.0 to be blacklisted (trimmed)")
	}

	if matcher.CheckUserAgent("nmap") != UserAgentBlacklist {
		t.Error("Expected nmap to be blacklisted")
	}

	// Comments should not be in the matcher
	if matcher.CheckUserAgent("# This is a comment") != UserAgentNotListed {
		t.Error("Comments should not be added to matcher")
	}

	if matcher.CheckUserAgent("# Comment") != UserAgentNotListed {
		t.Error("Comments should not be added to matcher")
	}
}

func TestComposeBanLists(t *testing.T) {
	tests := []struct {
		name            string
		activeBans      []string
		manualBlacklist []string
		whitelist       []string
		wantBans        []string
		wantBlacklist   []string
	}{
		{
			name:            "empty whitelist leaves both unchanged",
			activeBans:      []string{"10.0.0.0/24"},
			manualBlacklist: []string{"203.0.113.0/24"},
			whitelist:       nil,
			wantBans:        []string{"10.0.0.0/24"},
			wantBlacklist:   []string{"203.0.113.0/24"},
		},
		{
			name:            "whitelist fully covers manual blacklist entry",
			activeBans:      []string{"10.0.0.0/24"},
			manualBlacklist: []string{"192.168.1.0/24"},
			whitelist:       []string{"192.168.0.0/16"},
			wantBans:        []string{"10.0.0.0/24"},
			wantBlacklist:   nil,
		},
		{
			name:            "whitelist inside manual blacklist is subtracted",
			activeBans:      nil,
			manualBlacklist: []string{"10.0.0.0/16"},
			whitelist:       []string{"10.0.1.0/24"},
			wantBans:        nil,
			wantBlacklist: []string{
				"10.0.0.0/24", "10.0.2.0/23", "10.0.4.0/22",
				"10.0.8.0/21", "10.0.16.0/20", "10.0.32.0/19",
				"10.0.64.0/18", "10.0.128.0/17",
			},
		},
		{
			name:            "whitelist fully covers active ban",
			activeBans:      []string{"172.16.5.0/24"},
			manualBlacklist: nil,
			whitelist:       []string{"172.16.0.0/12"},
			wantBans:        nil,
			wantBlacklist:   nil,
		},
		{
			name:            "whitelist inside active ban is subtracted",
			activeBans:      []string{"10.5.5.0/24"},
			manualBlacklist: nil,
			whitelist:       []string{"10.5.5.0/25"},
			wantBans:        []string{"10.5.5.128/25"},
			wantBlacklist:   nil,
		},
		{
			name:            "empty inputs give empty outputs",
			activeBans:      nil,
			manualBlacklist: nil,
			whitelist:       []string{"10.0.0.0/8"},
			wantBans:        nil,
			wantBlacklist:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotBans, gotBlacklist := ComposeBanLists(tt.activeBans, tt.manualBlacklist, tt.whitelist)
			if !equalCIDRSets(gotBans, tt.wantBans) {
				t.Errorf("publishBans = %v, want %v", gotBans, tt.wantBans)
			}
			if !equalCIDRSets(gotBlacklist, tt.wantBlacklist) {
				t.Errorf("publishBlacklist = %v, want %v", gotBlacklist, tt.wantBlacklist)
			}
		})
	}
}

func equalCIDRSets(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	set := make(map[string]bool, len(got))
	for _, c := range got {
		set[c] = true
	}
	for _, c := range want {
		if !set[c] {
			return false
		}
	}
	return true
}

// TestDropFullyWhitelistedNoFragmentation is the regression guard for the jail
// blowup: many scattered /32 whitelist entries inside a jailed range must NOT
// fragment that range. The old pre-jail path called RemoveWhitelisted here,
// which subtracted every /32 hole and exploded a single /16 into thousands of
// gap CIDRs (the filtered list grew past its input, producing the nonsensical
// negative "prevented N CIDRs" count and a super-linear jail update). The
// remedy keeps partially-overlapping ranges whole and only drops ranges the
// whitelist fully covers.
func TestDropFullyWhitelistedNoFragmentation(t *testing.T) {
	const holes = 5000
	jail := []string{"10.0.0.0/16"}
	whitelist := make([]string, 0, holes)
	for i := 0; i < holes; i++ {
		whitelist = append(whitelist, fmt.Sprintf("10.0.%d.%d/32", i/256, i%256))
	}

	kept, dropped := DropFullyWhitelisted(jail, whitelist)

	// The jailed /16 is only partially covered, so it stays whole and is kept.
	if len(kept) != 1 || kept[0] != "10.0.0.0/16" {
		t.Fatalf("DropFullyWhitelisted fragmented or dropped a partially-covered range: got %v (len %d), want [10.0.0.0/16]", kept, len(kept))
	}
	if dropped != 0 {
		t.Errorf("dropped = %d, want 0 (no fully-covered range)", dropped)
	}

	// Demonstrate the bug being prevented: the old subtracting path explodes
	// the same input into far more entries than it received (hence the negative
	// count). This is exactly what we must NOT feed into the jail update.
	if frag := RemoveWhitelisted(jail, whitelist); len(frag) <= len(jail) {
		t.Skipf("RemoveWhitelisted no longer fragments (%d entries); contrast no longer demonstrable", len(frag))
	}

	// Invariant preserved: the whitelist still wins at the publish choke point,
	// so none of the whitelisted /32s can end up in the emitted ban list even
	// though the /16 was jailed whole.
	publishBans, _ := ComposeBanLists(kept, nil, whitelist)
	for _, w := range whitelist {
		if refIsWhitelisted(w, publishBans) {
			t.Fatalf("whitelisted entry %s is covered by a published ban range %v", w, publishBans)
		}
	}
}

// TestDropFullyWhitelistedDropsCovered checks the count is correct: ranges
// fully inside the whitelist are dropped and counted, partial and disjoint
// ranges are kept whole.
func TestDropFullyWhitelistedDropsCovered(t *testing.T) {
	jail := []string{
		"10.0.5.0/24",    // fully inside whitelisted 10.0.5.0/24 -> dropped
		"10.0.0.0/16",    // only partially covered -> kept whole
		"192.168.1.0/24", // disjoint -> kept
	}
	whitelist := []string{"10.0.5.0/24", "10.0.7.42/32"}

	kept, dropped := DropFullyWhitelisted(jail, whitelist)

	if dropped != 1 {
		t.Errorf("dropped = %d, want 1", dropped)
	}
	wantKept := map[string]bool{"10.0.0.0/16": true, "192.168.1.0/24": true}
	if len(kept) != len(wantKept) {
		t.Fatalf("kept = %v, want keys %v", kept, wantKept)
	}
	for _, c := range kept {
		if !wantKept[c] {
			t.Errorf("unexpected kept CIDR %s", c)
		}
	}
}

func BenchmarkDropFullyWhitelisted(b *testing.B) {
	const holes = 5000
	jail := []string{"10.0.0.0/16", "10.1.0.0/16", "10.2.0.0/16"}
	whitelist := make([]string, 0, holes)
	for i := 0; i < holes; i++ {
		whitelist = append(whitelist, fmt.Sprintf("10.0.%d.%d/32", i/256, i%256))
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DropFullyWhitelisted(jail, whitelist)
	}
}
