package cidr

import (
	"math/rand"
	"reflect"
	"sort"
	"testing"
)

// TestMergeCIDRs_MultiLevelCollapse covers merges that need more than two
// levels of sibling collapsing. The old collapseCIDRs made one greedy pass
// plus exactly one extra pass, so a chain where each merge enables the next
// one further LEFT stopped early and left two adjacent, aligned, equal-prefix
// ranges un-merged (10.0.0.0/24 + 10.0.1.0/24 in the first case).
func TestMergeCIDRs_MultiLevelCollapse(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "three levels",
			input:    []string{"10.0.0.0/24", "10.0.1.0/25", "10.0.1.128/26", "10.0.1.192/26"},
			expected: []string{"10.0.0.0/23"},
		},
		{
			name:     "three levels, unsorted input",
			input:    []string{"10.0.1.192/26", "10.0.1.0/25", "10.0.0.0/24", "10.0.1.128/26"},
			expected: []string{"10.0.0.0/23"},
		},
		{
			name: "six levels down to /32",
			input: []string{
				"10.0.0.0/27", "10.0.0.32/28", "10.0.0.48/29", "10.0.0.56/30",
				"10.0.0.60/31", "10.0.0.62/32", "10.0.0.63/32",
			},
			expected: []string{"10.0.0.0/26"},
		},
		{
			name: "whole address space from a /1 down to two /32",
			input: func() []string {
				// 0.0.0.0/1, 128.0.0.0/2, 192.0.0.0/3, ... , 255.255.255.254/32,
				// 255.255.255.255/32: every merge enables the next one to its left.
				var in []string
				var start uint32
				for p := 1; p <= 32; p++ {
					in = append(in, NumericCIDR{IP: start, PrefixLen: uint8(p)}.String())
					start += uint32(1) << (32 - p)
				}
				return append(in, "255.255.255.255/32")
			}(),
			expected: []string{"0.0.0.0/0"},
		},
		{
			name:     "cascade stops at an unaligned neighbour",
			input:    []string{"10.0.1.0/24", "10.0.2.0/25", "10.0.2.128/26", "10.0.2.192/26"},
			expected: []string{"10.0.1.0/24", "10.0.2.0/24"},
		},
		{
			name:     "cascade next to an unrelated range",
			input:    []string{"10.0.0.0/24", "10.0.1.0/25", "10.0.1.128/26", "10.0.1.192/26", "192.168.0.0/16"},
			expected: []string{"10.0.0.0/23", "192.168.0.0/16"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mergeBoth(t, tt.input)
			sort.Strings(got)
			want := append([]string(nil), tt.expected...)
			sort.Strings(want)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("MergeCIDRs(%v) = %v, want %v", tt.input, got, want)
			}
		})
	}
}

// TestMergeCIDRs_MatchesCanonicalDecomposition is a randomized differential
// check: for CIDR inputs the fully merged result is unique - it is the minimal
// CIDR decomposition of every maximal interval of the input union. Compare
// MergeCIDRs against that reference (built from appendOptimalNumeric on the
// merged union) over inputs drawn from a small address window, so adjacency,
// containment and multi-level sibling chains are all dense.
func TestMergeCIDRs_MatchesCanonicalDecomposition(t *testing.T) {
	rng := rand.New(rand.NewSource(20240611))
	for iter := 0; iter < 5000; iter++ {
		n := 1 + rng.Intn(24)
		in := make([]string, 0, n)
		for i := 0; i < n; i++ {
			prefix := 22 + rng.Intn(11) // /22../32
			// Window: 10.0.0.0/21, plus an occasional top-of-space range.
			base := uint32(0x0A000000) + uint32(rng.Intn(1<<11))
			if rng.Intn(16) == 0 {
				base = 0xFFFFF800 + uint32(rng.Intn(1<<11))
			}
			base &^= uint32(1)<<(32-prefix) - 1
			in = append(in, NumericCIDR{IP: base, PrefixLen: uint8(prefix)}.String())
		}

		var want []string
		for _, iv := range unionOf(t, mustParseCIDRs(t, in)) {
			for _, nc := range appendOptimalNumeric(nil, uint32(iv.start), uint32(iv.end)) {
				want = append(want, nc.String())
			}
		}
		got := mergeBoth(t, in)
		sort.Strings(got)
		sort.Strings(want)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("iteration %d: MergeCIDRs(%v)\n got  %v\n want %v", iter, in, got, want)
		}
	}
}
