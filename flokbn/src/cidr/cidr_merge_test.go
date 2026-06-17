package cidr

import (
	"net"
	"sort"
	"testing"
)

// TestMergeIPNets_TopOfSpace is the regression guard for URGENT-07 finding 1:
// the MergeIPNets fast-path used `currStart <= prevEnd+1` to detect overlap, but
// when the previous range already reaches 0xFFFFFFFF (e.g. 0.0.0.0/0, or any
// range touching the top of IPv4 space) prevEnd+1 wraps to 0, so the comparison
// became `currStart <= 0` which is false for every non-zero start. The sorted
// input was then returned VERBATIM (no removeContained/collapse), leaving
// overlapping or containing ranges un-merged at the top of the address space.
//
// Each case below FAILS on the pre-fix code (returns both inputs) and passes
// after the `prevEnd == 0xFFFFFFFF || ...` guard is added.
func TestMergeIPNets_TopOfSpace(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			// /0 reaches 0xFFFFFFFF, so prevEnd+1 wraps. The contained 10.0.0.0/8
			// must collapse into the /0.
			name:     "default route contains range",
			input:    []string{"0.0.0.0/0", "10.0.0.0/8"},
			expected: []string{"0.0.0.0/0"},
		},
		{
			// The first range ends exactly at 0xFFFFFFFE (255.255.255.254/31 covers
			// .254-.255), so prevEnd is 0xFFFFFFFF and +1 wraps. Adjacent/overlapping
			// pair must merge.
			name:     "top /31 contains top /32",
			input:    []string{"255.255.255.254/31", "255.255.255.255/32"},
			expected: []string{"255.255.255.254/31"},
		},
		{
			// 255.255.255.0/24 reaches 0xFFFFFFFF; the contained /25 must collapse.
			name:     "top /24 contains top /25",
			input:    []string{"255.255.255.0/24", "255.255.255.128/25"},
			expected: []string{"255.255.255.0/24"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ipNetsToStrings(MergeIPNets(mustParseCIDRs(t, tt.input)))
			sort.Strings(got)
			want := append([]string(nil), tt.expected...)
			sort.Strings(want)
			if len(got) != len(want) {
				t.Fatalf("MergeIPNets(%v) = %v, want %v", tt.input, got, want)
			}
			for i := range want {
				if got[i] != want[i] {
					t.Fatalf("MergeIPNets(%v) = %v, want %v", tt.input, got, want)
				}
			}
		})
	}
}

// rangeOf parses an IPv4 CIDR into its inclusive [start,end] as uint64 (wide
// enough to never wrap at the 0xFFFFFFFF boundary), for the fuzz invariants.
func rangeOf(t *testing.T, n *net.IPNet) (start, end uint64) {
	t.Helper()
	v4 := n.IP.To4()
	if v4 == nil || len(n.Mask) != 4 {
		t.Fatalf("non-IPv4 net reached invariant check: %v", n)
	}
	s := uint64(v4[0])<<24 | uint64(v4[1])<<16 | uint64(v4[2])<<8 | uint64(v4[3])
	m := uint64(n.Mask[0])<<24 | uint64(n.Mask[1])<<16 | uint64(n.Mask[2])<<8 | uint64(n.Mask[3])
	return s, s | (^m & 0xFFFFFFFF)
}
