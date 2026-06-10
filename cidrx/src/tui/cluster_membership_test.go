package tui

import (
	"reflect"
	"testing"
)

// intervalsEqual compares interval slices treating nil and empty as equal,
// since buildClusterIntervals legitimately returns either for "no ranges".
func intervalsEqual(got, want []ipInterval) bool {
	if len(got) == 0 && len(want) == 0 {
		return true
	}
	return reflect.DeepEqual(got, want)
}

// TestBuildClusterIntervalsCoalesce pins the parse+sort+coalesce behavior of
// buildClusterIntervals with hand-computed interval sets, including adjacency
// at both ends of the address space, containment, duplicates, /0, and invalid
// or non-IPv4 inputs.
func TestBuildClusterIntervalsCoalesce(t *testing.T) {
	cases := []struct {
		name      string
		cidrs     []string
		want      []ipInterval
		probesIn  []uint32
		probesOut []uint32
	}{
		{
			name:      "empty",
			cidrs:     nil,
			want:      nil,
			probesOut: []uint32{0x00000000, 0xFFFFFFFF},
		},
		{
			name:      "single",
			cidrs:     []string{"10.0.0.0/24"},
			want:      []ipInterval{{0x0A000000, 0x0A0000FF}},
			probesIn:  []uint32{0x0A000000, 0x0A0000FF},
			probesOut: []uint32{0x09FFFFFF, 0x0A000100},
		},
		{
			name:      "adjacent_merge",
			cidrs:     []string{"10.0.0.0/25", "10.0.0.128/25"},
			want:      []ipInterval{{0x0A000000, 0x0A0000FF}},
			probesIn:  []uint32{0x0A00007F, 0x0A000080},
			probesOut: []uint32{0x09FFFFFF, 0x0A000100},
		},
		{
			name:      "overlapping",
			cidrs:     []string{"10.0.0.0/24", "10.0.0.128/25"},
			want:      []ipInterval{{0x0A000000, 0x0A0000FF}},
			probesIn:  []uint32{0x0A000000, 0x0A000080, 0x0A0000FF},
			probesOut: []uint32{0x0A000100},
		},
		{
			name:      "duplicates",
			cidrs:     []string{"192.168.1.0/24", "192.168.1.0/24"},
			want:      []ipInterval{{0xC0A80100, 0xC0A801FF}},
			probesIn:  []uint32{0xC0A80100, 0xC0A801FF},
			probesOut: []uint32{0xC0A800FF, 0xC0A80200},
		},
		{
			name:      "contained",
			cidrs:     []string{"10.0.0.0/8", "10.20.0.0/16"},
			want:      []ipInterval{{0x0A000000, 0x0AFFFFFF}},
			probesIn:  []uint32{0x0A000000, 0x0A140000, 0x0AFFFFFF},
			probesOut: []uint32{0x09FFFFFF, 0x0B000000},
		},
		{
			name:      "adjacent_bottom",
			cidrs:     []string{"0.0.0.0/31", "0.0.0.2/31"},
			want:      []ipInterval{{0x00000000, 0x00000003}},
			probesIn:  []uint32{0x00000000},
			probesOut: []uint32{0x00000004},
		},
		{
			name:      "adjacent_near_top",
			cidrs:     []string{"255.255.255.252/31", "255.255.255.254/31"},
			want:      []ipInterval{{0xFFFFFFFC, 0xFFFFFFFF}},
			probesIn:  []uint32{0xFFFFFFFC, 0xFFFFFFFF},
			probesOut: []uint32{0xFFFFFFFB},
		},
		{
			// The overflow guard's adjacency clause at cluster_membership.go:71
			// (last.End != ^uint32(0) before computing last.End+1) is
			// short-circuited by the overlap clause when last.End==0xFFFFFFFF —
			// it is defensive and unreachable; this row covers the surrounding
			// merge at the top of the space, not that branch.
			name:      "top_of_space_overlapped",
			cidrs:     []string{"128.0.0.0/1", "255.255.255.255/32"},
			want:      []ipInterval{{0x80000000, 0xFFFFFFFF}},
			probesIn:  []uint32{0x80000000, 0xFFFFFFFF},
			probesOut: []uint32{0x7FFFFFFF, 0x00000000},
		},
		{
			name:      "gap_not_merged",
			cidrs:     []string{"10.0.0.0/25", "10.0.1.0/24"},
			want:      []ipInterval{{0x0A000000, 0x0A00007F}, {0x0A000100, 0x0A0001FF}},
			probesIn:  []uint32{0x0A000000, 0x0A00007F, 0x0A000100, 0x0A0001FF},
			probesOut: []uint32{0x0A000080, 0x0A000200},
		},
		{
			name:  "unsorted",
			cidrs: []string{"200.0.0.0/8", "10.0.0.0/8", "100.0.0.0/8"},
			want: []ipInterval{
				{0x0A000000, 0x0AFFFFFF},
				{0x64000000, 0x64FFFFFF},
				{0xC8000000, 0xC8FFFFFF},
			},
			probesIn:  []uint32{0x0A000000, 0x64FFFFFF, 0xC8000001},
			probesOut: []uint32{0x0B000000, 0x63FFFFFF, 0xC9000000},
		},
		{
			name:      "full_space",
			cidrs:     []string{"0.0.0.0/0"},
			want:      []ipInterval{{0x00000000, 0xFFFFFFFF}},
			probesIn:  []uint32{0x00000000, 0xFFFFFFFF, 0x12345678},
			probesOut: nil,
		},
		{
			name:      "full_space_plus_subset",
			cidrs:     []string{"0.0.0.0/0", "10.0.0.0/8"},
			want:      []ipInterval{{0x00000000, 0xFFFFFFFF}},
			probesIn:  []uint32{0x00000000, 0x0A000000, 0xFFFFFFFF},
			probesOut: nil,
		},
		{
			name:      "invalid_skipped",
			cidrs:     []string{"garbage", "2001:db8::/32"},
			want:      nil,
			probesOut: []uint32{0x00000000, 0x20010DB8, 0xFFFFFFFF},
		},
		{
			name:      "invalid_skipped_mixed",
			cidrs:     []string{"garbage", "2001:db8::/32", "10.0.0.0/24"},
			want:      []ipInterval{{0x0A000000, 0x0A0000FF}},
			probesIn:  []uint32{0x0A000000, 0x0A0000FF},
			probesOut: []uint32{0x09FFFFFF, 0x0A000100},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ci := buildClusterIntervals(newClusterSet(tc.cidrs...))
			if !intervalsEqual(ci.intervals, tc.want) {
				t.Fatalf("intervals = %v, want %v", ci.intervals, tc.want)
			}
			for _, p := range tc.probesIn {
				if !ci.Contains(p) {
					t.Errorf("Contains(0x%08X) = false, want true", p)
				}
			}
			for _, p := range tc.probesOut {
				if ci.Contains(p) {
					t.Errorf("Contains(0x%08X) = true, want false", p)
				}
			}
		})
	}

	t.Run("nil_cluster_set", func(t *testing.T) {
		ci := buildClusterIntervals(nil)
		if ci == nil {
			t.Fatal("buildClusterIntervals(nil) returned nil, want empty intervals")
		}
		if len(ci.intervals) != 0 {
			t.Errorf("intervals = %v, want empty", ci.intervals)
		}
		if ci.Contains(0) || ci.Contains(0xFFFFFFFF) {
			t.Error("nil cluster set must contain nothing")
		}
	})
}

// TestClusterIntervalsContainsNilAndEmpty pins the nil/zero-value safety of
// the clusterIntervals methods (both are documented nil-safe pointer
// receivers).
func TestClusterIntervalsContainsNilAndEmpty(t *testing.T) {
	var zero clusterIntervals
	for _, ip := range []uint32{0x00000000, 0x7FFFFFFF, 0xFFFFFFFF} {
		if zero.Contains(ip) {
			t.Errorf("zero-value Contains(0x%08X) = true, want false", ip)
		}
	}
	if !zero.empty() {
		t.Error("zero-value empty() = false, want true")
	}

	var nilCI *clusterIntervals
	for _, ip := range []uint32{0x00000000, 0x7FFFFFFF, 0xFFFFFFFF} {
		if nilCI.Contains(ip) {
			t.Errorf("nil receiver Contains(0x%08X) = true, want false", ip)
		}
	}
	if !nilCI.empty() {
		t.Error("nil receiver empty() = false, want true")
	}
}

// TestMembershipEquivalenceLowPrefixDeterministic checks the fast interval
// membership against net.Contains for explicit low-prefix (wide) cluster sets
// at hand-picked boundary IPs — the cases a random corpus is least likely to
// produce.
func TestMembershipEquivalenceLowPrefixDeterministic(t *testing.T) {
	sets := [][]string{
		{"0.0.0.0/0"},
		{"0.0.0.0/1"},
		{"128.0.0.0/1"},
		{"64.0.0.0/2", "0.0.0.0/8"},
	}
	boundaryIPs := []uint32{
		0x00000000, 0x00000001, 0x3FFFFFFF, 0x40000000,
		0x7FFFFFFF, 0x80000000, 0xFFFFFFFE, 0xFFFFFFFF,
	}

	for _, cidrStrs := range sets {
		intervals := buildClusterIntervals(newClusterSet(cidrStrs...))
		refNets := mustCIDRs(t, cidrStrs...)
		for _, ip := range boundaryIPs {
			got := intervals.Contains(ip)
			want := bruteContains(refNets, ip)
			if got != want {
				t.Errorf("set %v ip 0x%08X: interval=%v net.Contains=%v",
					cidrStrs, ip, got, want)
			}
		}
	}
}
