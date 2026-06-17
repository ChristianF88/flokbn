package cidr

import (
	"net"
	"testing"
)

func FuzzNumericCIDR_String(f *testing.F) {
	seeds := []struct {
		ip        uint32
		prefixLen uint8
	}{
		{0xC0A80100, 24}, // 192.168.1.0/24
		{0x0A000000, 8},  // 10.0.0.0/8
		{0, 0},           // 0.0.0.0/0
		{0xFFFFFFFF, 32}, // 255.255.255.255/32
		{0x01010101, 16}, // 1.1.1.1/16
	}
	for _, s := range seeds {
		f.Add(s.ip, s.prefixLen)
	}

	f.Fuzz(func(t *testing.T, ip uint32, prefixLen uint8) {
		nc := NumericCIDR{IP: ip, PrefixLen: prefixLen}
		// Should not panic
		result := nc.String()
		if prefixLen <= 32 && result == "" {
			t.Error("String() returned empty for valid prefix length")
		}
	})
}

// FuzzMergeCIDRs feeds MergeIPNets up to four CIDRs at once so the merge /
// containment / collapse logic is actually exercised (the old single-CIDR fuzzer
// returned at len<=1 and never reached the fast-path overlap check — which is why
// the top-of-space prevEnd+1 wraparound went uncaught). Post-merge invariants:
//
//	(a) results are pairwise non-overlapping (after sorting by start, no two
//	    output ranges share an address: prevEnd < currStart, using uint64 to
//	    avoid wrap at 0xFFFFFFFF). Note adjacency (prevEnd+1 == currStart) is
//	    legitimately allowed: two adjacent CIDRs of unequal/unaligned size cannot
//	    always be expressed as a single larger CIDR (e.g. 10.0.0.0/7 +
//	    12.0.0.0/10), so MergeIPNets correctly keeps them separate.
//	(b) the covered address set (union of [start,end] intervals) is loss-free and
//	    gain-free: it equals the union of the inputs;
//	(c) no two adjacent output CIDRs of EQUAL prefix that form an aligned
//	    power-of-two pair remain un-merged (the collapse must be complete for the
//	    mergeable case — this is what the top-of-space bug broke).
//
// IPv4-only: entries whose parsed mask is not 4 bytes are skipped, never fed into
// MergeIPNets (which reads the mask via BigEndian.Uint32).
func FuzzMergeCIDRs(f *testing.F) {
	type quad [4]string
	seeds := []quad{
		// The bug-triggering seeds: replayed by plain `go test` (no -fuzz needed).
		{"0.0.0.0/0", "10.0.0.0/8", "", ""},                  // /0 contains a range
		{"255.255.255.0/24", "255.255.255.128/25", "", ""},   // top-touching pair
		{"255.255.255.254/31", "255.255.255.255/32", "", ""}, // top /31 + top /32
		// Ordinary mergeable / non-mergeable mixes.
		{"192.168.0.0/24", "192.168.1.0/24", "10.0.0.0/8", "172.16.0.0/12"},
		{"10.0.0.0/16", "10.0.0.0/8", "192.168.1.0/25", "192.168.1.0/24"},
		{"invalid", "", "1.1.1.1/32", "2.2.2.0/24"},
	}
	for _, s := range seeds {
		f.Add(s[0], s[1], s[2], s[3])
	}

	f.Fuzz(func(t *testing.T, a, b, c, d string) {
		var nets []*net.IPNet
		for _, s := range []string{a, b, c, d} {
			_, ipNet, err := net.ParseCIDR(s)
			if err != nil {
				continue
			}
			// IPv4-only: skip non-4-byte masks (IPv6 / IPv4-mapped).
			if len(ipNet.Mask) != 4 {
				continue
			}
			nets = append(nets, ipNet)
		}
		if len(nets) == 0 {
			t.Skip()
		}

		// Union of the inputs as a uint64 interval set.
		inputUnion := unionOf(t, nets)

		merged := MergeIPNets(nets)

		// All merged outputs must remain IPv4 (4-byte mask).
		for _, n := range merged {
			if len(n.Mask) != 4 {
				t.Fatalf("merge produced a non-IPv4 result: %v", n)
			}
		}

		// Extract merged output intervals + prefix length (uint64, no wrap).
		type out struct {
			start, end uint64
			prefix     int
		}
		outs := make([]out, 0, len(merged))
		for _, n := range merged {
			s, e := rangeOf(t, n)
			p, _ := n.Mask.Size()
			outs = append(outs, out{s, e, p})
		}
		// Sort by start (small slices; insertion sort).
		for i := 1; i < len(outs); i++ {
			for j := i; j > 0 && outs[j-1].start > outs[j].start; j-- {
				outs[j-1], outs[j] = outs[j], outs[j-1]
			}
		}

		// Invariant (a): pairwise NON-OVERLAPPING (no shared address):
		// prevEnd < currStart (uint64 so prevEnd == 0xFFFFFFFF does not wrap).
		// Adjacency is allowed because two adjacent CIDRs of unequal/unaligned
		// size cannot always be expressed as a single larger CIDR.
		for i := 1; i < len(outs); i++ {
			if outs[i-1].end >= outs[i].start {
				t.Fatalf("merge left OVERLAPPING ranges: %v then %v (inputs a=%q b=%q c=%q d=%q)",
					outs[i-1], outs[i], a, b, c, d)
			}
			// Invariant (c): no two EQUAL-prefix, aligned, adjacent CIDRs remain —
			// those MUST collapse into the next-larger CIDR. This is exactly the
			// case the top-of-space wraparound bug broke.
			if outs[i-1].prefix == outs[i].prefix && outs[i-1].end+1 == outs[i].start {
				blockSize := uint64(1) << (32 - outs[i-1].prefix)
				if outs[i-1].start%(blockSize*2) == 0 {
					t.Fatalf("merge left a collapsible adjacent pair: %v then %v (prefix /%d) (inputs a=%q b=%q c=%q d=%q)",
						outs[i-1], outs[i], outs[i-1].prefix, a, b, c, d)
				}
			}
		}

		// Invariant (b): the merged union equals the input union (loss-free,
		// gain-free).
		mu := make([]covInterval, len(outs))
		for i, o := range outs {
			mu[i] = covInterval{o.start, o.end}
		}
		mergedUnion := mergeCov(mu)
		if !sameCoverage(inputUnion, mergedUnion) {
			t.Fatalf("merge changed coverage.\n inputs a=%q b=%q c=%q d=%q\n inputUnion=%v\n mergedUnion=%v",
				a, b, c, d, inputUnion, mergedUnion)
		}
	})
}

// covInterval is a normalized [start,end] uint64 interval used to compare
// coverage sets independent of CIDR shape.
type covInterval struct{ start, end uint64 }

// unionOf computes the merged union of the inputs' [start,end] intervals.
func unionOf(t *testing.T, nets []*net.IPNet) []covInterval {
	ivs := make([]covInterval, 0, len(nets))
	for _, n := range nets {
		s, e := rangeOf(t, n)
		ivs = append(ivs, covInterval{s, e})
	}
	return mergeCov(ivs)
}

// mergeCov sorts and merges overlapping/adjacent uint64 intervals.
func mergeCov(ivs []covInterval) []covInterval {
	if len(ivs) <= 1 {
		return ivs
	}
	for i := 1; i < len(ivs); i++ {
		for j := i; j > 0 && ivs[j-1].start > ivs[j].start; j-- {
			ivs[j-1], ivs[j] = ivs[j], ivs[j-1]
		}
	}
	out := []covInterval{ivs[0]}
	for _, cur := range ivs[1:] {
		last := &out[len(out)-1]
		if cur.start <= last.end+1 { // overlap or adjacency (uint64, no wrap)
			if cur.end > last.end {
				last.end = cur.end
			}
		} else {
			out = append(out, cur)
		}
	}
	return out
}

// sameCoverage reports whether two merged interval sets cover the same addresses.
func sameCoverage(a, b []covInterval) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
