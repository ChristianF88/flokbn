package trie

import (
	"math/rand"
	"net"
	"testing"

	"github.com/ChristianF88/flokbn/cidr"
)

// TestCountInCIDR_MatchesCountInRangeIPNet holds the numeric prefix walk to the
// range-intersection count it stands in for: every prefix length around
// addresses inside, next to and far from the inserted IPs, on tries built both
// ways and after deletions.
func TestCountInCIDR_MatchesCountInRangeIPNet(t *testing.T) {
	rng := rand.New(rand.NewSource(99))

	check := func(tr *Trie, ip uint32, prefix int) {
		t.Helper()
		nc := cidr.NumericCIDR{IP: ip, PrefixLen: uint8(prefix)}
		_, ipNet, err := net.ParseCIDR(nc.String())
		if err != nil {
			t.Fatalf("ParseCIDR(%s): %v", nc, err)
		}
		if got, want := tr.CountInCIDR(nc), tr.CountInRangeIPNet(ipNet); got != want {
			t.Fatalf("CountInCIDR(%s) = %d, CountInRangeIPNet = %d", nc, got, want)
		}
	}

	for round := 0; round < 40; round++ {
		// A few dense blocks plus scattered addresses, with repeats.
		var ips []uint32
		for b := 0; b < 1+rng.Intn(4); b++ {
			base := rng.Uint32()
			width := uint32(1) << uint(rng.Intn(16))
			for i := 0; i < rng.Intn(200); i++ {
				ips = append(ips, base+rng.Uint32()%width)
			}
		}
		for i := 0; i < rng.Intn(50); i++ {
			ips = append(ips, rng.Uint32())
		}
		ips = append(ips, 0xFFFFFFFF, 0xFFFFFFFF, 1)

		incremental := NewTrieSeq()
		for _, ip := range ips {
			incremental.InsertUint32(ip)
		}
		// Delete a third again, so pruned branches and lowered counts are
		// covered.
		for i, ip := range ips {
			if i%3 == 0 {
				incremental.DeleteUint32(ip)
			}
		}

		sorted := append([]uint32(nil), ips...)
		for i := 1; i < len(sorted); i++ {
			for j := i; j > 0 && sorted[j-1] > sorted[j]; j-- {
				sorted[j-1], sorted[j] = sorted[j], sorted[j-1]
			}
		}
		built := NewTrieSeq()
		built.BuildSorted(sorted)

		for _, tr := range []*Trie{incremental, built} {
			for probe := 0; probe < 60; probe++ {
				ip := ips[rng.Intn(len(ips))]
				switch rng.Intn(4) {
				case 0:
					ip ^= 1 << uint(rng.Intn(32)) // a neighbour block
				case 1:
					ip = rng.Uint32()
				}
				for prefix := 0; prefix <= 32; prefix++ {
					check(tr, ip, prefix)
				}
			}
		}
	}
}

func TestCountInCIDR_Edges(t *testing.T) {
	empty := NewTrieSeq()
	for _, nc := range []cidr.NumericCIDR{{}, {IP: 0x0A000000, PrefixLen: 8}, {IP: 0xFFFFFFFF, PrefixLen: 32}} {
		if got := empty.CountInCIDR(nc); got != 0 {
			t.Errorf("empty trie: CountInCIDR(%s) = %d, want 0", nc, got)
		}
	}

	tr := NewTrieSeq()
	for _, ip := range []uint32{0x0A000001, 0x0A000001, 0x0A0000FE, 0x0A000100, 0xC0A80101} {
		tr.InsertUint32(ip)
	}
	tests := []struct {
		nc   cidr.NumericCIDR
		want uint32
	}{
		{cidr.NumericCIDR{IP: 0, PrefixLen: 0}, 5},
		{cidr.NumericCIDR{IP: 0x0A000000, PrefixLen: 8}, 4},
		{cidr.NumericCIDR{IP: 0x0A000000, PrefixLen: 24}, 3},
		{cidr.NumericCIDR{IP: 0x0A00004D, PrefixLen: 24}, 3}, // host bits ignored
		{cidr.NumericCIDR{IP: 0x0A000001, PrefixLen: 32}, 2},
		{cidr.NumericCIDR{IP: 0x0A000002, PrefixLen: 32}, 0},
		{cidr.NumericCIDR{IP: 0x0A000100, PrefixLen: 24}, 1},
		{cidr.NumericCIDR{IP: 0xC0A80000, PrefixLen: 16}, 1},
		{cidr.NumericCIDR{IP: 0x80000000, PrefixLen: 1}, 1},
		{cidr.NumericCIDR{IP: 0x0A000000, PrefixLen: 33}, 0}, // not an IPv4 block
		{cidr.NumericCIDR{IP: 0x0A000000, PrefixLen: 255}, 0},
	}
	for _, tt := range tests {
		if got := tr.CountInCIDR(tt.nc); got != tt.want {
			t.Errorf("CountInCIDR(%d.%d.%d.%d/%d) = %d, want %d",
				byte(tt.nc.IP>>24), byte(tt.nc.IP>>16), byte(tt.nc.IP>>8), byte(tt.nc.IP), tt.nc.PrefixLen, got, tt.want)
		}
	}
}

// BenchmarkCountInCIDR compares the three ways to count one detected /24 on
// the trie of BenchmarkCountInRange: from the CIDR string (what both pipelines
// did per detected range), from a parsed *net.IPNet, and from the NumericCIDR
// the clustering walk returns.
func BenchmarkCountInCIDR(b *testing.B) {
	rng := rand.New(rand.NewSource(1))
	tr := NewTrieSeq()
	for i := 0; i < 200000; i++ {
		tr.InsertUint32(0x0A000000 + rng.Uint32()%(1<<16))
	}
	nc := cidr.NumericCIDR{IP: 0x0A004200, PrefixLen: 24}
	str := nc.String()
	_, ipNet, _ := net.ParseCIDR(str)

	b.Run("string", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, parsed, _ := net.ParseCIDR(str)
			_ = tr.CountInRangeIPNet(parsed)
		}
	})
	b.Run("IPNet", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = tr.CountInRangeIPNet(ipNet)
		}
	})
	b.Run("NumericCIDR", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = tr.CountInCIDR(nc)
		}
	})
}
