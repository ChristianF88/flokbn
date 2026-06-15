package trie

import (
	"fmt"
	"math/rand"
	"testing"

	"github.com/ChristianF88/flokbn/iputils"
)

// genUniformSorted returns n ascending-sorted uniform-random uint32 IPs.
func genUniformSorted(n int, seed int64) []uint32 {
	r := rand.New(rand.NewSource(seed))
	ips := make([]uint32, n)
	for i := range ips {
		ips[i] = r.Uint32()
	}
	iputils.RadixSortUint32(ips)
	return ips
}

// genClusteredSorted returns n ascending-sorted IPs clustered into a handful of
// /16 and /24 bases with some hot single IPs — representative of bot traffic.
func genClusteredSorted(n int, seed int64) []uint32 {
	r := rand.New(rand.NewSource(seed))
	bases16 := []uint32{0x0EA90000, 0x0EBA0000, 0x0EBF0000, 0x71AC0000, 0x7B140000}
	bases24 := []uint32{0x2D283200, 0x14A00000}
	hot := []uint32{0x148A0142, 0x9858CD5B, 0x29A8CF02}
	ips := make([]uint32, 0, n)
	for len(ips) < n {
		switch r.Intn(3) {
		case 0:
			b := bases16[r.Intn(len(bases16))]
			ips = append(ips, b|uint32(r.Intn(1<<16)))
		case 1:
			b := bases24[r.Intn(len(bases24))]
			ips = append(ips, b|uint32(r.Intn(1<<8)))
		default:
			ips = append(ips, hot[r.Intn(len(hot))])
		}
	}
	ips = ips[:n]
	iputils.RadixSortUint32(ips)
	return ips
}

// BenchmarkBuildSorted compares the old mutex-allocator sorted batch build
// (InsertSorted) against the new lock-free deferred-count build
// (BuildSorted) on uniform-random and clustered sorted data.
func BenchmarkBuildSorted(b *testing.B) {
	sizes := []int{100000, 500000, 1000000}
	dists := []struct {
		name string
		gen  func(int, int64) []uint32
	}{
		{"Random", genUniformSorted},
		{"Clustered", genClusteredSorted},
	}

	for _, dist := range dists {
		for _, size := range sizes {
			data := dist.gen(size, 0xC1DE)

			b.Run(fmt.Sprintf("Old_Batch/%s/%d", dist.name, size), func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					t := NewTrie()
					t.InsertSorted(data)
				}
			})

			b.Run(fmt.Sprintf("New_Seq/%s/%d", dist.name, size), func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					t := NewTrieSeq()
					t.BuildSorted(data)
				}
			})
		}
	}
}
