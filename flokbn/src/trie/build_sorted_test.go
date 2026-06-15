package trie

import (
	"math/rand"
	"testing"

	"github.com/ChristianF88/flokbn/cidr"
	"github.com/ChristianF88/flokbn/iputils"
)

// buildOld builds a trie via the existing mutex-allocator sorted batch path.
func buildOld(sortedIPs []uint32) *Trie {
	t := NewTrie()
	t.InsertSorted(sortedIPs)
	return t
}

// buildNew builds a trie via the new lock-free deferred-count sorted path.
func buildNew(sortedIPs []uint32) *Trie {
	t := NewTrieSeq()
	t.BuildSorted(sortedIPs)
	return t
}

// assertNodesIdentical does a synchronized DFS over both tries and asserts that
// every node has identical Count and identical child-presence. This is the
// structural-identity oracle: any divergence in shape or count fails here.
func assertNodesIdentical(t *testing.T, a, b *TrieNode, path string) {
	t.Helper()
	if (a == nil) != (b == nil) {
		t.Fatalf("node presence mismatch at %q: old=%v new=%v", path, a != nil, b != nil)
	}
	if a == nil {
		return
	}
	if a.Count != b.Count {
		t.Fatalf("Count mismatch at %q: old=%d new=%d", path, a.Count, b.Count)
	}
	for bit := 0; bit < 2; bit++ {
		ac := a.Children[bit]
		bc := b.Children[bit]
		if (ac == nil) != (bc == nil) {
			t.Fatalf("child[%d] presence mismatch at %q: old=%v new=%v", bit, path, ac != nil, bc != nil)
		}
	}
	assertNodesIdentical(t, a.Children[0], b.Children[0], path+"0")
	assertNodesIdentical(t, a.Children[1], b.Children[1], path+"1")
}

func assertCollectIdentical(t *testing.T, old, neu *Trie) {
	t.Helper()
	type params struct {
		minSize, minDepth, maxDepth uint32
		thr                         float64
	}
	sets := []params{
		{1, 0, 32, 0.1},
		{1000, 24, 32, 0.1},
		{10000, 16, 24, 0.2},
		{10000, 12, 16, 0.1},
		{2, 8, 32, 0.5},
		{1, 0, 16, 0.0},
	}
	for _, p := range sets {
		oc := old.CollectCIDRsNumeric(p.minSize, p.minDepth, p.maxDepth, p.thr)
		nc := neu.CollectCIDRsNumeric(p.minSize, p.minDepth, p.maxDepth, p.thr)
		if len(oc) != len(nc) {
			t.Fatalf("CollectCIDRsNumeric len mismatch for %+v: old=%d new=%d", p, len(oc), len(nc))
		}
		for i := range oc {
			if oc[i] != nc[i] {
				t.Fatalf("CollectCIDRsNumeric mismatch for %+v at %d: old=%v new=%v", p, i, oc[i], nc[i])
			}
		}
	}
}

// runIdentity sorts the input, builds both tries, and runs both oracles.
func runIdentity(t *testing.T, name string, ips []uint32) {
	t.Helper()
	t.Run(name, func(t *testing.T) {
		sorted := make([]uint32, len(ips))
		copy(sorted, ips)
		iputils.RadixSortUint32(sorted)

		old := buildOld(sorted)
		neu := buildNew(sorted)

		assertNodesIdentical(t, old.Root, neu.Root, "")
		// Root.Count must remain 0 (unchanged behavior).
		if neu.Root.Count != 0 {
			t.Fatalf("Root.Count expected 0, got %d", neu.Root.Count)
		}
		if old.Root.Count != 0 {
			t.Fatalf("old Root.Count expected 0, got %d", old.Root.Count)
		}
		assertCollectIdentical(t, old, neu)
	})
}

func TestBuildSortedIdentity(t *testing.T) {
	// empty
	runIdentity(t, "Empty", []uint32{})
	// single
	runIdentity(t, "Single", []uint32{0xC0A80101})
	// all-identical, multiplicity > 1
	runIdentity(t, "AllIdentical", []uint32{42, 42, 42, 42, 42, 42, 42})
	// two IPs differing only in MSB (d=0)
	runIdentity(t, "DiffMSB", []uint32{0x00000001, 0x80000001})
	// two IPs differing only in LSB (d=31)
	runIdentity(t, "DiffLSB", []uint32{0x12345678, 0x12345679})
	// boundary values
	runIdentity(t, "Boundaries", []uint32{0, 0, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x80000000})

	// uniform-random 10k
	{
		r := rand.New(rand.NewSource(0xC1DE))
		ips := make([]uint32, 10000)
		for i := range ips {
			ips[i] = r.Uint32()
		}
		runIdentity(t, "UniformRandom10k", ips)
	}

	// uniform-random 10k with heavy duplication (forces multiplicity runs)
	{
		r := rand.New(rand.NewSource(0xBEEF))
		ips := make([]uint32, 10000)
		for i := range ips {
			ips[i] = r.Uint32() % 2048 // many collisions
		}
		runIdentity(t, "UniformRandomDup10k", ips)
	}

	// CLUSTERED data: a handful of /16 and /24 bases with many hosts, plus
	// repeated exact IPs — representative of bot traffic. 100k requests.
	{
		r := rand.New(rand.NewSource(0xF00D))
		bases16 := []uint32{0x0EA90000, 0x0EBA0000, 0x0EBF0000, 0x71AC0000, 0x7B140000}
		bases24 := []uint32{0x2D283200, 0x14A00000}
		ips := make([]uint32, 0, 100000)
		for len(ips) < 100000 {
			switch r.Intn(3) {
			case 0:
				b := bases16[r.Intn(len(bases16))]
				ips = append(ips, b|uint32(r.Intn(1<<16)))
			case 1:
				b := bases24[r.Intn(len(bases24))]
				ips = append(ips, b|uint32(r.Intn(1<<8)))
			default:
				// a few hot single IPs hit repeatedly
				hot := []uint32{0x148A0142, 0x9858CD5B, 0x29A8CF02}
				ips = append(ips, hot[r.Intn(len(hot))])
			}
		}
		runIdentity(t, "Clustered100k", ips)
	}
}

// TestBuildSortedRealWorldParams mirrors the documented example params on
// clustered data to ensure clustering output parity on representative input.
func TestBuildSortedRealWorldParams(t *testing.T) {
	r := rand.New(rand.NewSource(0x5EED))
	bases := []uint32{0x0EA00000, 0x9858C000, 0x71AC0000, 0x7B140000, 0x0EBF0000}
	ips := make([]uint32, 0, 200000)
	for len(ips) < 200000 {
		b := bases[r.Intn(len(bases))]
		ips = append(ips, b|uint32(r.Intn(1<<16)))
	}
	iputils.RadixSortUint32(ips)

	old := buildOld(ips)
	neu := buildNew(ips)
	assertNodesIdentical(t, old.Root, neu.Root, "")

	oc := old.CollectCIDRsNumeric(1000, 12, 16, 0.1)
	nc := neu.CollectCIDRsNumeric(1000, 12, 16, 0.1)
	if len(oc) != len(nc) {
		t.Fatalf("len mismatch: old=%d new=%d", len(oc), len(nc))
	}
	for i := range oc {
		if oc[i] != nc[i] {
			t.Fatalf("mismatch at %d: old=%v new=%v", i, oc[i], nc[i])
		}
	}
	_ = cidr.NumericCIDR{} // keep cidr import meaningful if collect lists are empty
}
