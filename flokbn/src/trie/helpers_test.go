package trie

import (
	"net"

	"github.com/ChristianF88/flokbn/iputils"
)

// Test helpers on Trie. Production code works on uint32 IPs and numeric CIDRs
// (InsertUint32, DeleteUint32, BuildSorted, CollectCIDRsNumeric); the tests
// below read more naturally with net.IP and CIDR strings, so these wrappers
// live here and not in trie.go.

// Insert adds ip to the trie.
func (t *Trie) Insert(ip net.IP) {
	t.InsertUint32(iputils.IPToUint32(ip))
}

// Delete removes one occurrence of ip from the trie.
func (t *Trie) Delete(ip net.IP) {
	t.DeleteUint32(iputils.IPToUint32(ip))
}

// Count returns how often ip was inserted (and not deleted).
func (t *Trie) Count(ip net.IP) uint32 {
	node := t.Root
	val := iputils.IPToUint32(ip)
	for i := 31; i >= 0; i-- {
		node = node.Children[(val>>i)&1]
		if node == nil {
			return 0
		}
	}
	return node.Count
}

// CollectCIDRs is CollectCIDRsNumeric with the ranges as strings.
func (t *Trie) CollectCIDRs(minClusterSize, minDepth, maxDepth uint32, meanSubnetDifference float64) []string {
	numeric := t.CollectCIDRsNumeric(minClusterSize, minDepth, maxDepth, meanSubnetDifference)
	result := make([]string, len(numeric))
	for i, nc := range numeric {
		result[i] = nc.String()
	}
	return result
}

// InsertSorted inserts an ascending-sorted IP list one distinct IP at a time.
// It is the structural oracle for BuildSorted: build_sorted_test.go asserts
// both produce bit-identical tries.
func (t *Trie) InsertSorted(ips []uint32) {
	for i := 0; i < len(ips); {
		count := 1
		for i+count < len(ips) && ips[i+count] == ips[i] {
			count++
		}
		t.insertUint32WithCount(ips[i], uint32(count))
		i += count
	}
}

// insertUint32WithCount adds val count times in one walk.
func (t *Trie) insertUint32WithCount(val uint32, count uint32) {
	node := t.Root
	for i := 31; i >= 0; i-- {
		bit := (val >> i) & 1
		if node.Children[bit] == nil {
			node.Children[bit] = t.seqAlloc.GetNode()
		}
		node = node.Children[bit]
		node.Count += count
	}
}
