package trie

import (
	"math/bits"
	"net"

	"github.com/ChristianF88/cidrx/cidr"
	"github.com/ChristianF88/cidrx/iputils"
	"github.com/ChristianF88/cidrx/pools"
)

// --- Core Data Structures ---

// TrieNode is now defined in pools package to enable pooling
type TrieNode = pools.TrieNode

type Trie struct {
	Root      *TrieNode
	allocator *pools.NodeAllocator
	seqAlloc  *pools.SeqNodeAllocator
}

// NewTrie creates a new binary trie optimized for IP address storage
// Tuning via https://medium.com/@piyanin/boost-performance-binary-trees-of-a-benchmark-game-more-than-3x-times-for-go-language-ccafe813278c
func NewTrie() *Trie {
	allocator := pools.NewNodeAllocator()
	return &Trie{
		Root:      allocator.GetNode(),
		allocator: allocator,
	}
}

// NewTrieSeq creates a binary trie backed by a lock-free sequential bump
// allocator (single-thread use only). Intended to be paired with
// BuildSorted for the fastest possible sorted build.
func NewTrieSeq() *Trie {
	a := pools.NewSeqNodeAllocator()
	return &Trie{Root: a.GetNode(), seqAlloc: a}
}

// BuildSorted builds the trie from an ASCENDING-sorted slice of uint32
// IPs using a deferred-count prefix-stack algorithm. It REQUIRES a trie created
// by NewTrieSeq (t.seqAlloc != nil) and ascending-sorted input.
//
// The produced trie is bit-identical to InsertSorted (same node
// structure, same per-node Count, Root.Count left at 0) but avoids
// re-descending shared prefixes and writes each node's Count exactly once.
//
// path[d] is the node reached after matching d bits (depths 1..32 are real
// nodes; path[0] is the Root). pending[d] is the multiplicity accumulated for
// the currently-open node at path[d], not yet flushed into its .Count. Because
// the input is sorted, all IPs sharing a prefix are contiguous, so the node for
// that prefix stays open across exactly those runs and is flushed once on close.
func (t *Trie) BuildSorted(ips []uint32) {
	if len(ips) == 0 {
		return
	}

	var path [33]*TrieNode
	var pending [33]uint32
	path[0] = t.Root

	// descend creates/follows nodes from depth d+1..32 for value v, setting
	// pending=m on each freshly opened depth.
	descend := func(d int, v uint32, m uint32) {
		node := path[d]
		for depth := d + 1; depth <= 32; depth++ {
			i := uint(32 - depth)
			bit := (v >> i) & 1
			child := node.Children[bit]
			if child == nil {
				child = t.seqAlloc.GetNode()
				node.Children[bit] = child
			}
			node = child
			path[depth] = node
			pending[depth] = m
		}
	}

	// First run.
	i := 0
	v := ips[0]
	m := uint32(1)
	for i+int(m) < len(ips) && ips[i+int(m)] == v {
		m++
	}
	descend(0, v, m)
	pv := v
	i += int(m)

	for i < len(ips) {
		v = ips[i]
		m = 1
		for i+int(m) < len(ips) && ips[i+int(m)] == v {
			m++
		}

		// d = number of shared leading bits between pv and v (0..31, since v != pv).
		d := bits.LeadingZeros32(pv ^ v)

		// Close nodes deeper than the shared prefix: flush their pending counts.
		for k := 32; k > d; k-- {
			path[k].Count += pending[k]
			pending[k] = 0
		}
		// Shared open nodes (depths 1..d) accumulate this run's multiplicity.
		for k := 1; k <= d; k++ {
			pending[k] += m
		}
		// Open new nodes from depth d for this value.
		descend(d, v, m)

		pv = v
		i += int(m)
	}

	// Flush all remaining open nodes.
	for k := 32; k >= 1; k-- {
		path[k].Count += pending[k]
	}
}

// Insert adds an IP address to the Trie and increments counts along the path
func (t *Trie) Insert(ip net.IP) {
	val := iputils.IPToUint32(ip)
	t.InsertUint32(val)
}

// InsertUint32 adds a uint32 IP directly - ELIMINATES net.IP conversion overhead
func (t *Trie) InsertUint32(val uint32) {
	node := t.Root
	for i := 31; i >= 0; i-- {
		bit := (val >> i) & 1
		if node.Children[bit] == nil {
			node.Children[bit] = t.allocator.GetNode()
		}
		node = node.Children[bit]
		node.Count++
	}
}

// InsertSorted efficiently inserts sorted uint32 IPs with optimized traversal
// This method takes advantage of:
// 1. Batching identical IPs (only one traversal, but increment count by batch size)
// 2. Reusing common prefixes between consecutive IPs
// 3. Caching traversal state to avoid re-traversing from root
//
// Kept as the structural test oracle for the production BuildSorted:
// build_sorted_test.go asserts both produce bit-identical tries.
func (t *Trie) InsertSorted(ips []uint32) {
	if len(ips) == 0 {
		return
	}

	i := 0
	for i < len(ips) {
		currentIP := ips[i]

		// Count consecutive identical IPs
		count := 1
		for i+count < len(ips) && ips[i+count] == currentIP {
			count++
		}

		// Insert this IP with the batch count
		t.insertUint32WithCount(currentIP, uint32(count))

		i += count
	}
}

// insertUint32WithCount adds a uint32 IP with a specific count increment
func (t *Trie) insertUint32WithCount(val uint32, count uint32) {
	node := t.Root
	for i := 31; i >= 0; i-- {
		bit := (val >> i) & 1
		if node.Children[bit] == nil {
			node.Children[bit] = t.allocator.GetNode()
		}
		node = node.Children[bit]
		node.Count += count // Increment by the batch count instead of just 1
	}
}

// Delete removes an IP address from the Trie. It traverses the Trie
// based on the binary representation of the IP address and decrements
// the count of nodes along the path. If a node's count reaches zero,
// it removes the corresponding child node to free up memory.
//
// Parameters:
//   - ip: The IP address to be removed, represented as a net.IP.
//
// Note:
//   - If the IP address does not exist in the Trie, the function exits
//     without making any changes.
func (t *Trie) Delete(ip net.IP) {
	node := t.Root
	val := iputils.IPToUint32(ip)
	var stack []*TrieNode

	for i := 31; i >= 0; i-- {
		bit := (val >> i) & 1
		if node.Children[bit] == nil {
			return
		}
		node = node.Children[bit]
		stack = append(stack, node)
	}

	// The IP was found, then the counts need to be modified at each node
	for i := len(stack) - 1; i >= 0; i-- {
		if stack[i].Count == 0 {
			return
		}
		stack[i].Count--
	}
}

// Count returns the count of a specific IP address in the Trie.
// Kept as a test verification primitive (per-IP count assertions).
func (t *Trie) Count(ip net.IP) uint32 {
	node := t.Root
	val := iputils.IPToUint32(ip)
	for i := 31; i >= 0; i-- {
		bit := (val >> i) & 1
		if node.Children[bit] == nil {
			return 0
		}
		node = node.Children[bit]
	}
	return node.Count
}

// CountAll returns the total count of all IPs in the Trie
func (t *Trie) CountAll() uint32 {
	if t.Root == nil {
		return 0
	} else if t.Root.Children[0] == nil && t.Root.Children[1] == nil {
		return t.Root.Count
	} else {
		var leftCount, rightCount uint32
		leftCount = 0
		rightCount = 0
		if t.Root.Children[0] != nil {
			leftCount = t.Root.Children[0].Count
		}
		if t.Root.Children[1] != nil {
			rightCount = t.Root.Children[1].Count
		}
		return leftCount + rightCount
	}
}

// CountInRange counts all IPs of a Trie within a specific CIDR range
// Uses optimized tree traversal that correctly handles all range boundaries
func (t *Trie) CountInRange(cidr string) (uint32, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return 0, err
	}
	return t.CountInRangeIPNet(ipNet), nil
}

// CountInRangeIPNet counts all IPs of a Trie within a specific IPNet range
// High-performance version that avoids string parsing overhead
func (t *Trie) CountInRangeIPNet(ipNet *net.IPNet) uint32 {
	maskBits, _ := ipNet.Mask.Size()
	if maskBits == 0 {
		// /0 spans the whole address space; CountAll sums the children
		// correctly and avoids the undefined uint32(1)<<32 shift plus the
		// Root.Count==0 trap in the full-containment branch.
		return t.CountAll()
	}
	rangeStart := iputils.IPToUint32(ipNet.IP)

	// Calculate the end of the range
	rangeSize := uint32(1) << (32 - maskBits)
	rangeEnd := rangeStart + rangeSize - 1

	return t.countInRange(t.Root, rangeStart, rangeEnd, 0, 0)
}

// countInRange traverses the trie efficiently using proper range intersection
func (t *Trie) countInRange(node *TrieNode, rangeStart, rangeEnd uint32, currentPrefix, depth uint32) uint32 {
	if node == nil {
		return 0
	}

	// Calculate the range of IPs that this node represents
	var nodeStart, nodeEnd uint32
	if depth == 32 {
		// Leaf node represents a single IP
		nodeStart = currentPrefix
		nodeEnd = currentPrefix
	} else {
		// Internal node represents a range of IPs
		nodeStart = currentPrefix
		nodeEnd = currentPrefix | ((uint32(1) << (32 - depth)) - 1)
	}

	// Check if the node's range intersects with our target range
	if nodeEnd < rangeStart || nodeStart > rangeEnd {
		// No intersection
		return 0
	}

	// If we're at a leaf node (depth 32), return the count if it's in range
	if depth == 32 {
		return node.Count
	}

	// If the target range completely contains the node's range, return all counts
	if rangeStart <= nodeStart && rangeEnd >= nodeEnd {
		return node.Count
	}

	// Partial intersection - need to recurse into children
	var count uint32

	// Check left child (bit 0)
	if node.Children[0] != nil {
		leftPrefix := currentPrefix
		count += t.countInRange(node.Children[0], rangeStart, rangeEnd, leftPrefix, depth+1)
	}

	// Check right child (bit 1)
	if node.Children[1] != nil {
		rightPrefix := currentPrefix | (uint32(1) << (31 - depth))
		count += t.countInRange(node.Children[1], rangeStart, rangeEnd, rightPrefix, depth+1)
	}

	return count
}

// collectCIDRsNode - Sequential version returning numeric CIDRs
func (t *Trie) collectCIDRsNode(node *TrieNode, prefix uint32, depth uint32, results *[]cidr.NumericCIDR, minClusterSize, minDepth, maxDepth uint32, threshold uint32) {
	// Check for nil node
	if node == nil {
		return
	}

	if depth == maxDepth {
		if node.Count >= minClusterSize {
			*results = append(*results, prefixToNumericCIDR(prefix, depth))
		}
		return
	}

	// Calculate if this node should be appended
	var appendCluster bool
	hasLeft := node.Children[0] != nil
	hasRight := node.Children[1] != nil

	// Leaf node - exit early
	if !hasLeft && !hasRight {
		return
	}

	// Optimized distribution check using integer math
	if hasLeft && hasRight {
		// Fast path for equal counts
		if node.Children[0].Count == node.Children[1].Count {
			appendCluster = true
		} else {
			// Integer math version of mean difference calculation
			var diff uint32
			if node.Children[0].Count > node.Children[1].Count {
				diff = node.Children[0].Count - node.Children[1].Count
			} else {
				diff = node.Children[1].Count - node.Children[0].Count
			}
			// Compare (2000*diff)/node.Count < threshold using cross-multiplication
			appendCluster = (2000 * diff) < (threshold * node.Count)
		}
	}

	// If the node meets the cluster size and depth requirements, add it as a CIDR
	// and stop further processing of its children.
	if appendCluster && node.Count >= minClusterSize && depth >= minDepth {
		*results = append(*results, prefixToNumericCIDR(prefix, depth))
		// Stop further processing of child nodes to avoid including smaller CIDRs
		return
	}

	// Fast path for common case: both children exist with early exit optimization
	if hasLeft && hasRight {
		leftCount := node.Children[0].Count
		rightCount := node.Children[1].Count

		// Process smaller subtree first to minimize stack depth
		// Only process children that meet minimum cluster size requirement
		if leftCount <= rightCount {
			if leftCount >= minClusterSize {
				t.collectCIDRsNode(node.Children[0], prefix, depth+1,
					results, minClusterSize, minDepth, maxDepth, threshold)
			}
			if rightCount >= minClusterSize {
				t.collectCIDRsNode(node.Children[1], prefix|(1<<(31-depth)), depth+1,
					results, minClusterSize, minDepth, maxDepth, threshold)
			}
		} else {
			if rightCount >= minClusterSize {
				t.collectCIDRsNode(node.Children[1], prefix|(1<<(31-depth)), depth+1,
					results, minClusterSize, minDepth, maxDepth, threshold)
			}
			if leftCount >= minClusterSize {
				t.collectCIDRsNode(node.Children[0], prefix, depth+1,
					results, minClusterSize, minDepth, maxDepth, threshold)
			}
		}
		return
	}

	// Recursively traverse the left and right children with early exit optimization
	if hasLeft && node.Children[0].Count >= minClusterSize {
		t.collectCIDRsNode(node.Children[0], prefix, depth+1, results, minClusterSize, minDepth, maxDepth, threshold)
	}
	if hasRight && node.Children[1].Count >= minClusterSize {
		t.collectCIDRsNode(node.Children[1], prefix|(1<<(31-depth)), depth+1, results, minClusterSize, minDepth, maxDepth, threshold)
	}
}

// prefixToNumericCIDR converts a prefix and depth to numeric CIDR without string allocation
func prefixToNumericCIDR(prefix uint32, depth uint32) cidr.NumericCIDR {
	return cidr.NumericCIDR{
		IP:        prefix,
		PrefixLen: uint8(depth),
	}
}

// CollectCIDRsNumeric - Numeric sequential clustering algorithm returning numeric CIDRs
// Avoids string allocations in hot paths for maximum performance
func (t *Trie) CollectCIDRsNumeric(minClusterSize, minDepth, maxDepth uint32, meanSubnetDifference float64) []cidr.NumericCIDR {
	// Convert threshold once. Clamp negative inputs first: converting an
	// out-of-range (negative) float64 to uint32 is implementation-defined in Go
	// (huge value on amd64, 0 on arm64), so a negative meanSubnetDifference must
	// deterministically behave like 0.
	if meanSubnetDifference < 0 {
		meanSubnetDifference = 0
	}
	threshold := uint32(meanSubnetDifference * 1000)

	// Handle edge cases
	if t.Root == nil {
		return []cidr.NumericCIDR{}
	}

	if t.Root.Children[0] == nil && t.Root.Children[1] == nil {
		if t.Root.Count >= minClusterSize && 0 >= minDepth {
			return []cidr.NumericCIDR{{IP: 0, PrefixLen: 0}}
		}
		return []cidr.NumericCIDR{}
	}

	// Fixed starting capacity for the result slice; clusters are sparse relative
	// to the input so this is a reasonable prealloc that grows if needed.
	estimatedCapacity := uint32(128)

	results := make([]cidr.NumericCIDR, 0, estimatedCapacity)
	t.collectCIDRsNode(t.Root, 0, 0, &results, minClusterSize, minDepth, maxDepth, threshold)
	return results
}

// CollectCIDRs runs sequential CIDR clustering and returns the results as
// strings. String-returning wrapper around CollectCIDRsNumeric.
func (t *Trie) CollectCIDRs(minClusterSize, minDepth, maxDepth uint32, meanSubnetDifference float64) []string {
	// Use the numeric version and convert to strings only at the end
	numericResults := t.CollectCIDRsNumeric(minClusterSize, minDepth, maxDepth, meanSubnetDifference)
	result := make([]string, len(numericResults))
	for i, nc := range numericResults {
		result[i] = nc.String()
	}
	return result
}
