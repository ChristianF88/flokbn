package trie

import (
	"math"
	"math/bits"
	"net"

	"github.com/ChristianF88/flokbn/cidr"
	"github.com/ChristianF88/flokbn/iputils"
	"github.com/ChristianF88/flokbn/pools"
)

// --- Core Data Structures ---

// TrieNode is now defined in pools package to enable pooling
type TrieNode = pools.TrieNode

type Trie struct {
	Root     *TrieNode
	seqAlloc *pools.SeqNodeAllocator
}

// NewTrieSeq creates a binary trie backed by a lock-free sequential bump
// allocator (single-thread use only). The static pipeline builds it in one
// pass with BuildSorted; the single-goroutine sliding window keeps it current
// with InsertUint32 and DeleteUint32.
func NewTrieSeq() *Trie {
	a := pools.NewSeqNodeAllocator()
	return &Trie{Root: a.GetNode(), seqAlloc: a}
}

// BuildSorted builds the trie from an ASCENDING-sorted slice of uint32
// IPs using a deferred-count prefix-stack algorithm. It REQUIRES a trie created
// by NewTrieSeq (t.seqAlloc != nil) and ascending-sorted input.
//
// The produced trie is bit-identical to inserting every IP one by one (same
// node structure, same per-node Count, Root.Count left at 0) but avoids
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

// InsertUint32 adds one IP and increments the counts along its path.
func (t *Trie) InsertUint32(val uint32) {
	node := t.Root
	for i := 31; i >= 0; i-- {
		bit := (val >> i) & 1
		if node.Children[bit] == nil {
			node.Children[bit] = t.seqAlloc.GetNode()
		}
		node = node.Children[bit]
		node.Count++
	}
}

// DeleteUint32 removes one occurrence of an IP. It decrements the counts along
// the IP's path. After a successful decrement it prunes: any node whose Count
// reaches zero AND that has no surviving children is detached from its parent
// (parent.Children[bit] = nil). Pruning walks the path from the deepest node
// upward and stops at the first node that still has a non-zero count or a
// surviving child, so a deeper still-present IP keeps all of its shared
// ancestors. The Root is never pruned.
//
// An IP that is not in the trie leaves it unchanged. The bump allocator keeps
// a detached node's chunk resident for the allocator's lifetime; the sliding
// window therefore also periodically rebuilds its trie from a fresh allocator
// to bound RSS.
func (t *Trie) DeleteUint32(val uint32) {
	node := t.Root

	// path[k] is the node reached after matching bit position (31-k); its
	// parent is path[k-1] (or Root when k==0). bitAt[k] is the child slot in
	// the parent that points at path[k].
	var path [32]*TrieNode
	var bitAt [32]uint32

	for i := 31; i >= 0; i-- {
		bit := (val >> i) & 1
		if node.Children[bit] == nil {
			return
		}
		node = node.Children[bit]
		k := 31 - i
		path[k] = node
		bitAt[k] = bit
	}

	// The IP was found; decrement counts along the path. Guard against
	// underflow on an over-delete (count already 0): bail without wrapping.
	for k := 31; k >= 0; k-- {
		if path[k].Count == 0 {
			return
		}
		path[k].Count--
	}

	// Prune from the deepest node upward: detach any node that genuinely
	// reached Count==0 on this delete and has no surviving children. Stop as
	// soon as a node must survive (non-zero count or a remaining child), since
	// every shallower node is then an ancestor of a live node.
	for k := 31; k >= 0; k-- {
		n := path[k]
		if n.Count != 0 || n.Children[0] != nil || n.Children[1] != nil {
			break
		}
		var parent *TrieNode
		if k == 0 {
			parent = t.Root
		} else {
			parent = path[k-1]
		}
		parent.Children[bitAt[k]] = nil
	}
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
		// NOTE: keep this /0 special-case ABOVE the IPv4-only guard so a
		// genuine IPv4 "0.0.0.0/0" (4-byte mask, maskBits 0) still routes to
		// CountAll. An IPv6 "::/0" also lands here harmlessly (CountAll of an
		// IPv4 trie); IPv6 with maskBits>0 is rejected by the guard below.
		return t.CountAll()
	}
	// IPv4-only tool: reject any non-IPv4 range up front (defense-in-depth).
	// A 4-byte mask is IPv4-notation only; IPv6 (incl. IPv4-mapped /120, whose
	// mask is 16 bytes) has len != 4. This also implies maskBits <= 32, so the
	// `uint32(1) << (32 - maskBits)` shift below can never go negative (an IPv6
	// prefix >32 previously panicked with "negative shift amount"). This is a
	// one-time check per range/cluster CIDR, not on the per-IP countInRange
	// recursion, so there is no hot-path cost.
	if len(ipNet.Mask) != 4 {
		return 0
	}
	rangeStart := iputils.IPToUint32(ipNet.IP)

	// Calculate the end of the range
	rangeSize := uint32(1) << (32 - maskBits)
	rangeEnd := rangeStart + rangeSize - 1

	return t.countInRange(t.Root, rangeStart, rangeEnd, 0, 0)
}

// CountInCIDR returns how many inserted IPs (duplicates included) lie in the
// block nc. It is the numeric counterpart of CountInRangeIPNet for callers
// that already hold a NumericCIDR: no parsing, no *net.IPNet.
//
// A CIDR block is exactly one trie node - the one reached by following the
// first PrefixLen bits of the address - and the Count of that node is the
// answer, so this is a walk of at most 32 steps. Host bits set in nc.IP are
// ignored. A prefix length above 32 is not an IPv4 block and counts 0.
func (t *Trie) CountInCIDR(nc cidr.NumericCIDR) uint32 {
	if nc.PrefixLen == 0 {
		// The Count of the Root itself is never incremented; CountAll sums
		// its children.
		return t.CountAll()
	}
	if nc.PrefixLen > 32 || t.Root == nil {
		return 0
	}
	node := t.Root
	for shift, last := 31, 32-int(nc.PrefixLen); shift >= last; shift-- {
		node = node.Children[(nc.IP>>uint(shift))&1]
		if node == nil {
			return 0
		}
	}
	return node.Count
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
			// Balance test 2*diff/node.Count < meanSubnetDifference, with the
			// threshold pre-scaled by thresholdScale (see balanceThreshold) and
			// the division removed by cross-multiplication. Both products are
			// widened to uint64: diff and node.Count are below 2^32 and
			// threshold is at most 2*thresholdScale, so each side stays below
			// 2^32 * 2e6 (about 2^53) - exact, pure integer math, no overflow
			// for multi-million-request tries.
			appendCluster = uint64(2*thresholdScale)*uint64(diff) < uint64(threshold)*uint64(node.Count)
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

		// Recurse into the smaller-count subtree first (the left one on a
		// tie). The result order is therefore deterministic for a given trie
		// but NOT sorted by prefix: a lighter right half is emitted before a
		// heavier left half. Callers that need address order must sort
		// (cidr.MergeCIDRs does). Recursion depth is bounded by trie height
		// (<=32) regardless of child order.
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

// thresholdScale is the fixed-point scale of the balance threshold used by
// collectCIDRsNode: meanSubnetDifference is carried as an integer number of
// millionths so the per-node balance test stays in integer math.
const thresholdScale = 1_000_000

// balanceThreshold converts meanSubnetDifference to its fixed-point form
// (millionths, rounded to nearest). It runs once per clustering call.
//
// The imbalance 2*diff/count of a node with two children lies in [0, 2), so
// the input is clamped to [0, 2]: 0 clusters only exactly equal halves, and
// anything >= 2 clusters every node that has two children. NaN, negative and
// huge values are clamped BEFORE the float -> integer conversion, which is
// implementation-defined for out-of-range inputs (the result differs between
// amd64 and arm64). Rounding (instead of truncating) keeps a decimal literal
// whose product lands just below the integer, e.g. 1.001*1000 =
// 1000.9999999999999. For multiples of 0.001 the result is exactly 1000 times
// the old milli-threshold, so the balance test decides identically.
func balanceThreshold(meanSubnetDifference float64) uint32 {
	if !(meanSubnetDifference > 0) { // zero, negative, NaN
		return 0
	}
	if meanSubnetDifference >= 2 {
		return 2 * thresholdScale
	}
	return uint32(math.Round(meanSubnetDifference * thresholdScale))
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
//
// Inputs are clamped defensively (config validation is the first line of
// defense, this is the last):
//   - minClusterSize 0 is treated as 1. Every node below the Root has
//     Count >= 1, so the two differ only at the Root, whose Count is never
//     incremented (InsertUint32 and BuildSorted leave it at 0 by design). A
//     minimum of 0 would let that Root pass the size gate and emit 0.0.0.0/0.
//     With the clamp 0.0.0.0/0 is never emitted, for any input.
//   - meanSubnetDifference is clamped to [0, 2] (NaN -> 0), see balanceThreshold.
func (t *Trie) CollectCIDRsNumeric(minClusterSize, minDepth, maxDepth uint32, meanSubnetDifference float64) []cidr.NumericCIDR {
	if minClusterSize == 0 {
		minClusterSize = 1
	}
	threshold := balanceThreshold(meanSubnetDifference)

	// Empty trie: nothing to cluster.
	if t.Root == nil || (t.Root.Children[0] == nil && t.Root.Children[1] == nil) {
		return []cidr.NumericCIDR{}
	}

	// Fixed starting capacity for the result slice; clusters are sparse relative
	// to the input so this is a reasonable prealloc that grows if needed.
	estimatedCapacity := uint32(128)

	results := make([]cidr.NumericCIDR, 0, estimatedCapacity)
	t.collectCIDRsNode(t.Root, 0, 0, &results, minClusterSize, minDepth, maxDepth, threshold)
	return results
}
