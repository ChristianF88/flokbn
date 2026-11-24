package cidr

import (
	"encoding/binary"
	"net"
	"reflect"
	"sort"
	"testing"

	"github.com/ChristianF88/flokbn/iputils"
)

// This file holds the *net.IPNet based merge that production used before
// MergeCIDRs: MergeIPNets with its helpers removeContained, collapseCIDRs and
// maskLen, copied verbatim under an "old" prefix. Nothing in the shipped
// package calls them any more. They stay as the ORACLE of the merge tests:
// mergeBoth runs every test input through both implementations and fails when
// the ranges or their order differ.

// mergeBoth merges the CIDR strings with the production MergeCIDRs and with the
// oracle oldMergeIPNets, fails the test when the two disagree, and returns the
// merged ranges as strings (nil for none).
func mergeBoth(tb testing.TB, cidrs []string) []string {
	tb.Helper()
	want := ipNetsToStrings(oldMergeIPNets(mustParseCIDRs(tb, cidrs)))
	got := mergeCIDRStrings(tb, cidrs)
	if !reflect.DeepEqual(got, want) {
		tb.Fatalf("MergeCIDRs(%v)\n got  %v\n want %v (oldMergeIPNets)", cidrs, got, want)
	}
	return got
}

// oldMergeIPNets consolidates overlapping and adjacent IPNet ranges
// High-performance version that works directly with IPNets
// Optimized with early exit conditions and minimal re-allocations
func oldMergeIPNets(ipNets []*net.IPNet) []*net.IPNet {
	if len(ipNets) <= 1 {
		return ipNets
	}

	// Fast path: if already sorted and no overlaps, skip expensive operations
	isSorted := true
	hasOverlaps := false
	prevIP := uint32(0)

	for i, net := range ipNets {
		currIP := iputils.IPToUint32(net.IP)
		if i > 0 {
			if currIP < prevIP {
				isSorted = false
			}
			// Quick overlap check - more sophisticated than just IP comparison
			if !hasOverlaps {
				prevNet := ipNets[i-1]
				prevStart := iputils.IPToUint32(prevNet.IP)
				prevEnd := prevStart | ^binary.BigEndian.Uint32(prevNet.Mask)
				currStart := currIP

				// Guard against prevEnd == 0xFFFFFFFF: prevEnd+1 would wrap to 0
				// and the comparison would falsely report "no overlap" at the top
				// of IPv4 space. When the previous range already reaches the top,
				// any following range overlaps (input is sorted). Mirrors the same
				// guard in NewIntervalSet and subtractRanges.
				if prevEnd == 0xFFFFFFFF || currStart <= prevEnd+1 { // Adjacent or overlapping
					hasOverlaps = true
				}
			}
		}
		prevIP = currIP
	}

	// If no overlaps and already sorted, return as-is
	if isSorted && !hasOverlaps {
		return ipNets
	}

	// Remove CIDRs fully contained in others
	filtered := oldRemoveContained(ipNets)

	// Sort if needed
	if !isSorted {
		sort.Slice(filtered, func(i, j int) bool {
			a := iputils.IPToUint32(filtered[i].IP)
			b := iputils.IPToUint32(filtered[j].IP)
			if a != b {
				return a < b
			}
			m1, _ := filtered[i].Mask.Size()
			m2, _ := filtered[j].Mask.Size()
			return m1 < m2
		})
	}

	// Collapse adjacent CIDRs only if we detected potential overlaps
	if hasOverlaps {
		return oldCollapseCIDRs(filtered)
	}

	return filtered
}

// oldRemoveContained removes CIDR ranges that are fully contained within other ranges
// True O(n log n) implementation using optimized sweep line algorithm with early termination
func oldRemoveContained(nets []*net.IPNet) []*net.IPNet {
	if len(nets) <= 1 {
		return nets
	}

	// Create intervals with start/end points and original index
	type interval struct {
		start, end uint32
		oldMaskLen int
		net        *net.IPNet
	}

	intervals := make([]interval, len(nets))
	for i, net := range nets {
		start := iputils.IPToUint32(net.IP)
		end := start | ^binary.BigEndian.Uint32(net.Mask)
		intervals[i] = interval{
			start:      start,
			end:        end,
			oldMaskLen: oldMaskLen(net),
			net:        net,
		}
	}

	// Sort by start IP, then by mask length (smaller masks first for containment)
	sort.Slice(intervals, func(i, j int) bool {
		if intervals[i].start != intervals[j].start {
			return intervals[i].start < intervals[j].start
		}
		return intervals[i].oldMaskLen < intervals[j].oldMaskLen
	})

	result := make([]*net.IPNet, 0, len(nets))

	// True O(n log n) sweep line with interval tree optimization
	// Keep track of active containing intervals
	activeContainers := make([]interval, 0, 32) // Pre-allocate for typical use cases

	for _, curr := range intervals {
		contained := false

		// Remove expired containers (end < curr.start) using two-pointer technique
		n := 0
		for _, container := range activeContainers {
			if container.end >= curr.start {
				activeContainers[n] = container
				n++
			}
		}
		activeContainers = activeContainers[:n]

		// Check if current interval is contained by any active container
		for _, container := range activeContainers {
			// Container must have smaller or equal mask (larger or equal network)
			if container.oldMaskLen <= curr.oldMaskLen && container.end >= curr.end {
				contained = true
				break
			}
		}

		if !contained {
			result = append(result, curr.net)
			// Add current as potential container for future intervals
			activeContainers = append(activeContainers, curr)
		}
	}

	return result
}

// oldCollapseCIDRs merges sibling CIDR ranges (two equal-size halves of the same
// parent block) into their parent until no such pair is left. For disjoint
// input (oldMergeIPNets runs oldRemoveContained first) the result is the unique
// minimal CIDR set covering the same addresses.
//
// One sort plus one pass over a stack: each range is pushed, and while the two
// topmost entries are siblings they are replaced by their parent. A merge can
// make the new parent a sibling of the entry below it, so the check repeats
// down the stack - this is what a fixed number of left-to-right passes misses
// (10.0.0.0/24, 10.0.1.0/25, 10.0.1.128/26, 10.0.1.192/26 needs three
// cascading merges to become 10.0.0.0/23). Every merge shrinks the stack by
// one, so the pass is O(n) after the O(n log n) sort.
//
// nets is sorted and compacted IN PLACE and the returned slice aliases it.
// Unmerged ranges keep their original *net.IPNet; an IPNet is only allocated
// for a parent that survives to the output.
func oldCollapseCIDRs(nets []*net.IPNet) []*net.IPNet {
	if len(nets) <= 1 {
		return nets
	}

	// Sort networks by IP address and prefix length for optimal merging
	sort.Slice(nets, func(i, j int) bool {
		a := iputils.IPToUint32(nets[i].IP)
		b := iputils.IPToUint32(nets[j].IP)
		if a != b {
			return a < b
		}
		// If same IP, prefer shorter prefix (larger network) first
		m1, _ := nets[i].Mask.Size()
		m2, _ := nets[j].Mask.Size()
		return m1 < m2
	})

	// stack[k] is the numeric form of output entry k. The matching pointer
	// lives in nets[k] (nil = a parent synthesized by a merge, materialized
	// below). The stack never outgrows the number of ranges consumed, so
	// writing nets[k] never clobbers an unread input.
	type block struct {
		start  uint32
		prefix int
	}
	stack := make([]block, 0, len(nets))

	for _, n := range nets {
		cur := block{start: iputils.IPToUint32(n.IP), prefix: oldMaskLen(n)}
		curNet := n
		for len(stack) > 0 {
			top := stack[len(stack)-1]
			// Siblings have the same prefix length. /0 has no parent; a
			// prefix outside 1..32 is not an IPv4 block (defensive).
			if top.prefix != cur.prefix || cur.prefix < 1 || cur.prefix > 32 {
				break
			}
			size := uint32(1) << (32 - cur.prefix)
			// top must be the LOWER half of the parent block (aligned to
			// 2*size; for a /1 the mask wraps to all ones, i.e. start == 0)
			// and cur the upper half right behind it. The alignment check
			// also guarantees top.start+size cannot overflow.
			if top.start&(size<<1-1) != 0 || top.start+size != cur.start {
				break
			}
			stack = stack[:len(stack)-1]
			cur = block{start: top.start, prefix: cur.prefix - 1}
			curNet = nil
		}
		nets[len(stack)] = curNet
		stack = append(stack, cur)
	}

	result := nets[:len(stack)]
	for i, b := range stack {
		if result[i] == nil {
			result[i] = &net.IPNet{IP: iputils.Uint32ToIP(b.start), Mask: net.CIDRMask(b.prefix, 32)}
		}
	}
	return result
}

// oldMaskLen returns the prefix length of a network mask
func oldMaskLen(net *net.IPNet) int {
	n, _ := net.Mask.Size()
	return n
}
