package tui

import (
	"net"
	"sort"

	"github.com/ChristianF88/cidrx/iputils"
	"github.com/ChristianF88/cidrx/output"
)

// ipInterval is a half-inclusive numeric range [Start, End] covering a CIDR's
// full address span (both endpoints inclusive). Stored as uint32 so membership
// can be tested with integer comparisons and no allocation in the hot loop.
type ipInterval struct {
	Start uint32
	End   uint32
}

// clusterIntervals holds the detected cluster ranges of a single cluster set as
// a sorted, non-overlapping list of numeric intervals. Membership is answered
// with a binary search (O(log k) per request, allocation-free).
type clusterIntervals struct {
	intervals []ipInterval
}

// buildClusterIntervals parses every CIDR in the cluster set's detected ranges
// once into a numeric interval and returns them sorted by start. Clusters
// within a set are non-overlapping, so the sorted list is disjoint and a single
// binary search suffices for membership.
//
// MergedRanges is used because that is exactly the set of ranges the
// visualization lists below the heatmap (renderHeatmap iterates MergedRanges).
func buildClusterIntervals(clusterSet *output.ClusterResult) *clusterIntervals {
	if clusterSet == nil || len(clusterSet.MergedRanges) == 0 {
		return &clusterIntervals{}
	}

	ci := &clusterIntervals{
		intervals: make([]ipInterval, 0, len(clusterSet.MergedRanges)),
	}

	for _, r := range clusterSet.MergedRanges {
		_, ipNet, err := net.ParseCIDR(r.CIDR)
		if err != nil {
			continue
		}
		ip4 := ipNet.IP.To4()
		if ip4 == nil || len(ipNet.Mask) != 4 {
			continue
		}
		start := iputils.IPToUint32(ip4)
		// End = start with all host bits set: start | ^mask.
		mask := ipNet.Mask
		hostMask := ^(uint32(mask[0])<<24 | uint32(mask[1])<<16 | uint32(mask[2])<<8 | uint32(mask[3]))
		end := start | hostMask
		ci.intervals = append(ci.intervals, ipInterval{Start: start, End: end})
	}

	sort.Slice(ci.intervals, func(i, j int) bool {
		return ci.intervals[i].Start < ci.intervals[j].Start
	})

	// Coalesce overlapping/adjacent intervals into a disjoint set. Real cluster
	// sets are non-overlapping, but merging makes the binary-search membership
	// correct for any input (e.g. a /8 that contains a nested /16).
	merged := ci.intervals[:0]
	for _, iv := range ci.intervals {
		if len(merged) > 0 {
			last := &merged[len(merged)-1]
			// Overlap or contiguity (guard +1 overflow at the top of the space).
			if iv.Start <= last.End || (last.End != ^uint32(0) && iv.Start == last.End+1) {
				if iv.End > last.End {
					last.End = iv.End
				}
				continue
			}
		}
		merged = append(merged, iv)
	}
	ci.intervals = merged

	return ci
}

// Contains reports whether ip (network byte order uint32) falls inside any
// detected cluster range. Allocation-free; O(log k).
func (c *clusterIntervals) Contains(ip uint32) bool {
	if c == nil || len(c.intervals) == 0 {
		return false
	}
	iv := c.intervals
	// Find the last interval whose Start <= ip, then check its End.
	// sort.Search returns the first index where Start > ip; the candidate is
	// the element just before it.
	idx := sort.Search(len(iv), func(i int) bool {
		return iv[i].Start > ip
	})
	if idx == 0 {
		return false
	}
	cand := iv[idx-1]
	return ip >= cand.Start && ip <= cand.End
}

// empty reports whether there are no cluster intervals.
func (c *clusterIntervals) empty() bool {
	return c == nil || len(c.intervals) == 0
}
