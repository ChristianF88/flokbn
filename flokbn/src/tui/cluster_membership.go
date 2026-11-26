package tui

import (
	"github.com/ChristianF88/flokbn/cidr"
	"github.com/ChristianF88/flokbn/output"
)

// buildClusterIntervals returns the addresses covered by the cluster set's
// ranges as a cidr.IntervalSet, so membership is an allocation-free binary
// search (IntervalSet.Contains) in the per-request loop of clusteredGrids.
// Entries that are not IPv4 CIDRs are skipped; overlapping and adjacent ranges
// are coalesced, so the answer is correct for any input (e.g. a /8 that
// contains a nested /16). A nil or empty cluster set gives the empty set.
//
// MergedRanges is used because that is exactly the set of ranges the
// visualization lists below the heatmap (renderHeatmap iterates MergedRanges).
func buildClusterIntervals(clusterSet *output.ClusterResult) cidr.IntervalSet {
	if clusterSet == nil || len(clusterSet.MergedRanges) == 0 {
		return nil
	}
	ranges := make([]cidr.Interval, 0, len(clusterSet.MergedRanges))
	for _, r := range clusterSet.MergedRanges {
		if nc, ok := cidr.Parse(r.CIDR); ok {
			ranges = append(ranges, nc.Interval())
		}
	}
	return cidr.NewIntervalSet(ranges)
}
