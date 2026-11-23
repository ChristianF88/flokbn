package config

import (
	"errors"
	"math"
	"strconv"
	"strings"
)

// maxPrefixLen is the IPv4 bit width: the deepest prefix a cluster walk can
// reach, hence the ceiling for minDepth and maxDepth.
const maxPrefixLen = 32

// maxMeanSubnetDifference is the upper bound of the balance threshold. The
// trie compares |left-right| / mean(left, right) against it; that ratio peaks
// at 2 (all traffic in one half), so a larger threshold cannot gate anything.
const maxMeanSubnetDifference = 2.0

// validateClusterArgValues is THE validator for one cluster-arg set. Both the
// TOML path (parseClusterArgSetsFromTOML, static and live tables) and the flag
// path (ParseClusterArgSetsFromStrings) hand it the four raw numbers as float64
// and get back the typed set, so the two surfaces cannot disagree on what is
// accepted.
//
// Rules, checked on the FLOAT values before any integer conversion (a
// float->uint32 conversion of a negative, NaN or out-of-range value is
// implementation-defined in Go and silently yields garbage):
//   - minClusterSize: integral, 1 <= n <= MaxUint32 (0 would make every node a
//     cluster candidate)
//   - minDepth, maxDepth: integral, 0 <= minDepth <= maxDepth <= 32
//   - meanSubnetDifference: finite, 0 <= t <= 2
//
// Every problem in the set is reported in ONE error (joined with "; "), so the
// caller emits exactly one diagnostic per rejected set.
func validateClusterArgValues(minClusterSize, minDepth, maxDepth, meanSubnetDifference float64) (ClusterArgSet, error) {
	var problems []string

	if !isIntegralInRange(minClusterSize, 1, math.MaxUint32) {
		problems = append(problems, "minClusterSize ("+formatArg(minClusterSize)+") must be a whole number between 1 and 4294967295")
	}
	minDepthOK := isIntegralInRange(minDepth, 0, maxPrefixLen)
	if !minDepthOK {
		problems = append(problems, "minDepth ("+formatArg(minDepth)+") must be a whole number between 0 and 32")
	}
	maxDepthOK := isIntegralInRange(maxDepth, 0, maxPrefixLen)
	if !maxDepthOK {
		problems = append(problems, "maxDepth ("+formatArg(maxDepth)+") must be a whole number between 0 and 32")
	}
	if minDepthOK && maxDepthOK && minDepth > maxDepth {
		problems = append(problems, "minDepth ("+formatArg(minDepth)+") must be <= maxDepth ("+formatArg(maxDepth)+")")
	}
	// The negated form also rejects NaN (every comparison with NaN is false).
	if !(meanSubnetDifference >= 0 && meanSubnetDifference <= maxMeanSubnetDifference) {
		problems = append(problems, "meanSubnetDifference ("+formatArg(meanSubnetDifference)+") must be a number between 0 and 2")
	}

	if len(problems) > 0 {
		return ClusterArgSet{}, errors.New(strings.Join(problems, "; "))
	}
	return ClusterArgSet{
		MinClusterSize:       uint32(minClusterSize),
		MinDepth:             uint32(minDepth),
		MaxDepth:             uint32(maxDepth),
		MeanSubnetDifference: meanSubnetDifference,
	}, nil
}

// isIntegralInRange reports whether v is a whole number with lo <= v <= hi.
// NaN and +-Inf fail the range comparison, so they are rejected too.
func isIntegralInRange(v, lo, hi float64) bool {
	return v >= lo && v <= hi && v == math.Trunc(v)
}

// formatArg renders a cluster-arg value for a diagnostic: shortest form that
// round-trips, so 32 prints as "32" and 0.25 as "0.25" (never "3.2e+01").
func formatArg(v float64) string {
	if v == math.Trunc(v) && math.Abs(v) < 1e15 {
		return strconv.FormatFloat(v, 'f', 0, 64)
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}
