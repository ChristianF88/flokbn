package cidr

import (
	"encoding/binary"
	"net"
	"sort"

	"github.com/ChristianF88/flokbn/iputils"
)

// This file holds package-local reference implementations of the four legacy
// CIDR functions that used to live in cidr.go (IsWhitelisted, SubtractMultiple,
// GenerateOptimal, GenerateOptimalNumeric). Those functions had zero production
// callers and were deleted, but several tests still need them as ORACLES — most
// importantly the differential test that compares the production
// RemoveWhitelisted against the old algorithm. Keeping verbatim copies here
// preserves that coverage without keeping dead code in the shipped package.

// refIsWhitelisted is a verbatim copy of the deleted cidr.IsWhitelisted.
func refIsWhitelisted(cidr string, whitelist []string) bool {
	_, candidateNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}

	var whitelistNets []*net.IPNet
	for _, whitelistEntry := range whitelist {
		_, whitelistNet, err := net.ParseCIDR(whitelistEntry)
		if err != nil {
			continue // Skip invalid entries
		}
		whitelistNets = append(whitelistNets, whitelistNet)
	}

	return IsWhitelistedIPNet(candidateNet, whitelistNets)
}

// refSubtractMultiple is a verbatim copy of the deleted cidr.SubtractMultiple.
func refSubtractMultiple(blacklistCidr string, whitelistCidrs []string) ([]string, error) {
	_, blackNet, err := net.ParseCIDR(blacklistCidr)
	if err != nil {
		return []string{blacklistCidr}, nil
	}

	blackStart := iputils.IPToUint32(blackNet.IP)
	blackEnd := blackStart | ^binary.BigEndian.Uint32(blackNet.Mask)

	excludeRanges := make([][2]uint32, 0, len(whitelistCidrs))

	for _, whiteCidr := range whitelistCidrs {
		_, whiteNet, err := net.ParseCIDR(whiteCidr)
		if err != nil {
			continue
		}

		whiteStart := iputils.IPToUint32(whiteNet.IP)
		whiteEnd := whiteStart | ^binary.BigEndian.Uint32(whiteNet.Mask)

		if whiteEnd < blackStart || whiteStart > blackEnd {
			continue // No intersection
		}

		if whiteStart < blackStart {
			whiteStart = blackStart
		}
		if whiteEnd > blackEnd {
			whiteEnd = blackEnd
		}

		if whiteStart <= whiteEnd {
			excludeRanges = append(excludeRanges, [2]uint32{whiteStart, whiteEnd})
		}
	}

	if len(excludeRanges) == 0 {
		return []string{blacklistCidr}, nil
	}

	sort.Slice(excludeRanges, func(i, j int) bool {
		return excludeRanges[i][0] < excludeRanges[j][0]
	})

	mergedCount := 1
	for i := 1; i < len(excludeRanges); i++ {
		curr := &excludeRanges[mergedCount-1]
		next := excludeRanges[i]

		if next[0] <= curr[1]+1 { // Overlapping or adjacent
			if next[1] > curr[1] {
				curr[1] = next[1]
			}
		} else {
			excludeRanges[mergedCount] = next
			mergedCount++
		}
	}
	excludeRanges = excludeRanges[:mergedCount]

	result := make([]string, 0, len(excludeRanges)*2+1)
	pos := blackStart

	for _, excludeRange := range excludeRanges {
		if pos < excludeRange[0] {
			result = append(result, refGenerateOptimal(pos, excludeRange[0]-1)...)
		}
		if excludeRange[1] == 0xFFFFFFFF {
			return result, nil
		}
		pos = excludeRange[1] + 1
	}

	if pos <= blackEnd {
		result = append(result, refGenerateOptimal(pos, blackEnd)...)
	}

	return result, nil
}

// refGenerateOptimalNumeric is a verbatim copy of the deleted
// cidr.GenerateOptimalNumeric. It delegates to the still-present
// appendOptimalNumeric, which is the production allocation-free core.
func refGenerateOptimalNumeric(start, end uint32) []NumericCIDR {
	if start > end {
		return nil
	}

	rangeBits := uint32(32)
	if start != end {
		rangeBits = 32 - uint32(LargestCIDRSize(start, end-start+1))
	}
	estimatedSize := int(rangeBits) + 1
	if estimatedSize > 32 {
		estimatedSize = 32
	}

	result := make([]NumericCIDR, 0, estimatedSize)
	return appendOptimalNumeric(result, start, end)
}

// refGenerateOptimal is a verbatim copy of the deleted cidr.GenerateOptimal.
func refGenerateOptimal(start, end uint32) []string {
	numericResults := refGenerateOptimalNumeric(start, end)
	result := make([]string, len(numericResults))
	for i, nc := range numericResults {
		result[i] = nc.String()
	}
	return result
}
