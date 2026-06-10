package cidr

import (
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/ChristianF88/cidrx/iputils"
)

// NumericCIDR represents a CIDR range using numeric values to avoid string allocations
type NumericCIDR struct {
	IP        uint32
	PrefixLen uint8
}

// String converts NumericCIDR to string representation only when needed.
// Uses manual byte building to avoid fmt.Sprintf allocation overhead.
func (nc NumericCIDR) String() string {
	// Max: "255.255.255.255/255" = 19 bytes (PrefixLen is uint8, can be > 99)
	var buf [19]byte
	pos := 0

	pos = appendOctet(buf[:], pos, byte(nc.IP>>24))
	buf[pos] = '.'
	pos++
	pos = appendOctet(buf[:], pos, byte(nc.IP>>16))
	buf[pos] = '.'
	pos++
	pos = appendOctet(buf[:], pos, byte(nc.IP>>8))
	buf[pos] = '.'
	pos++
	pos = appendOctet(buf[:], pos, byte(nc.IP))
	buf[pos] = '/'
	pos++
	pos = appendOctet(buf[:], pos, nc.PrefixLen)

	return string(buf[:pos])
}

func appendOctet(buf []byte, pos int, v byte) int {
	if v >= 100 {
		buf[pos] = '0' + v/100
		pos++
		buf[pos] = '0' + (v%100)/10
		pos++
		buf[pos] = '0' + v%10
		pos++
	} else if v >= 10 {
		buf[pos] = '0' + v/10
		pos++
		buf[pos] = '0' + v%10
		pos++
	} else {
		buf[pos] = '0' + v
		pos++
	}
	return pos
}

// StringsToIPNets converts CIDR strings to IPNet objects
func StringsToIPNets(cidrs []string) ([]*net.IPNet, error) {
	var ipNets []*net.IPNet
	for _, cidr := range cidrs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %s: %w", cidr, err)
		}
		ipNets = append(ipNets, ipNet)
	}
	return ipNets, nil
}

// Merge consolidates overlapping and adjacent CIDR ranges
func Merge(cidrs []string) ([]string, error) {
	ipNets, err := StringsToIPNets(cidrs)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CIDRs: %w", err)
	}

	merged := MergeIPNets(ipNets)

	var result []string
	for _, net := range merged {
		result = append(result, net.String())
	}
	return result, nil
}

// MergeIPNets consolidates overlapping and adjacent IPNet ranges
// High-performance version that works directly with IPNets
// Optimized with early exit conditions and minimal re-allocations
func MergeIPNets(ipNets []*net.IPNet) []*net.IPNet {
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

				if currStart <= prevEnd+1 { // Adjacent or overlapping
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
	filtered := removeContained(ipNets)

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
		return collapseCIDRs(filtered)
	}

	return filtered
}

// removeContained removes CIDR ranges that are fully contained within other ranges
// True O(n log n) implementation using optimized sweep line algorithm with early termination
func removeContained(nets []*net.IPNet) []*net.IPNet {
	if len(nets) <= 1 {
		return nets
	}

	// Create intervals with start/end points and original index
	type interval struct {
		start, end uint32
		maskLen    int
		net        *net.IPNet
	}

	intervals := make([]interval, len(nets))
	for i, net := range nets {
		start := iputils.IPToUint32(net.IP)
		end := start | ^binary.BigEndian.Uint32(net.Mask)
		intervals[i] = interval{
			start:   start,
			end:     end,
			maskLen: maskLen(net),
			net:     net,
		}
	}

	// Sort by start IP, then by mask length (smaller masks first for containment)
	sort.Slice(intervals, func(i, j int) bool {
		if intervals[i].start != intervals[j].start {
			return intervals[i].start < intervals[j].start
		}
		return intervals[i].maskLen < intervals[j].maskLen
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
			if container.maskLen <= curr.maskLen && container.end >= curr.end {
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

// collapseCIDRs merges adjacent CIDR ranges using optimized O(n) single-pass algorithm
// Eliminates iterative passes for true O(n) performance after initial O(n log n) sort
func collapseCIDRs(nets []*net.IPNet) []*net.IPNet {
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

	// Single-pass merge algorithm with greedy approach
	// Instead of multiple passes, merge greedily in one pass
	result := make([]*net.IPNet, 0, len(nets))
	current := nets[0]

	for i := 1; i < len(nets); i++ {
		// Try to merge current with next network
		if merged := tryMerge(current, nets[i]); merged != nil {
			current = merged
			// Continue trying to merge the new larger network
			continue
		}

		// Can't merge, add current to result and move to next
		result = append(result, current)
		current = nets[i]
	}

	// Add the final network
	result = append(result, current)

	// Single additional pass to catch any merges created by the greedy approach
	// This handles cases where A+B creates C that can merge with D
	if len(result) > 1 {
		final := make([]*net.IPNet, 0, len(result))
		current = result[0]

		for i := 1; i < len(result); i++ {
			if merged := tryMerge(current, result[i]); merged != nil {
				current = merged
			} else {
				final = append(final, current)
				current = result[i]
			}
		}
		final = append(final, current)
		return final
	}

	return result
}

// tryMerge attempts to merge two adjacent CIDR ranges
func tryMerge(a, b *net.IPNet) *net.IPNet {
	aIP := iputils.IPToUint32(a.IP)
	bIP := iputils.IPToUint32(b.IP)

	aMaskLen := maskLen(a)
	if aMaskLen != maskLen(b) {
		return nil
	}

	blockSize := uint32(1) << (32 - aMaskLen)
	if aIP+blockSize != bIP {
		return nil
	}

	newMaskLen := aMaskLen - 1
	newMask := net.CIDRMask(newMaskLen, 32)
	mergedIP := aIP &^ (1 << (32 - aMaskLen))

	ip := iputils.Uint32ToIP(mergedIP)
	newNet := &net.IPNet{IP: ip, Mask: newMask}

	if newNet.Contains(a.IP) && newNet.Contains(b.IP) {
		return newNet
	}
	return nil
}

// maskLen returns the prefix length of a network mask
func maskLen(net *net.IPNet) int {
	n, _ := net.Mask.Size()
	return n
}

// IsWhitelisted checks if a CIDR range is covered by any whitelist entry
func IsWhitelisted(cidr string, whitelist []string) bool {
	_, candidateNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}

	// Parse whitelist entries individually to handle invalid entries gracefully
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

// IsWhitelistedIPNet checks if an IPNet is covered by any whitelist IPNet
// High-performance version that works directly with IPNets
func IsWhitelistedIPNet(candidateNet *net.IPNet, whitelistNets []*net.IPNet) bool {
	for _, whitelistNet := range whitelistNets {
		// Check if the candidate CIDR is completely contained within the whitelist CIDR
		if whitelistNet.Contains(candidateNet.IP) {
			// Check if the candidate network is a subset of the whitelist network
			candidateMask, _ := candidateNet.Mask.Size()
			whitelistMask, _ := whitelistNet.Mask.Size()

			// If whitelist has smaller or equal mask (larger or equal network),
			// and contains the candidate IP, then candidate is whitelisted
			if whitelistMask <= candidateMask {
				// Verify the entire candidate range is within whitelist range
				candidateStart := iputils.IPToUint32(candidateNet.IP)
				candidateEnd := candidateStart | ^binary.BigEndian.Uint32(candidateNet.Mask)

				whitelistStart := iputils.IPToUint32(whitelistNet.IP)
				whitelistEnd := whitelistStart | ^binary.BigEndian.Uint32(whitelistNet.Mask)

				if candidateStart >= whitelistStart && candidateEnd <= whitelistEnd {
					return true
				}
			}
		}
	}
	return false
}

// LargestCIDRSize finds the largest CIDR block size that fits at the given start address
// Optimized using bit manipulation and early termination
func LargestCIDRSize(start, maxSize uint32) uint8 {
	if maxSize == 0 {
		return 0
	}

	// Fast path for single IP
	if maxSize == 1 {
		return 0
	}

	// Find largest power of 2 alignment using bit operations
	// Count trailing zeros to find alignment
	alignment := uint8(0)
	if start != 0 {
		// Use bit manipulation to find trailing zeros (alignment)
		temp := start
		for temp&1 == 0 && alignment < 32 {
			temp >>= 1
			alignment++
		}
	} else {
		// start == 0 is aligned to any power of 2
		alignment = 32
	}

	// Find largest power of 2 that doesn't exceed maxSize
	maxSizeAlignment := uint8(0)
	temp := maxSize
	for temp > 1 {
		temp >>= 1
		maxSizeAlignment++
	}

	// Return minimum of alignment and maxSize constraints
	if alignment <= maxSizeAlignment {
		return alignment
	}
	return maxSizeAlignment
}

// SubtractMultiple subtracts multiple whitelist CIDRs from a single blacklist CIDR
// Optimized with pre-allocated slices and faster intersection detection
func SubtractMultiple(blacklistCidr string, whitelistCidrs []string) ([]string, error) {
	_, blackNet, err := net.ParseCIDR(blacklistCidr)
	if err != nil {
		return []string{blacklistCidr}, nil
	}

	blackStart := iputils.IPToUint32(blackNet.IP)
	blackEnd := blackStart | ^binary.BigEndian.Uint32(blackNet.Mask)

	// Pre-allocate with estimated capacity to reduce allocations
	excludeRanges := make([][2]uint32, 0, len(whitelistCidrs))

	// Optimized intersection detection and range collection
	for _, whiteCidr := range whitelistCidrs {
		_, whiteNet, err := net.ParseCIDR(whiteCidr)
		if err != nil {
			continue
		}

		whiteStart := iputils.IPToUint32(whiteNet.IP)
		whiteEnd := whiteStart | ^binary.BigEndian.Uint32(whiteNet.Mask)

		// Fast intersection check using uint32 arithmetic (faster than Contains())
		if whiteEnd < blackStart || whiteStart > blackEnd {
			continue // No intersection
		}

		// Clip whitelist range to blacklist bounds
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

	// Sort exclude ranges by start address
	sort.Slice(excludeRanges, func(i, j int) bool {
		return excludeRanges[i][0] < excludeRanges[j][0]
	})

	// Merge overlapping/adjacent ranges in-place to reduce allocations
	mergedCount := 1
	for i := 1; i < len(excludeRanges); i++ {
		curr := &excludeRanges[mergedCount-1]
		next := excludeRanges[i]

		if next[0] <= curr[1]+1 { // Overlapping or adjacent
			if next[1] > curr[1] {
				curr[1] = next[1] // Extend current range
			}
		} else {
			excludeRanges[mergedCount] = next
			mergedCount++
		}
	}
	excludeRanges = excludeRanges[:mergedCount]

	// Generate CIDRs for remaining ranges with pre-allocated result slice
	result := make([]string, 0, len(excludeRanges)*2+1) // Estimate capacity
	pos := blackStart

	for _, excludeRange := range excludeRanges {
		// Add CIDRs before this exclude range
		if pos < excludeRange[0] {
			cidrs := GenerateOptimal(pos, excludeRange[0]-1)
			result = append(result, cidrs...)
		}
		if excludeRange[1] == 0xFFFFFFFF {
			// Exclusion reaches the top of the address space; pos would wrap to 0.
			// Ranges are sorted and merged, so the remaining tail is fully covered.
			return result, nil
		}
		pos = excludeRange[1] + 1
	}

	// Add CIDRs after the last exclude range
	if pos <= blackEnd {
		cidrs := GenerateOptimal(pos, blackEnd)
		result = append(result, cidrs...)
	}

	return result, nil
}

// GenerateOptimalNumeric generates the minimal set of CIDRs covering the range [start, end]
// Returns numeric CIDRs to avoid string allocations in hot paths
// Optimized with pre-allocation and overflow protection
func GenerateOptimalNumeric(start, end uint32) []NumericCIDR {
	if start > end {
		return nil
	}

	// Full address space: end-start+1 would overflow uint32; emit the single optimal /0.
	if start == 0 && end == 0xFFFFFFFF {
		return []NumericCIDR{{IP: 0, PrefixLen: 0}}
	}

	// Estimate result size to reduce allocations
	// In worst case (all single IPs), we need (end-start+1) entries
	// In best case (single large CIDR), we need 1 entry
	// Use log-based estimate for reasonable pre-allocation
	rangeBits := uint32(32)
	if start != end {
		rangeBits = 32 - uint32(LargestCIDRSize(start, end-start+1))
	}
	estimatedSize := int(rangeBits) + 1
	if estimatedSize > 32 {
		estimatedSize = 32
	}

	result := make([]NumericCIDR, 0, estimatedSize)
	current := start

	for current <= end && current >= start { // Overflow protection
		// Find the largest CIDR that fits
		remaining := end - current + 1
		cidrSize := LargestCIDRSize(current, remaining)
		if cidrSize > 0 {
			result = append(result, NumericCIDR{
				IP:        current,
				PrefixLen: uint8(32 - cidrSize),
			})
			next := current + (1 << cidrSize)
			if next < current { // Overflow check
				break
			}
			current = next
		} else {
			// Handle single IP case
			result = append(result, NumericCIDR{
				IP:        current,
				PrefixLen: 32,
			})
			if current == 0xFFFFFFFF { // Avoid overflow on max uint32
				break
			}
			current++
		}
	}

	return result
}

// GenerateOptimal generates the minimal set of CIDRs covering the range [start, end]
// Legacy string-based version for backward compatibility
func GenerateOptimal(start, end uint32) []string {
	numericResults := GenerateOptimalNumeric(start, end)
	result := make([]string, len(numericResults))
	for i, nc := range numericResults {
		result[i] = nc.String()
	}
	return result
}

// RemoveWhitelisted removes any CIDRs from the blacklist that are covered by whitelist entries
// and performs CIDR subtraction when whitelist entries are contained within blacklist entries
func RemoveWhitelisted(blacklist []string, whitelist []string) []string {
	if len(whitelist) == 0 {
		return blacklist
	}

	var result []string

	for _, blackCidr := range blacklist {
		// Check if this blacklist CIDR should be completely removed (case 1: blacklist ⊆ whitelist)
		if IsWhitelisted(blackCidr, whitelist) {
			continue // Skip this CIDR entirely
		}

		// Subtract all applicable whitelist entries at once
		remainingCidrs, err := SubtractMultiple(blackCidr, whitelist)
		if err != nil {
			// If subtraction fails, keep the original
			result = append(result, blackCidr)
		} else {
			result = append(result, remainingCidrs...)
		}
	}

	return result
}

// UserAgentMatchResult represents the result of User-Agent matching
type UserAgentMatchResult int8

const (
	UserAgentNotListed UserAgentMatchResult = 0  // Not in any list
	UserAgentWhitelist UserAgentMatchResult = 1  // In whitelist
	UserAgentBlacklist UserAgentMatchResult = -1 // In blacklist
)

// UserAgentMatcher provides ultra-fast O(1) exact string matching for User-Agent whitelist/blacklist
// Uses a single map for both whitelist and blacklist with different values for maximum efficiency
type UserAgentMatcher struct {
	userAgents map[string]UserAgentMatchResult // Case-insensitive exact match lookup
}

// NewUserAgentMatcher creates a new fast User-Agent exact matcher
func NewUserAgentMatcher(whitelistPatterns, blacklistPatterns []string) *UserAgentMatcher {
	// Pre-allocate map with estimated capacity
	capacity := len(whitelistPatterns) + len(blacklistPatterns)
	if capacity < 16 {
		capacity = 16 // Minimum reasonable capacity
	}

	matcher := &UserAgentMatcher{
		userAgents: make(map[string]UserAgentMatchResult, capacity),
	}

	// Add blacklist patterns first (case-insensitive)
	for _, pattern := range blacklistPatterns {
		pattern = strings.TrimSpace(pattern)
		if pattern != "" && !strings.HasPrefix(pattern, "#") {
			// Store in lowercase for case-insensitive matching
			matcher.userAgents[strings.ToLower(pattern)] = UserAgentBlacklist
		}
	}

	// Add whitelist patterns last (case-insensitive)
	// Note: whitelist takes precedence over blacklist if same pattern exists
	for _, pattern := range whitelistPatterns {
		pattern = strings.TrimSpace(pattern)
		if pattern != "" && !strings.HasPrefix(pattern, "#") {
			// Store in lowercase for case-insensitive matching - overwrites blacklist
			matcher.userAgents[strings.ToLower(pattern)] = UserAgentWhitelist
		}
	}

	return matcher
}

// CheckUserAgent performs O(1) exact match lookup for User-Agent
// Returns UserAgentMatchResult indicating whitelist/blacklist/not-listed status
func (m *UserAgentMatcher) CheckUserAgent(userAgent string) UserAgentMatchResult {
	if m == nil || len(m.userAgents) == 0 {
		return UserAgentNotListed
	}

	// O(1) case-insensitive lookup
	result, exists := m.userAgents[strings.ToLower(userAgent)]
	if !exists {
		return UserAgentNotListed
	}
	return result
}

// IsWhitelisted checks if User-Agent is exactly whitelisted
func (m *UserAgentMatcher) IsWhitelisted(userAgent string) bool {
	return m.CheckUserAgent(userAgent) == UserAgentWhitelist
}

// IsBlacklisted checks if User-Agent is exactly blacklisted
func (m *UserAgentMatcher) IsBlacklisted(userAgent string) bool {
	return m.CheckUserAgent(userAgent) == UserAgentBlacklist
}

// Count returns the total number of User-Agent patterns loaded
func (m *UserAgentMatcher) Count() int {
	if m == nil {
		return 0
	}
	return len(m.userAgents)
}

// CountWhitelist returns the number of whitelisted User-Agent patterns
func (m *UserAgentMatcher) CountWhitelist() int {
	if m == nil {
		return 0
	}
	count := 0
	for _, result := range m.userAgents {
		if result == UserAgentWhitelist {
			count++
		}
	}
	return count
}

// CountBlacklist returns the number of blacklisted User-Agent patterns
func (m *UserAgentMatcher) CountBlacklist() int {
	if m == nil {
		return 0
	}
	count := 0
	for _, result := range m.userAgents {
		if result == UserAgentBlacklist {
			count++
		}
	}
	return count
}
