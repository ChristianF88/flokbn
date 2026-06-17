package cidr

import (
	"encoding/binary"
	"net"
	"sort"
	"strings"

	"github.com/ChristianF88/flokbn/iputils"
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

				// Guard against prevEnd == 0xFFFFFFFF: prevEnd+1 would wrap to 0
				// and the comparison would falsely report "no overlap" at the top
				// of IPv4 space. When the previous range already reaches the top,
				// any following range overlaps (input is sorted). Mirrors the same
				// guard in parseWhitelistRanges and subtractRanges.
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

// IsWhitelistedIPNet checks if an IPNet is covered by any whitelist IPNet
// High-performance version that works directly with IPNets
func IsWhitelistedIPNet(candidateNet *net.IPNet, whitelistNets []*net.IPNet) bool {
	// IPv4-only tool: the uint32 comparison below reads the mask via
	// BigEndian.Uint32, which misreads a 16-byte (IPv6/IPv4-mapped) mask. A CIDR
	// parsed from IPv4 dotted-quad notation always has a 4-byte mask; anything
	// else is non-IPv4 and is treated as "not whitelisted" (kept verbatim).
	if len(candidateNet.Mask) != 4 {
		return false
	}
	candidateStart := iputils.IPToUint32(candidateNet.IP)
	candidateEnd := candidateStart | ^binary.BigEndian.Uint32(candidateNet.Mask)
	for _, whitelistNet := range whitelistNets {
		if len(whitelistNet.Mask) != 4 {
			continue
		}
		// The numeric subset test is sufficient on its own: if the candidate's
		// whole [start,end] range lies inside the whitelist's [start,end] range,
		// the candidate IP is contained AND the whitelist mask is necessarily
		// smaller-or-equal. The earlier Contains() and mask comparison were
		// redundant (and Contains() allocated/iterated per entry on the hot
		// DropFullyWhitelisted path).
		whitelistStart := iputils.IPToUint32(whitelistNet.IP)
		whitelistEnd := whitelistStart | ^binary.BigEndian.Uint32(whitelistNet.Mask)
		if candidateStart >= whitelistStart && candidateEnd <= whitelistEnd {
			return true
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

// appendOptimalNumeric appends the minimal set of CIDRs covering [start, end] to
// dst and returns the extended slice. It is the allocation-free core used by the
// hot RemoveWhitelisted loop so a single scratch buffer can be reused across all
// blacklist CIDRs instead of allocating a fresh slice per range gap.
func appendOptimalNumeric(dst []NumericCIDR, start, end uint32) []NumericCIDR {
	if start > end {
		return dst
	}

	// Full address space: end-start+1 would overflow; emit the single /0.
	if start == 0 && end == 0xFFFFFFFF {
		return append(dst, NumericCIDR{IP: 0, PrefixLen: 0})
	}

	current := start
	for current <= end && current >= start { // Overflow protection
		remaining := end - current + 1
		cidrSize := LargestCIDRSize(current, remaining)
		if cidrSize > 0 {
			dst = append(dst, NumericCIDR{
				IP:        current,
				PrefixLen: uint8(32 - cidrSize),
			})
			next := current + (1 << cidrSize)
			if next < current { // Overflow check
				break
			}
			current = next
		} else {
			dst = append(dst, NumericCIDR{
				IP:        current,
				PrefixLen: 32,
			})
			if current == 0xFFFFFFFF {
				break
			}
			current++
		}
	}
	return dst
}

// rng32 is a closed numeric interval [start, end] over the IPv4 address space.
type rng32 struct {
	start, end uint32
}

// parseWhitelistRanges parses every whitelist CIDR ONCE into a sorted, merged
// set of numeric [start,end] intervals. Invalid entries are skipped. The
// merged+sorted invariant means that clipping the set to any sub-range stays
// sorted+merged, so per-blacklist-CIDR subtraction is byte-identical to
// subtracting the raw (unmerged) whitelist.
//
// This replaces the O(B*W) net.ParseCIDR storm in RemoveWhitelisted: the
// whitelist is parsed once (O(W)) instead of once per blacklist CIDR.
func parseWhitelistRanges(whitelist []string) []rng32 {
	ranges := make([]rng32, 0, len(whitelist))
	for _, entry := range whitelist {
		_, wn, err := net.ParseCIDR(entry)
		if err != nil {
			continue // skip invalid entries
		}
		// IPv4-only tool: a non-IPv4 whitelist entry would inject garbage uint32
		// ranges (IPToUint32 returns 0, BigEndian.Uint32 reads the top 4 mask
		// bytes), e.g. ::/0 -> {0,0xFFFFFFFF} drops every IPv4 ban. Skip it.
		// Gate on mask length, not To4(): To4() is non-nil for IPv4-mapped IPv6
		// (::ffff:a.b.c.d) but net.ParseCIDR gives it a 16-byte mask, which
		// BigEndian.Uint32 would misread. The mask is 4 bytes only for IPv4-notation.
		if len(wn.Mask) != 4 {
			continue
		}
		start := iputils.IPToUint32(wn.IP)
		end := start | ^binary.BigEndian.Uint32(wn.Mask)
		ranges = append(ranges, rng32{start, end})
	}
	if len(ranges) <= 1 {
		return ranges
	}

	sort.Slice(ranges, func(i, j int) bool {
		return ranges[i].start < ranges[j].start
	})

	// Merge overlapping/adjacent intervals in place.
	merged := 0
	for i := 1; i < len(ranges); i++ {
		curr := &ranges[merged]
		next := ranges[i]
		// next.start <= curr.end+1 means overlap or adjacency. Guard against
		// curr.end == 0xFFFFFFFF (the +1 would wrap) — in that case curr already
		// covers the whole tail, so anything is absorbed.
		if curr.end == 0xFFFFFFFF || next.start <= curr.end+1 {
			if next.end > curr.end {
				curr.end = next.end
			}
		} else {
			merged++
			ranges[merged] = next
		}
	}
	return ranges[:merged+1]
}

// subtractRanges subtracts the pre-sorted, pre-merged whitelist intervals from
// the blacklist range [blackStart, blackEnd], appending the resulting numeric
// CIDRs to dst. The whitelist ranges are clipped to the blacklist bounds; since
// they are already globally sorted+merged, the clipped overlap stays sorted and
// merged, so the emitted gaps (and therefore the CIDRs) are the minimal set
// covering this blacklist CIDR with the whitelisted holes removed.
func subtractRanges(dst []NumericCIDR, blackStart, blackEnd uint32, whiteRanges []rng32) []NumericCIDR {
	pos := blackStart
	for _, wr := range whiteRanges {
		// Skip ranges entirely before the blacklist window.
		if wr.end < blackStart {
			continue
		}
		// Sorted: once a range starts past the window, none of the rest overlap.
		if wr.start > blackEnd {
			break
		}

		s := wr.start
		if s < blackStart {
			s = blackStart
		}
		e := wr.end
		if e > blackEnd {
			e = blackEnd
		}

		// Emit the gap before this exclusion.
		if pos < s {
			dst = appendOptimalNumeric(dst, pos, s-1)
		}
		if e == 0xFFFFFFFF {
			// Exclusion reaches the top of the address space; pos would wrap.
			// Sorted+merged, so the remaining tail is fully covered.
			return dst
		}
		if e+1 > pos {
			pos = e + 1
		}
	}

	if pos <= blackEnd {
		dst = appendOptimalNumeric(dst, pos, blackEnd)
	}
	return dst
}

// rangeFullyCovered reports whether [start,end] is completely contained within a
// single MERGED whitelist interval. Because whiteRanges is already sorted and
// merged (adjacent/overlapping entries collapsed by parseWhitelistRanges), this
// is effectively union coverage: a binary search finds the only candidate
// interval that could contain start, and that one interval already represents
// the union of all entries touching it.
func rangeFullyCovered(start, end uint32, whiteRanges []rng32) bool {
	// Find the last range whose start <= start.
	i := sort.Search(len(whiteRanges), func(i int) bool {
		return whiteRanges[i].start > start
	}) - 1
	if i < 0 {
		return false
	}
	return whiteRanges[i].start <= start && whiteRanges[i].end >= end
}

// rangeIntersects reports whether any whitelist interval overlaps [start,end].
// whiteRanges is sorted by start and merged (non-overlapping), so the first
// interval whose end >= start is the only candidate that can intersect.
func rangeIntersects(start, end uint32, whiteRanges []rng32) bool {
	i := sort.Search(len(whiteRanges), func(i int) bool {
		return whiteRanges[i].end >= start
	})
	return i < len(whiteRanges) && whiteRanges[i].start <= end
}

// RemoveWhitelisted removes any CIDRs from the blacklist that are covered by whitelist entries
// and performs CIDR subtraction when whitelist entries are contained within blacklist entries.
//
// The whitelist is parsed exactly once (parseWhitelistRanges) and reused for
// every blacklist CIDR, giving O(B + W) parsing instead of the O(B*W)
// net.ParseCIDR allocation storm of the previous per-candidate re-parsing.
//
// The result is read-only: on a no-op whitelist (empty, or only invalid/non-IPv4
// entries) it returns the input slice unchanged rather than a fresh copy, so
// callers must not append to or mutate it.
func RemoveWhitelisted(blacklist []string, whitelist []string) []string {
	if len(whitelist) == 0 {
		return blacklist
	}

	whiteRanges := parseWhitelistRanges(whitelist)
	if len(whiteRanges) == 0 {
		// Whitelist had only invalid entries — nothing to subtract or remove.
		return blacklist
	}

	var result []string
	// Scratch buffer for per-CIDR numeric subtraction, reused across iterations.
	var scratch []NumericCIDR

	for _, blackCidr := range blacklist {
		_, blackNet, err := net.ParseCIDR(blackCidr)
		if err != nil {
			// An unparseable blacklist entry is never whitelisted and cannot be
			// subtracted, so keep the original string unchanged.
			result = append(result, blackCidr)
			continue
		}

		// IPv4-only tool: a non-IPv4 CIDR can't go through the uint32 numeric path
		// (IPToUint32 returns 0). Keep it verbatim rather than corrupting it. Config
		// load rejects IPv6 (config.loadCIDRFile), so this is defense-in-depth.
		// Gate on mask length, not To4(): IPv4-mapped IPv6 (::ffff:a.b.c.d) has a
		// non-nil To4() but a 16-byte mask, which BigEndian.Uint32 would misread.
		// The mask is 4 bytes only for IPv4-notation CIDRs.
		if len(blackNet.Mask) != 4 {
			result = append(result, blackCidr)
			continue
		}

		blackStart := iputils.IPToUint32(blackNet.IP)
		blackEnd := blackStart | ^binary.BigEndian.Uint32(blackNet.Mask)

		// Fully covered by a single whitelist entry — drop. (Covered only by the
		// UNION of several entries still subtracts to empty below, same outcome.)
		if rangeFullyCovered(blackStart, blackEnd, whiteRanges) {
			continue
		}

		// No whitelist entry intersects this CIDR — keep it VERBATIM, preserving
		// the exact bytes (including any non-canonical host-bits form) rather than
		// re-emitting a canonicalized NumericCIDR.String().
		if !rangeIntersects(blackStart, blackEnd, whiteRanges) {
			result = append(result, blackCidr)
			continue
		}

		scratch = subtractRanges(scratch[:0], blackStart, blackEnd, whiteRanges)
		for _, nc := range scratch {
			result = append(result, nc.String())
		}
	}

	return result
}

// DropFullyWhitelisted returns the blacklist CIDRs that are NOT fully covered
// by the whitelist, each kept intact, plus the count of CIDRs dropped because
// the whitelist covers them completely.
//
// Unlike RemoveWhitelisted it never SPLITS a partially-overlapping CIDR into
// the gaps around whitelisted holes. That fragmentation is catastrophic when
// the whitelist holds many scattered /32s (e.g. User-Agent-whitelisted bot
// IPs): a single jailed /16 with thousands of interior /32 holes explodes into
// thousands of fragment CIDRs, which then feed a super-linear jail update.
// Keeping ranges whole here is safe because the whitelist is still applied
// exactly at the publish choke point (ComposeBanLists) before any ban is
// written, so a whitelisted address can never end up banned.
//
// The whitelist is parsed once, so this is O(B + W) parsing instead of O(B*W).
func DropFullyWhitelisted(blacklist, whitelist []string) (kept []string, dropped int) {
	if len(whitelist) == 0 {
		return blacklist, 0
	}

	whitelistNets := make([]*net.IPNet, 0, len(whitelist))
	for _, entry := range whitelist {
		_, wn, err := net.ParseCIDR(entry)
		if err != nil {
			continue // skip invalid entries
		}
		whitelistNets = append(whitelistNets, wn)
	}

	kept = make([]string, 0, len(blacklist))
	for _, bc := range blacklist {
		_, candidateNet, err := net.ParseCIDR(bc)
		if err != nil {
			kept = append(kept, bc) // keep unparseable entries as-is
			continue
		}
		if IsWhitelistedIPNet(candidateNet, whitelistNets) {
			dropped++
			continue
		}
		kept = append(kept, bc)
	}
	return kept, dropped
}

// ComposeBanLists applies the whitelist to both the active jail bans and the
// manual blacklist as the final step before a ban file is written. Whitelists
// always win: fully covered entries are dropped and partial overlaps are
// subtracted (see RemoveWhitelisted). Both static and live mode must publish
// through this function so the invariant holds in one place.
func ComposeBanLists(activeBans, manualBlacklist, whitelist []string) (publishBans, publishBlacklist []string) {
	return RemoveWhitelisted(activeBans, whitelist), RemoveWhitelisted(manualBlacklist, whitelist)
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

// Count returns the total number of User-Agent patterns loaded
func (m *UserAgentMatcher) Count() int {
	if m == nil {
		return 0
	}
	return len(m.userAgents)
}
