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

// collapseCIDRs merges sibling CIDR ranges (two equal-size halves of the same
// parent block) into their parent until no such pair is left. For disjoint
// input (MergeIPNets runs removeContained first) the result is the unique
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
		cur := block{start: iputils.IPToUint32(n.IP), prefix: maskLen(n)}
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

// maskLen returns the prefix length of a network mask
func maskLen(net *net.IPNet) int {
	n, _ := net.Mask.Size()
	return n
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

// subtractRanges subtracts the pre-sorted, pre-merged whitelist intervals from
// the blacklist range [blackStart, blackEnd], appending the resulting numeric
// CIDRs to dst. The whitelist ranges are clipped to the blacklist bounds; since
// they are already globally sorted+merged, the clipped overlap stays sorted and
// merged, so the emitted gaps (and therefore the CIDRs) are the minimal set
// covering this blacklist CIDR with the whitelisted holes removed.
func subtractRanges(dst []NumericCIDR, blackStart, blackEnd uint32, whiteRanges IntervalSet) []NumericCIDR {
	pos := blackStart
	for _, wr := range whiteRanges {
		// Skip ranges entirely before the blacklist window.
		if wr.End < blackStart {
			continue
		}
		// Sorted: once a range starts past the window, none of the rest overlap.
		if wr.Start > blackEnd {
			break
		}

		s := wr.Start
		if s < blackStart {
			s = blackStart
		}
		e := wr.End
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

// RemoveWhitelisted removes any CIDRs from the blacklist that are covered by whitelist entries
// and performs CIDR subtraction when whitelist entries are contained within blacklist entries.
//
// The whitelist is parsed exactly once (ParseIntervalSet) and reused for
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
	return removeWhitelisted(blacklist, ParseIntervalSet(whitelist))
}

// removeWhitelisted is RemoveWhitelisted for a whitelist that is already
// parsed, so ComposeBanLists parses it once for both of its lists.
func removeWhitelisted(blacklist []string, whiteRanges IntervalSet) []string {
	if len(whiteRanges) == 0 {
		// Whitelist had only invalid entries - nothing to subtract or remove.
		return blacklist
	}
	if len(blacklist) == 0 {
		return nil
	}

	result := make([]string, 0, len(blacklist))
	// Scratch buffer for per-CIDR numeric subtraction, reused across iterations.
	var scratch []NumericCIDR

	for _, blackCidr := range blacklist {
		// An entry Parse rejects is kept as the original string:
		//   - unparseable: it is never whitelisted and cannot be subtracted;
		//   - not IPv4 (IPv6, or IPv4-mapped IPv6 such as ::ffff:a.b.c.d/120,
		//     which net.ParseCIDR gives a 16-byte mask): it has no uint32
		//     form, and keeping it verbatim beats corrupting it. Config load
		//     rejects IPv6 (config.loadCIDRFile), so this is defense-in-depth.
		black, ok := Parse(blackCidr)
		if !ok {
			result = append(result, blackCidr)
			continue
		}
		bounds := black.Interval()

		// Fully covered - drop. whiteRanges is merged, so coverage by the
		// union of several whitelist entries counts.
		if whiteRanges.covers(bounds.Start, bounds.End) {
			continue
		}

		// No whitelist entry intersects this CIDR - keep it VERBATIM, preserving
		// the exact bytes (including any non-canonical host-bits form) rather than
		// re-emitting a canonicalized NumericCIDR.String().
		if !whiteRanges.intersects(bounds.Start, bounds.End) {
			result = append(result, blackCidr)
			continue
		}

		scratch = subtractRanges(scratch[:0], bounds.Start, bounds.End, whiteRanges)
		for _, nc := range scratch {
			result = append(result, nc.String())
		}
	}

	// nil when nothing is left, as before result was preallocated.
	if len(result) == 0 {
		return nil
	}
	return result
}

// DropFullyWhitelisted returns the blacklist CIDRs that are NOT fully covered
// by a single whitelist entry, each kept intact, plus the count of CIDRs
// dropped because one entry covers them completely. Coverage by the union of
// several entries does not drop a CIDR (deliberate, see the jail invariant
// tests), which is why this scans the entries instead of using an IntervalSet.
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
// Each list is parsed once, into numeric ranges. With nothing to check or
// nothing to check against the input is returned as is and the other list is
// not parsed at all. Entries Parse rejects (malformed, non-IPv4) never cover
// anything on the whitelist side and are kept as they are on the blacklist
// side.
func DropFullyWhitelisted(blacklist, whitelist []string) (kept []string, dropped int) {
	if len(blacklist) == 0 || len(whitelist) == 0 {
		return blacklist, 0
	}

	entries := make([]Interval, 0, len(whitelist))
	for _, entry := range whitelist {
		if nc, ok := Parse(entry); ok {
			entries = append(entries, nc.Interval())
		}
	}

	kept = make([]string, 0, len(blacklist))
candidates:
	for _, bc := range blacklist {
		if nc, ok := Parse(bc); ok {
			candidate := nc.Interval()
			for _, entry := range entries {
				if candidate.Start >= entry.Start && candidate.End <= entry.End {
					dropped++
					continue candidates
				}
			}
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
//
// The whitelist is parsed once for both lists.
func ComposeBanLists(activeBans, manualBlacklist, whitelist []string) (publishBans, publishBlacklist []string) {
	if len(whitelist) == 0 {
		return activeBans, manualBlacklist
	}
	whiteRanges := ParseIntervalSet(whitelist)
	return removeWhitelisted(activeBans, whiteRanges), removeWhitelisted(manualBlacklist, whiteRanges)
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
