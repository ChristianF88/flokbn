package cidr

import (
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
	var buf [iputils.MaxIPv4Len + 4]byte
	pos := iputils.PutIPv4(buf[:], nc.IP)
	buf[pos] = '/'
	pos = iputils.PutUint8(buf[:], pos+1, nc.PrefixLen)
	return string(buf[:pos])
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
// hot removeWhitelisted loop so a single scratch buffer can be reused across all
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

// removeWhitelisted removes from blacklist every address covered by the
// parsed whitelist: a CIDR covered by the union of whitelist entries is
// dropped, a partial overlap is carved into the remaining ranges. The caller
// parses the whitelist once (ParseIntervalSet), so ComposeBanLists parses it
// once for both of its lists: O(B + W) instead of O(B*W).
//
// The result is read-only: on a no-op whitelist (empty, or only invalid/non-IPv4
// entries) it returns the input slice unchanged rather than a fresh copy, so
// callers must not append to or mutate it.
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
// Unlike removeWhitelisted it never SPLITS a partially-overlapping CIDR into
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
// subtracted (see removeWhitelisted). Both static and live mode must publish
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
