package cidr

import (
	"net"
	"slices"

	"github.com/ChristianF88/flokbn/iputils"
)

// Parse reads an IPv4 CIDR ("a.b.c.d/n") into its numeric form. The address is
// masked to the network address, like net.ParseCIDR does: "10.0.0.77/24" is
// 10.0.0.0/24.
//
// ok is false for everything that is not an IPv4-notation CIDR: malformed
// input, a bare address, IPv6 and IPv4-mapped IPv6 ("::ffff:10.0.0.0/120").
// Parse accepts exactly the strings for which net.ParseCIDR succeeds with a
// 4-byte mask (the IPv4-only gate used across flokbn) and returns the same
// network; FuzzParse holds it to that. The canonical spelling - what flokbn
// itself writes - is parsed without allocating; anything else falls back to
// net.ParseCIDR.
func Parse(s string) (nc NumericCIDR, ok bool) {
	if nc, ok = parseCanonical(s); ok {
		return nc, true
	}
	_, n, err := net.ParseCIDR(s)
	if err != nil || len(n.Mask) != 4 {
		return NumericCIDR{}, false
	}
	ones, _ := n.Mask.Size()
	return NumericCIDR{IP: iputils.IPToUint32(n.IP), PrefixLen: uint8(ones)}, true
}

// parseCanonical parses the canonical spelling of an IPv4 CIDR: four decimal
// octets without leading zeros and a prefix length of one or two digits
// without a leading zero. It rejects everything else, including spellings
// net.ParseCIDR accepts (a zero-padded prefix length such as "/08"); Parse
// retries those the slow way.
func parseCanonical(s string) (NumericCIDR, bool) {
	var ip uint32
	i := 0
	for field := 0; field < 4; field++ {
		if i >= len(s) {
			return NumericCIDR{}, false
		}
		d := s[i] - '0'
		if d > 9 {
			return NumericCIDR{}, false
		}
		v := uint32(d)
		i++
		// A leading zero ends the octet: "0" is fine, "01" fails on the
		// separator check below.
		if d != 0 {
			for n := 0; n < 2 && i < len(s); n++ {
				d = s[i] - '0'
				if d > 9 {
					break
				}
				v = v*10 + uint32(d)
				i++
			}
		}
		if v > 255 {
			return NumericCIDR{}, false
		}
		ip = ip<<8 | v

		sep := byte('.')
		if field == 3 {
			sep = '/'
		}
		if i >= len(s) || s[i] != sep {
			return NumericCIDR{}, false
		}
		i++
	}

	var prefix uint32
	switch len(s) - i {
	case 1:
		d := s[i] - '0'
		if d > 9 {
			return NumericCIDR{}, false
		}
		prefix = uint32(d)
	case 2:
		d0, d1 := s[i]-'0', s[i+1]-'0'
		if d0 == 0 || d0 > 9 || d1 > 9 {
			return NumericCIDR{}, false
		}
		prefix = uint32(d0)*10 + uint32(d1)
	default:
		return NumericCIDR{}, false
	}
	if prefix > 32 {
		return NumericCIDR{}, false
	}
	// A shift by 32 (prefix 0) yields 0 in Go: the /0 mask.
	return NumericCIDR{IP: ip & (^uint32(0) << (32 - prefix)), PrefixLen: uint8(prefix)}, true
}

// Interval is a closed range [Start, End] of IPv4 addresses, both ends
// included.
type Interval struct {
	Start, End uint32
}

// Interval returns the address range the CIDR covers. Host bits set in IP are
// ignored, so the range always starts at the network address.
func (nc NumericCIDR) Interval() Interval {
	// A shift by 32 or more yields 0: a /32 has no host bits.
	hostMask := ^uint32(0) >> nc.PrefixLen
	return Interval{Start: nc.IP &^ hostMask, End: nc.IP | hostMask}
}

// IntervalSet is a set of IPv4 addresses held as sorted, disjoint, non-adjacent
// closed intervals: the union of the ranges it was built from. Build one with
// NewIntervalSet or ParseIntervalSet. The zero value is the empty set.
//
// It is the one numeric form of "a list of CIDRs as address ranges" outside the
// jail: the whitelist of removeWhitelisted and the detected ranges behind the
// TUI's cluster overlay both use it.
type IntervalSet []Interval

// NewIntervalSet returns the union of ivs. It sorts and merges ivs IN PLACE and
// the result aliases it.
func NewIntervalSet(ivs []Interval) IntervalSet {
	if len(ivs) <= 1 {
		return ivs
	}

	slices.SortFunc(ivs, func(a, b Interval) int {
		if a.Start < b.Start {
			return -1
		}
		if a.Start > b.Start {
			return 1
		}
		return 0
	})

	// Merge overlapping and adjacent intervals in place.
	merged := 0
	for i := 1; i < len(ivs); i++ {
		curr := &ivs[merged]
		next := ivs[i]
		// next.Start <= curr.End+1 means overlap or adjacency. Guard against
		// curr.End == 0xFFFFFFFF (the +1 would wrap) - in that case curr
		// already covers the whole tail, so anything is absorbed.
		if curr.End == 0xFFFFFFFF || next.Start <= curr.End+1 {
			if next.End > curr.End {
				curr.End = next.End
			}
		} else {
			merged++
			ivs[merged] = next
		}
	}
	return ivs[:merged+1]
}

// ParseIntervalSet parses every CIDR once and returns the union of their
// ranges. Entries Parse rejects (malformed, non-IPv4) are skipped: an IPv6
// entry must never turn into a numeric range ("::/0" read as uint32 would be
// 0.0.0.0/0).
func ParseIntervalSet(cidrs []string) IntervalSet {
	ivs := make([]Interval, 0, len(cidrs))
	for _, entry := range cidrs {
		if nc, ok := Parse(entry); ok {
			ivs = append(ivs, nc.Interval())
		}
	}
	return NewIntervalSet(ivs)
}

// firstEndingFrom returns the index of the first interval whose End is >= ip,
// or len(s) when every interval ends before ip. The intervals are disjoint and
// sorted, so that is the only one that can contain ip or reach past it.
func (s IntervalSet) firstEndingFrom(ip uint32) int {
	lo, hi := 0, len(s)
	for lo < hi {
		mid := int(uint(lo+hi) >> 1)
		if s[mid].End < ip {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	return lo
}

// Contains reports whether ip is in the set. O(log n), no allocation.
func (s IntervalSet) Contains(ip uint32) bool {
	i := s.firstEndingFrom(ip)
	return i < len(s) && s[i].Start <= ip
}

// covers reports whether the whole range [start, end] is in the set. The set
// holds no two touching intervals, so a covered range lies inside one of them.
func (s IntervalSet) covers(start, end uint32) bool {
	i := s.firstEndingFrom(start)
	return i < len(s) && s[i].Start <= start && s[i].End >= end
}

// intersects reports whether any address of [start, end] is in the set.
func (s IntervalSet) intersects(start, end uint32) bool {
	i := s.firstEndingFrom(start)
	return i < len(s) && s[i].Start <= end
}

// MergeCIDRs returns the smallest list of CIDRs that covers exactly the
// addresses of cidrs, in ascending address order: ranges contained in another
// are dropped and sibling halves are joined into their parent block,
// repeatedly.
//
// Every entry must be a valid IPv4 block: PrefixLen <= 32 and no host bits set
// in IP (what the trie emits and Parse returns). cidrs is sorted and compacted
// IN PLACE and the result aliases it.
//
// It replaced the *net.IPNet based MergeIPNets and returns the same ranges in
// the same order; that implementation lives on in merge_ref_test.go as the
// oracle of the merge tests (TestMergeCIDRs_MatchesMergeIPNets, FuzzMergeCIDRs).
func MergeCIDRs(cidrs []NumericCIDR) []NumericCIDR {
	if len(cidrs) <= 1 {
		return cidrs
	}

	// Fast path, the common case for one cluster set: the trie walk emits
	// disjoint ranges, so when they are ascending and no two neighbours touch
	// there is nothing to drop or join.
	clean := true
	for i := 1; i < len(cidrs); i++ {
		prevEnd := cidrs[i-1].Interval().End
		// prevEnd+1 wraps at the top of the address space; a range that
		// reaches the top touches whatever follows it.
		if cidrs[i].IP < cidrs[i-1].IP || prevEnd == 0xFFFFFFFF || cidrs[i].IP <= prevEnd+1 {
			clean = false
			break
		}
	}
	if clean {
		return cidrs
	}

	// By address, the larger block first on a tie, so a block always comes
	// before everything it contains.
	slices.SortFunc(cidrs, func(a, b NumericCIDR) int {
		if a.IP != b.IP {
			if a.IP < b.IP {
				return -1
			}
			return 1
		}
		return int(a.PrefixLen) - int(b.PrefixLen)
	})

	// One pass over a stack that lives in the front of cidrs. The stack never
	// outgrows the number of entries consumed, so writing it never clobbers
	// an unread entry.
	out := cidrs[:0]
	for _, cur := range cidrs {
		// CIDR blocks are nested or disjoint, and everything on the stack
		// starts at or before cur: if cur starts inside the top block it lies
		// inside it entirely (also when that block is a parent joined below,
		// which covers exactly its two halves).
		if n := len(out); n > 0 && cur.IP <= out[n-1].Interval().End {
			continue
		}
		// While the top of the stack and cur are the two halves of one parent
		// block, replace them by the parent. The parent can in turn be the
		// sibling of the entry below it, so the check repeats down the stack
		// (10.0.0.0/24, 10.0.1.0/25, 10.0.1.128/26, 10.0.1.192/26 needs three
		// cascading joins to become 10.0.0.0/23).
		for len(out) > 0 {
			top := out[len(out)-1]
			// Siblings have the same prefix length. /0 has no parent; a
			// prefix above 32 is not an IPv4 block (defensive).
			if top.PrefixLen != cur.PrefixLen || cur.PrefixLen < 1 || cur.PrefixLen > 32 {
				break
			}
			size := uint32(1) << (32 - cur.PrefixLen)
			// top must be the LOWER half of the parent block (aligned to
			// 2*size; for a /1 the mask wraps to all ones, i.e. IP == 0) and
			// cur the upper half right behind it. The alignment check also
			// guarantees top.IP+size cannot overflow.
			if top.IP&(size<<1-1) != 0 || top.IP+size != cur.IP {
				break
			}
			out = out[:len(out)-1]
			cur = NumericCIDR{IP: top.IP, PrefixLen: cur.PrefixLen - 1}
		}
		out = append(out, cur)
	}
	return out
}
