package cidr

import (
	"reflect"
	"sort"
	"testing"
)

// This file locks in the IPv4-only fix. The tool is IPv4-only; previously an
// IPv6 whitelist entry could inject a bogus uint32 range into the numeric
// subtraction path and silently wipe IPv4 bans (e.g. "::/0" -> {0,0xFFFFFFFF}
// dropped EVERY ban; "2000::/3" -> {0,0x1FFFFFFF} wiped 0.0.0.0-31.255.255.255).
// parseWhitelistRanges now skips non-IPv4 entries, and RemoveWhitelisted keeps a
// non-IPv4 blacklist CIDR verbatim instead of mangling it.

// equalUnordered compares two string slices as multisets (order-independent),
// since RemoveWhitelisted does not guarantee output order across paths.
func equalUnordered(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	ac := append([]string(nil), a...)
	bc := append([]string(nil), b...)
	sort.Strings(ac)
	sort.Strings(bc)
	return reflect.DeepEqual(ac, bc)
}

// CRITICAL regression: an IPv6 catch-all "::/0" in the whitelist must be IGNORED,
// not interpreted as a range that wipes every IPv4 ban.
func TestRemoveWhitelisted_IPv6DefaultRouteDoesNotWipeBans(t *testing.T) {
	blacklist := []string{"1.2.3.0/24", "10.0.0.0/8"}
	whitelist := []string{"::/0"}

	got := RemoveWhitelisted(blacklist, whitelist)

	if !equalUnordered(got, blacklist) {
		t.Fatalf("IPv6 ::/0 whitelist wiped/altered IPv4 bans.\n  blacklist=%v\n  got=%v\n  want=%v",
			blacklist, got, blacklist)
	}
}

// IPv6 whitelist entries mixed with a real IPv4 whitelist entry: only the IPv4
// entry applies. The IPv6 entries (2000::/3, 2001:db8::/32) must NOT cause any
// spurious drops of low-address (0.0.0.0-31.x) bans, which is exactly what the
// pre-fix bug did via {0,0x1FFFFFFF}.
func TestRemoveWhitelisted_IPv6EntriesIgnored_IPv4StillApplies(t *testing.T) {
	// Bans include addresses inside the bogus 0.0.0.0-31.255.255.255 window that
	// "2000::/3" used to wipe, plus one that the real IPv4 whitelist covers.
	blacklist := []string{
		"5.5.5.0/24", // inside the old bogus window — must survive
		"31.0.0.0/8", // inside the old bogus window — must survive
		"10.0.0.0/8", // covered by the real IPv4 whitelist below — must drop
		"203.0.113.0/24",
	}
	whitelist := []string{
		"2000::/3",      // IPv6 — ignored
		"10.0.0.0/8",    // real IPv4 — applies (drops the 10.0.0.0/8 ban)
		"2001:db8::/32", // IPv6 — ignored
	}

	got := RemoveWhitelisted(blacklist, whitelist)

	want := []string{"5.5.5.0/24", "31.0.0.0/8", "203.0.113.0/24"}
	if !equalUnordered(got, want) {
		t.Fatalf("IPv6 whitelist entries caused spurious drops or IPv4 entry mis-applied.\n  got=%v\n  want=%v", got, want)
	}
}

// A non-IPv4 blacklist CIDR passed directly to RemoveWhitelisted is kept VERBATIM
// (defense-in-depth: config load rejects IPv6, but the hot path must not corrupt
// it if one slips through).
func TestRemoveWhitelisted_NonIPv4BlacklistKeptVerbatim(t *testing.T) {
	blacklist := []string{"2001:db8::/32", "203.0.113.0/24"}
	// "0.0.0.0/1" is chosen to INTERSECT the IPv6 entry's bogus numeric range:
	// IPToUint32 maps the IPv6 IP to 0 and BigEndian.Uint32 misreads its 16-byte
	// mask, so without the len(Mask)!=4 guard the entry collapses to [0,0] and is
	// seen as fully covered by 0.0.0.0/1 → silently dropped. The guard keeps it
	// verbatim instead. 203.0.113.0/24 sits outside 0.0.0.0/1, so it must survive
	// too (sanity that a real, un-whitelisted IPv4 ban is preserved).
	whitelist := []string{"0.0.0.0/1"}

	got := RemoveWhitelisted(blacklist, whitelist)

	want := []string{"2001:db8::/32", "203.0.113.0/24"}
	if !equalUnordered(got, want) {
		t.Fatalf("non-IPv4 blacklist CIDR not kept verbatim.\n  got=%v\n  want=%v", got, want)
	}
	// Stronger: the exact IPv6 string must appear unchanged (not canonicalized).
	found := false
	for _, c := range got {
		if c == "2001:db8::/32" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected exact IPv6 string \"2001:db8::/32\" in output, got %v", got)
	}
}

// Happy path 1: a real IPv4 whitelist that fully covers a ban still drops it.
func TestRemoveWhitelisted_IPv4FullCoverStillDrops(t *testing.T) {
	blacklist := []string{"10.0.0.0/8", "192.168.1.0/24"}
	whitelist := []string{"10.0.0.0/8"}

	got := RemoveWhitelisted(blacklist, whitelist)

	want := []string{"192.168.1.0/24"}
	if !equalUnordered(got, want) {
		t.Fatalf("IPv4 full-cover whitelist did not drop covered ban.\n  got=%v\n  want=%v", got, want)
	}
}

// Happy path 2: a partial IPv4 overlap still subtracts (splits the ban around the
// whitelisted hole). Confirms the fix didn't disturb the numeric subtraction path.
func TestRemoveWhitelisted_IPv4PartialOverlapStillSubtracts(t *testing.T) {
	// Whitelist 10.0.0.0/24 carves a hole out of the 10.0.0.0/16 ban.
	blacklist := []string{"10.0.0.0/16"}
	whitelist := []string{"10.0.0.0/24"}

	got := RemoveWhitelisted(blacklist, whitelist)

	// Compare against SubtractMultiple, the proven reference for this case.
	want, err := SubtractMultiple("10.0.0.0/16", []string{"10.0.0.0/24"})
	if err != nil {
		t.Fatalf("reference SubtractMultiple errored: %v", err)
	}
	if len(want) == 0 {
		t.Fatal("test setup wrong: expected a non-empty subtraction result")
	}
	// The whole-ban must NOT survive intact (it was partially carved).
	if equalUnordered(got, blacklist) {
		t.Fatalf("partial overlap left the ban un-subtracted: got=%v", got)
	}
	if !equalUnordered(got, want) {
		t.Fatalf("partial overlap subtraction mismatch.\n  got=%v\n  want=%v", got, want)
	}
}

// Direct unit test of the unexported parseWhitelistRanges: feed mixed IPv4 + IPv6
// and assert only IPv4-derived numeric ranges come out. Without the fix, "::/0"
// would yield {0, 0xFFFFFFFF} and "2000::/3" would yield {0, 0x1FFFFFFF}.
func TestParseWhitelistRanges_SkipsIPv6(t *testing.T) {
	whitelist := []string{
		"::/0",           // IPv6 catch-all — must be skipped
		"10.0.0.0/8",     // IPv4 — kept
		"2000::/3",       // IPv6 — must be skipped
		"2001:db8::/32",  // IPv6 — must be skipped
		"192.168.0.0/16", // IPv4 — kept
	}

	ranges := parseWhitelistRanges(whitelist)

	// Expected: only the two IPv4 ranges, sorted+merged. They are disjoint and
	// non-adjacent so no merging occurs.
	// 10.0.0.0/8     -> [0x0A000000, 0x0AFFFFFF]
	// 192.168.0.0/16 -> [0xC0A80000, 0xC0A8FFFF]
	want := []rng32{
		{start: 0x0A000000, end: 0x0AFFFFFF},
		{start: 0xC0A80000, end: 0xC0A8FFFF},
	}

	if len(ranges) != len(want) {
		t.Fatalf("expected %d IPv4 ranges, got %d: %+v", len(want), len(ranges), ranges)
	}
	if !reflect.DeepEqual(ranges, want) {
		t.Fatalf("parseWhitelistRanges injected IPv6-derived ranges.\n  got=%+v\n  want=%+v", ranges, want)
	}

	// Explicit guard against the historical bug: NO range may start at 0 (which is
	// what every IPv6 entry collapsed to via IPToUint32==0).
	for _, r := range ranges {
		if r.start == 0 {
			t.Fatalf("found a range starting at 0 — IPv6 entry leaked into ranges: %+v", ranges)
		}
	}
}

// IPv4-mapped IPv6 (::ffff:a.b.c.d) is the residual hole the mask-length fix
// closes. To4() is NON-nil for "::ffff:1.2.3.0/120", so the old To4()==nil guard
// let it through, but net.ParseCIDR gives it a 16-byte mask, which
// BigEndian.Uint32 misreads — corrupting the IPv4 range into a single IP and
// fragmenting the ban. The whitelist entry must be IGNORED and the ban survive.
func TestRemoveWhitelisted_MappedIPv6WhitelistIgnored(t *testing.T) {
	blacklist := []string{"1.2.3.0/24"}
	whitelist := []string{"::ffff:1.2.3.0/120"} // IPv4-mapped IPv6 — must be skipped

	got := RemoveWhitelisted(blacklist, whitelist)

	if !equalUnordered(got, blacklist) {
		t.Fatalf("mapped-IPv6 whitelist altered/fragmented the IPv4 ban.\n  blacklist=%v\n  got=%v\n  want=%v",
			blacklist, got, blacklist)
	}
}

// Direct unit test: parseWhitelistRanges must SKIP an IPv4-mapped IPv6 entry.
// Without the mask-length fix it yielded {16909056,16909056} (a single IP)
// instead of being skipped.
func TestParseWhitelistRanges_SkipsMappedIPv6(t *testing.T) {
	ranges := parseWhitelistRanges([]string{"::ffff:1.2.3.0/120"})
	if len(ranges) != 0 {
		t.Fatalf("expected mapped-IPv6 entry to be skipped, got %+v", ranges)
	}
}

// Belt-and-suspenders: a whitelist of ONLY IPv6 entries must subtract to nothing,
// i.e. the full blacklist is returned unchanged.
func TestRemoveWhitelisted_OnlyIPv6Whitelist_NoOp(t *testing.T) {
	blacklist := []string{"1.2.3.0/24", "10.0.0.0/8", "0.0.0.0/8"}
	whitelist := []string{"::/0", "2000::/3", "fe80::/10"}

	got := RemoveWhitelisted(blacklist, whitelist)

	if !equalUnordered(got, blacklist) {
		t.Fatalf("an all-IPv6 whitelist altered the IPv4 blacklist.\n  got=%v\n  want=%v", got, blacklist)
	}
}
