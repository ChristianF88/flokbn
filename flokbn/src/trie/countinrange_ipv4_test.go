package trie

import (
	"net"
	"testing"
)

// AUDIT-03: CountInRangeIPNet must reject non-IPv4 ranges up front (IPv4-only
// tool, defense-in-depth). An IPv6 prefix >32 (e.g. /48, /120) previously made
// `uint32(1) << (32 - maskBits)` shift by a negative amount and PANIC with
// "negative shift amount", crashing the trie worker. An IPv6 prefix <=32
// silently mis-counted via the IPToUint32 reject-sentinel (0). The guard now
// returns 0 (no panic) for every non-IPv4 ipNet, while IPv4 ranges are
// unchanged.

// CountInRangeIPNet must return 0 and not panic for IPv6 ranges, regardless of
// prefix length (>32 was the historical panic, <=32 the silent mis-count).
func TestCountInRangeIPNet_RejectsIPv6NoPanic(t *testing.T) {
	tr := NewTrie()
	// Populate with a handful of IPv4 IPs so the trie is non-empty.
	for _, s := range []string{"192.168.1.1", "10.0.0.1", "2.3.4.5"} {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("failed to parse %s", s)
		}
		tr.Insert(ip)
	}

	ipv6Cases := []string{
		"2001:db8::/48",          // prefix > 32: historical negative-shift panic
		"2001:db8::/120",         // prefix > 32
		"2001:db8::/32",          // prefix <= 32: historical silent mis-count
		"::ffff:192.168.1.0/120", // IPv4-mapped IPv6: non-nil To4(), 16-byte mask
		"::/0",                   // IPv6 default route
	}
	for _, cidr := range ipv6Cases {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			t.Fatalf("net.ParseCIDR(%q) failed: %v", cidr, err)
		}
		var got uint32
		if !panicFree(func() { got = tr.CountInRangeIPNet(ipNet) }) {
			t.Fatalf("CountInRangeIPNet(%q) panicked", cidr)
		}
		// "::/0" routes to the maskBits==0 CountAll branch (above the guard);
		// it is harmless on an IPv4 trie but returns the total, not 0. Every
		// other IPv6 form must return 0 via the guard.
		if cidr == "::/0" {
			continue
		}
		if got != 0 {
			t.Errorf("CountInRangeIPNet(%q) = %d, want 0 (IPv6 rejected)", cidr, got)
		}
	}
}

// IPv4 ranges must still count correctly — the guard must not change any
// legitimate IPv4 result.
func TestCountInRangeIPNet_IPv4Unchanged(t *testing.T) {
	tr := NewTrie()
	for _, s := range []string{"192.168.1.1", "192.168.1.2", "192.168.1.3", "10.0.0.1"} {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("failed to parse %s", s)
		}
		tr.Insert(ip)
	}

	cases := []struct {
		cidr string
		want uint32
	}{
		{"192.168.1.0/24", 3},
		{"10.0.0.0/8", 1},
		{"0.0.0.0/0", 4}, // IPv4 default route routes to CountAll
		{"172.16.0.0/12", 0},
	}
	for _, c := range cases {
		_, ipNet, err := net.ParseCIDR(c.cidr)
		if err != nil {
			t.Fatalf("net.ParseCIDR(%q) failed: %v", c.cidr, err)
		}
		if got := tr.CountInRangeIPNet(ipNet); got != c.want {
			t.Errorf("CountInRangeIPNet(%q) = %d, want %d", c.cidr, got, c.want)
		}
	}
}

// panicFree runs f and reports whether it completed without panicking.
func panicFree(f func()) (ok bool) {
	defer func() {
		if r := recover(); r != nil {
			ok = false
		}
	}()
	f()
	return true
}
