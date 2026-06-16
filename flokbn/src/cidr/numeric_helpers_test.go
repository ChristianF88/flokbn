package cidr

// Direct, deterministic unit tests for the numeric whitelist-subtraction
// helpers introduced by the perf rewrite. These assert the binary-search and
// 0xFFFFFFFF tail/wrap branches in isolation, independent of whether the
// differential fuzz (zz_diff_review_test.go) happens to generate them.

import (
	"net"
	"strings"
	"testing"
)

// mkIP builds a uint32 IPv4 address from octets.
func mkIP(a, b, c, d byte) uint32 {
	return uint32(a)<<24 | uint32(b)<<16 | uint32(c)<<8 | uint32(d)
}

func TestRangeFullyCovered(t *testing.T) {
	tests := []struct {
		name       string
		start, end uint32
		ranges     []rng32
		want       bool
	}{
		{"empty ranges", 10, 20, nil, false},
		{"start below all", 5, 8, []rng32{{10, 20}}, false},
		{"exact single cover", 10, 20, []rng32{{10, 20}}, true},
		{"interior single cover", 12, 18, []rng32{{10, 20}}, true},
		{"end beyond entry", 10, 21, []rng32{{10, 20}}, false},
		{"start before entry", 9, 20, []rng32{{10, 20}}, false},
		{"end exactly at entry end", 15, 20, []rng32{{10, 20}}, true},
		{"union-only (no single covers)", 10, 20, []rng32{{10, 15}, {16, 20}}, false},
		{"query above all", 30, 40, []rng32{{10, 20}}, false},
		{"second entry covers", 100, 150, []rng32{{10, 20}, {90, 200}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := rangeFullyCovered(tt.start, tt.end, tt.ranges); got != tt.want {
				t.Errorf("rangeFullyCovered(%d,%d,%v) = %v, want %v", tt.start, tt.end, tt.ranges, got, tt.want)
			}
		})
	}
}

func TestRangeIntersects(t *testing.T) {
	tests := []struct {
		name       string
		start, end uint32
		ranges     []rng32
		want       bool
	}{
		{"empty ranges", 10, 20, nil, false},
		{"disjoint left", 10, 50, []rng32{{100, 200}}, false},
		{"disjoint right", 100, 200, []rng32{{10, 50}}, false},
		{"touching boundary right", 50, 60, []rng32{{10, 50}}, true},
		{"touching boundary left", 5, 10, []rng32{{10, 50}}, true},
		{"contained", 40, 50, []rng32{{10, 100}}, true},
		{"spanning entry", 10, 100, []rng32{{40, 50}}, true},
		{"hits second range", 150, 160, []rng32{{10, 20}, {100, 200}}, true},
		{"falls in gap", 50, 60, []rng32{{10, 20}, {100, 200}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := rangeIntersects(tt.start, tt.end, tt.ranges); got != tt.want {
				t.Errorf("rangeIntersects(%d,%d,%v) = %v, want %v", tt.start, tt.end, tt.ranges, got, tt.want)
			}
		})
	}
}

// subtractToStrings runs subtractRanges and renders the result as CIDR strings.
func subtractToStrings(blackStart, blackEnd uint32, ranges []rng32) []string {
	ncs := subtractRanges(nil, blackStart, blackEnd, ranges)
	out := make([]string, len(ncs))
	for i, nc := range ncs {
		out[i] = nc.String()
	}
	return out
}

func TestSubtractRanges(t *testing.T) {
	tests := []struct {
		name       string
		blackStart uint32
		blackEnd   uint32
		ranges     []rng32
		want       string // joined with ","
	}{
		{
			name:       "no whitelist returns whole range optimally",
			blackStart: mkIP(10, 0, 0, 0), blackEnd: mkIP(10, 0, 0, 255),
			ranges: nil,
			want:   "10.0.0.0/24",
		},
		{
			name:       "fully covered subtracts to empty",
			blackStart: mkIP(10, 0, 0, 0), blackEnd: mkIP(10, 0, 0, 255),
			ranges: []rng32{{mkIP(10, 0, 0, 0), mkIP(10, 0, 0, 255)}},
			want:   "",
		},
		{
			name:       "interior hole",
			blackStart: mkIP(10, 0, 0, 0), blackEnd: mkIP(10, 0, 0, 255),
			ranges: []rng32{{mkIP(10, 0, 0, 64), mkIP(10, 0, 0, 127)}},
			want:   "10.0.0.0/26,10.0.0.128/25",
		},
		{
			name:       "0xFFFFFFFF tail early-return",
			blackStart: mkIP(255, 255, 255, 0), blackEnd: mkIP(255, 255, 255, 255),
			ranges: []rng32{{mkIP(255, 255, 255, 128), 0xFFFFFFFF}},
			want:   "255.255.255.0/25",
		},
		{
			name:       "clip-left (whitelist starts before window)",
			blackStart: mkIP(10, 0, 0, 0), blackEnd: mkIP(10, 0, 0, 255),
			ranges: []rng32{{mkIP(9, 255, 255, 0), mkIP(10, 0, 0, 63)}},
			want:   "10.0.0.64/26,10.0.0.128/25",
		},
		{
			name:       "skip-left then break-right around a single hole",
			blackStart: mkIP(10, 0, 0, 0), blackEnd: mkIP(10, 0, 0, 255),
			ranges: []rng32{
				{mkIP(9, 0, 0, 0), mkIP(9, 0, 0, 255)},    // entirely before window -> skip (continue)
				{mkIP(10, 0, 0, 64), mkIP(10, 0, 0, 127)}, // the hole
				{mkIP(11, 0, 0, 0), mkIP(11, 0, 0, 255)},  // entirely after window -> break
			},
			want: "10.0.0.0/26,10.0.0.128/25",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := strings.Join(subtractToStrings(tt.blackStart, tt.blackEnd, tt.ranges), ",")
			if got != tt.want {
				t.Errorf("subtractRanges = %q, want %q", got, tt.want)
			}
		})
	}
}

// mustNets parses CIDR strings into *net.IPNet (helper for IsWhitelistedIPNet).
func mustNets(t *testing.T, cidrs ...string) []*net.IPNet {
	t.Helper()
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			t.Fatalf("ParseCIDR(%q): %v", c, err)
		}
		nets = append(nets, n)
	}
	return nets
}

// TestIsWhitelistedIPNet_MaskGuard locks the IPv4-only mask-length guard: a
// 16-byte (IPv6/IPv4-mapped) mask must never satisfy whitelisting, and the
// guard must be a no-op for genuine IPv4 inputs.
func TestIsWhitelistedIPNet_MaskGuard(t *testing.T) {
	_, ipv4Candidate, _ := net.ParseCIDR("10.0.0.0/24")
	_, mappedCandidate, _ := net.ParseCIDR("::ffff:10.0.0.0/120")

	// Mapped-IPv6 whitelist entry must NOT whitelist a real IPv4 candidate.
	if IsWhitelistedIPNet(ipv4Candidate, mustNets(t, "::ffff:10.0.0.0/120")) {
		t.Error("mapped-IPv6 whitelist entry wrongly whitelisted an IPv4 candidate")
	}
	// Non-IPv4 candidate is never whitelisted (guard returns false).
	if IsWhitelistedIPNet(mappedCandidate, mustNets(t, "10.0.0.0/8")) {
		t.Error("non-IPv4 candidate wrongly reported as whitelisted")
	}
	// Guard is a no-op for real IPv4: a covering IPv4 whitelist still whitelists.
	if !IsWhitelistedIPNet(ipv4Candidate, mustNets(t, "10.0.0.0/8")) {
		t.Error("IPv4 candidate covered by IPv4 whitelist should be whitelisted")
	}
}

// TestDropFullyWhitelisted_MappedIPv6Ignored confirms the guard inside
// IsWhitelistedIPNet protects DropFullyWhitelisted's caller too.
func TestDropFullyWhitelisted_MappedIPv6Ignored(t *testing.T) {
	kept, dropped := DropFullyWhitelisted(
		[]string{"10.0.0.0/24"},
		[]string{"::ffff:10.0.0.0/120"},
	)
	if dropped != 0 || len(kept) != 1 || kept[0] != "10.0.0.0/24" {
		t.Errorf("mapped-IPv6 whitelist must not drop an IPv4 ban: kept=%v dropped=%d", kept, dropped)
	}
}
