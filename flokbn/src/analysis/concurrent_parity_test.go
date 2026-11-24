package analysis

import (
	"testing"

	"github.com/ChristianF88/flokbn/accesslog"
	"github.com/ChristianF88/flokbn/cidr"
	"github.com/ChristianF88/flokbn/config"
)

// filterCounts holds the out-parameters that both filter paths populate, so the
// concurrent and sequential paths can be compared field-for-field.
type filterCounts struct {
	filteredRequestCount int
	invalidIPCount       int
	uaWhitelistExcluded  int
	whitelistIPs         []string
	blacklistIPs         []string
	ipsToInsert          []uint32
}

// ipSetStrings renders the IPs a filter collected for a UA list as the set of
// their dotted-quad strings (each IP once, order unspecified; the assertions
// below compare them as sets). The filter reports one entry per request.
func ipSetStrings(ips []uint32) []string {
	seen := make(map[uint32]struct{}, len(ips))
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		if _, dup := seen[ip]; dup {
			continue
		}
		seen[ip] = struct{}{}
		out = append(out, accesslog.Uint32ToIPString(ip))
	}
	return out
}

// toFilterCounts maps a filterResult onto the fields the parity tests compare.
func toFilterCounts(res filterResult) filterCounts {
	return filterCounts{
		filteredRequestCount: len(res.ips),
		invalidIPCount:       res.invalid,
		uaWhitelistExcluded:  res.uaExcluded,
		whitelistIPs:         ipSetStrings(res.uaWhitelistIPs),
		blacklistIPs:         ipSetStrings(res.uaBlacklistIPs),
		ipsToInsert:          res.ips,
	}
}

// runSequential drives filterSequential over reqs and returns the resulting counts.
func runSequential(reqs []accesslog.Request, tc *config.TrieConfig, m *cidr.UserAgentMatcher) filterCounts {
	var noBounds timeBounds // no time filters in this test
	return toFilterCounts(filterSequential(reqs, tc, noBounds, m))
}

// runConcurrent drives filterConcurrent over reqs and returns the counts.
func runConcurrent(t *testing.T, reqs []accesslog.Request, tc *config.TrieConfig, m *cidr.UserAgentMatcher) filterCounts {
	t.Helper()
	var noBounds timeBounds // no time filters in this test
	return toFilterCounts(filterConcurrent(reqs, tc, noBounds, m))
}

// TestConcurrentSequentialParity_ZeroIPWhitelistedUA is the regression test for
// the URGENT-15 parity bug: a request with IPUint32==0 whose User-Agent matches
// the global UA whitelist was counted as neither invalid nor UA-excluded by the
// concurrent collector, while the sequential path counted it as invalid. After
// the fix both paths must produce identical SkippedInvalidIPs / UAWhitelistExcluded
// / TotalRequestsAfterFiltering for the same input.
//
// IPv4-only: every nonzero IP below is a literal IPv4 uint32; the "missing IP"
// cases use IPUint32==0 (the parser's representation of an unparseable/empty %h
// host field). No IPv6 is introduced anywhere.
func TestConcurrentSequentialParity_ZeroIPWhitelistedUA(t *testing.T) {
	// Global UA whitelist (exact-match) contains "Googlebot"; blacklist contains
	// "evilbot". A whitelisted UA removes the request; a blacklisted UA's IP is
	// collected as a /32.
	matcher := cidr.NewUserAgentMatcher([]string{"Googlebot"}, []string{"evilbot"})

	// IPv4 helper: a.b.c.d -> uint32 (big-endian, matching accesslog.Uint32ToIPString).
	ipv4 := func(a, b, c, d uint32) uint32 {
		return a<<24 | b<<16 | c<<8 | d
	}

	reqs := []accesslog.Request{
		// (a) normal IPs, non-whitelisted UA -> included.
		{IPUint32: ipv4(192, 168, 1, 1), UserAgent: "Mozilla/5.0"},
		{IPUint32: ipv4(192, 168, 1, 2), UserAgent: "Mozilla/5.0"},
		// (b) zero IP + UA-whitelisted -> must count as INVALID on BOTH paths
		//     (this is the bug: previously the concurrent path counted it as
		//     neither invalid nor UA-excluded). Must NOT be collected as a
		//     whitelist /32 (0.0.0.0 must never be collected).
		{IPUint32: 0, UserAgent: "Googlebot"},
		{IPUint32: 0, UserAgent: "Googlebot"},
		// (c) zero IP + non-whitelisted UA -> invalid on both paths.
		{IPUint32: 0, UserAgent: "Mozilla/5.0"},
		// (d) nonzero IP + UA-whitelisted -> UA-excluded, IP collected as whitelist /32.
		{IPUint32: ipv4(10, 0, 0, 5), UserAgent: "Googlebot"},
		// (e) nonzero IP + UA-blacklisted -> included AND IP collected as blacklist /32.
		{IPUint32: ipv4(10, 0, 0, 9), UserAgent: "evilbot"},
		// (f) zero IP + UA-blacklisted -> invalid on both paths; must NOT be
		//     collected as a blacklist /32.
		{IPUint32: 0, UserAgent: "evilbot"},
	}

	// No per-trie regex/time filters, but the global UA matcher makes hasFilters
	// true in production; here we exercise the filter functions directly.
	tc := &config.TrieConfig{}

	seq := runSequential(reqs, tc, matcher)
	con := runConcurrent(t, reqs, tc, matcher)

	if seq.invalidIPCount != con.invalidIPCount {
		t.Errorf("SkippedInvalidIPs diverged: sequential=%d concurrent=%d", seq.invalidIPCount, con.invalidIPCount)
	}
	if seq.uaWhitelistExcluded != con.uaWhitelistExcluded {
		t.Errorf("UAWhitelistExcluded diverged: sequential=%d concurrent=%d", seq.uaWhitelistExcluded, con.uaWhitelistExcluded)
	}
	if seq.filteredRequestCount != con.filteredRequestCount {
		t.Errorf("TotalRequestsAfterFiltering diverged: sequential=%d concurrent=%d", seq.filteredRequestCount, con.filteredRequestCount)
	}

	// Expected absolute values (sequential is the reference behavior):
	//  invalid: (b)x2 + (c) + (f) = 4
	//  uaWhitelistExcluded: (d) = 1
	//  filteredRequestCount: (a)x2 + (e) = 3
	if seq.invalidIPCount != 4 {
		t.Errorf("expected 4 invalid IPs, got %d (sequential)", seq.invalidIPCount)
	}
	if seq.uaWhitelistExcluded != 1 {
		t.Errorf("expected 1 UA-whitelist-excluded, got %d (sequential)", seq.uaWhitelistExcluded)
	}
	if seq.filteredRequestCount != 3 {
		t.Errorf("expected 3 filtered/inserted, got %d (sequential)", seq.filteredRequestCount)
	}

	// A 0.0.0.0 entry must never be collected as a UA whitelist/blacklist /32 on
	// either path (it is converted to a /32 for jail/ban processing).
	zeroIP := accesslog.Uint32ToIPString(0)
	for _, ip := range append(append([]string{}, seq.whitelistIPs...), con.whitelistIPs...) {
		if ip == zeroIP {
			t.Errorf("0.0.0.0 must not be collected as a UA whitelist IP")
		}
	}
	for _, ip := range append(append([]string{}, seq.blacklistIPs...), con.blacklistIPs...) {
		if ip == zeroIP {
			t.Errorf("0.0.0.0 must not be collected as a UA blacklist IP")
		}
	}

	// The collected whitelist/blacklist IP SETS must match between paths.
	if !sameStringSet(seq.whitelistIPs, con.whitelistIPs) {
		t.Errorf("whitelist IP sets diverged: sequential=%v concurrent=%v", seq.whitelistIPs, con.whitelistIPs)
	}
	if !sameStringSet(seq.blacklistIPs, con.blacklistIPs) {
		t.Errorf("blacklist IP sets diverged: sequential=%v concurrent=%v", seq.blacklistIPs, con.blacklistIPs)
	}
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]int, len(a))
	for _, s := range a {
		seen[s]++
	}
	for _, s := range b {
		seen[s]--
	}
	for _, v := range seen {
		if v != 0 {
			return false
		}
	}
	return true
}
