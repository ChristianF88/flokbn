package jail_test

// This file proves the critical safety invariant of the whole tool:
//
//	A whitelisted IP or CIDR range — whether it came from the CIDR whitelist
//	file or from a User-Agent-whitelisted IP (added as a /32) — must NEVER be
//	covered by any entry in the published ban file, under ANY path, including
//	when it is also manually blacklisted, and including across jail reloads on
//	subsequent runs.
//
// The production publish chain (analysis.ProcessJailWithWhitelist and the live
// cli/api.go loop) is:
//
//	allWhitelists := whitelistCIDRs + UA-whitelist IPs as /32
//	filtered      := cidr.DropFullyWhitelisted(jailCIDRs, allWhitelists) // keeps PARTIAL overlaps whole
//	jail.Update(filtered)                                                // a whole range with whitelisted holes lands in jail
//	jail.JailToFile(...) / jail.FileToJail(...)                          // persists whole ranges, never the subtraction
//	activeBans := jail.ListActiveBans()
//	publishBans, publishBlacklist := cidr.ComposeBanLists(activeBans, blacklistCIDRs, allWhitelists) // THE choke point
//	jail.WriteBanFileWithBlacklist(banFile, publishBans, publishBlacklist)
//
// These tests drive that exact chain in the jail package (the cleanest seam
// that exercises jail.Update -> persistence -> ComposeBanLists -> ban file
// without importing cli/) and then PARSE THE ACTUAL EMITTED BAN FILE, asserting
// that no emitted ban CIDR covers any whitelisted address. The decisive guard
// is cidr.ComposeBanLists: DropFullyWhitelisted intentionally does NOT fragment
// partial overlaps (to avoid a /32-hole explosion), so the only thing standing
// between a whitelisted address and the ban file is ComposeBanLists. If that
// guard were reverted to a no-op, TestPublishedBanFile_* below would fail.

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ChristianF88/flokbn/cidr"
	"github.com/ChristianF88/flokbn/jail"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// cidrBounds parses an IPv4 CIDR into its inclusive [start,end] numeric range.
func cidrBounds(t *testing.T, c string) (start, end uint32) {
	t.Helper()
	_, n, err := net.ParseCIDR(c)
	if err != nil {
		t.Fatalf("parse CIDR %q: %v", c, err)
	}
	v4 := n.IP.To4()
	if v4 == nil {
		t.Fatalf("CIDR %q is not IPv4", c)
	}
	start = binary.BigEndian.Uint32(v4)
	end = start | ^binary.BigEndian.Uint32(n.Mask)
	return start, end
}

// rangesOverlap reports whether [aS,aE] and [bS,bE] share any address.
func rangesOverlap(aS, aE, bS, bE uint32) bool {
	return aS <= bE && bS <= aE
}

// assertNoWhitelistedAddressBanned is THE invariant check. Given the list of
// CIDRs actually emitted into the ban file and the set of whitelisted CIDRs, it
// fails if ANY whitelisted address is contained in ANY emitted ban CIDR.
//
// It checks two independent ways for robustness:
//  1. cidr.IsWhitelisted(banCIDR, whitelist) must be false — i.e. no emitted
//     ban CIDR is fully inside the whitelist. (This catches a whole ban range
//     that should have been dropped.)
//  2. A direct numeric containment test: no whitelisted range may overlap any
//     emitted ban range at all. (This catches partial leaks where a ban CIDR
//     covers part of a whitelisted range — the case (1) would miss because the
//     ban CIDR is larger than the whitelist entry.)
func assertNoWhitelistedAddressBanned(t *testing.T, emittedBans, whitelist []string) {
	t.Helper()

	for _, ban := range emittedBans {
		// Robustness check (1): a published ban CIDR must never itself be fully
		// covered by the whitelist — that ban should have been dropped.
		if cidr.IsWhitelisted(ban, whitelist) {
			t.Errorf("INVARIANT VIOLATED: published ban CIDR %q is fully covered by the whitelist (should have been dropped)", ban)
		}
	}

	// Robustness check (2): direct numeric containment. For every whitelisted
	// range and every emitted ban range, they must not overlap by even one
	// address. This is the strict end-to-end statement of the invariant.
	for _, w := range whitelist {
		wS, wE := cidrBounds(t, w)
		for _, ban := range emittedBans {
			bS, bE := cidrBounds(t, ban)
			if rangesOverlap(wS, wE, bS, bE) {
				t.Errorf("INVARIANT VIOLATED: whitelisted range %q [%d-%d] overlaps published ban %q [%d-%d]",
					w, wS, wE, ban, bS, bE)
			}
		}
	}
}

// parseBanFile returns the CIDRs emitted into a ban file (active bans +
// manual blacklist entries), exactly as a downstream consumer (fail2ban /
// firewall script) would read them: skip comment and blank lines.
func parseBanFile(t *testing.T, path string) []string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read ban file %q: %v", path, err)
	}
	var out []string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}

// publishToBanFile runs the real production publish chain and returns the
// CIDRs actually emitted into the ban file on disk. jailCIDRs are the ranges
// detected this run (post-merge, pre-whitelist), blacklist is the manual
// blacklist, whitelist is allWhitelists (CIDR file + UA /32s).
func publishToBanFile(t *testing.T, j *jail.Jail, banFile string, jailCIDRs, blacklist, whitelist []string) []string {
	t.Helper()

	// Pre-jail filter (keeps partial overlaps whole — matches production).
	filtered, _ := cidr.DropFullyWhitelisted(jailCIDRs, whitelist)

	if err := j.Update(filtered); err != nil {
		t.Fatalf("jail.Update: %v", err)
	}

	// THE publish choke point.
	activeBans := j.ListActiveBans()
	publishBans, publishBlacklist := cidr.ComposeBanLists(activeBans, blacklist, whitelist)

	if err := jail.WriteBanFileWithBlacklist(banFile, publishBans, publishBlacklist); err != nil {
		t.Fatalf("WriteBanFileWithBlacklist: %v", err)
	}
	return parseBanFile(t, banFile)
}

// ---------------------------------------------------------------------------
// (a) A jailed range that fully contains many UA-whitelisted /32s.
// ---------------------------------------------------------------------------

func TestPublishedBanFile_JailedRangeWithManyWhitelistedSlash32s(t *testing.T) {
	dir := t.TempDir()
	banFile := filepath.Join(dir, "bans.conf")

	// A single jailed /16 (10.10.0.0/16) — the kind of whole range
	// DropFullyWhitelisted lets through because it is only PARTIALLY covered.
	jailCIDRs := []string{"10.10.0.0/16"}

	// Many scattered UA-whitelisted /32s inside that /16 (the realistic
	// "thousands of bot IPs" case that motivated the no-fragment design).
	whitelist := make([]string, 0, 500)
	for i := 0; i < 500; i++ {
		// spread across the /16: 10.10.(i%256).(i*7%256)
		whitelist = append(whitelist, net.IPv4(10, 10, byte(i%256), byte((i*7)%256)).String()+"/32")
	}

	j := jail.NewJail()
	emitted := publishToBanFile(t, &j, banFile, jailCIDRs, nil, whitelist)

	if len(emitted) == 0 {
		t.Fatalf("expected the /16 to be published (carved around the holes), got nothing")
	}
	assertNoWhitelistedAddressBanned(t, emitted, whitelist)
}

// ---------------------------------------------------------------------------
// (b) A jailed /24 partially overlapping a whitelisted /25.
// ---------------------------------------------------------------------------

func TestPublishedBanFile_PartialOverlapWhitelistedSubRange(t *testing.T) {
	dir := t.TempDir()
	banFile := filepath.Join(dir, "bans.conf")

	jailCIDRs := []string{"192.168.1.0/24"} // the jailed range
	whitelist := []string{"192.168.1.0/25"} // lower half whitelisted
	whitelistedHole := "192.168.1.0/25"     // 192.168.1.0 - 192.168.1.127

	j := jail.NewJail()
	emitted := publishToBanFile(t, &j, banFile, jailCIDRs, nil, whitelist)

	// The banned half (192.168.1.128/25) must be present...
	wantBannedS, wantBannedE := cidrBounds(t, "192.168.1.128/25")
	covered := false
	for _, ban := range emitted {
		bS, bE := cidrBounds(t, ban)
		if bS <= wantBannedS && bE >= wantBannedE {
			covered = true
		}
	}
	if !covered {
		t.Errorf("expected the non-whitelisted half 192.168.1.128/25 to be banned; emitted=%v", emitted)
	}

	// ...and the whitelisted half must NOT be covered by any emitted ban.
	assertNoWhitelistedAddressBanned(t, emitted, []string{whitelistedHole})
}

// ---------------------------------------------------------------------------
// (c) A whitelisted CIDR that is ALSO in the manual blacklist — whitelist wins.
// ---------------------------------------------------------------------------

func TestPublishedBanFile_WhitelistBeatsManualBlacklist(t *testing.T) {
	dir := t.TempDir()
	banFile := filepath.Join(dir, "bans.conf")

	// The exact same range appears in both lists.
	blacklist := []string{"203.0.113.0/24", "198.51.100.0/24"}
	whitelist := []string{"203.0.113.0/24"} // also blacklisted -> must NOT appear

	// No jail activity this run; only the manual blacklist drives output.
	j := jail.NewJail()
	emitted := publishToBanFile(t, &j, banFile, nil, blacklist, whitelist)

	// The non-whitelisted blacklist entry must survive.
	survived := false
	for _, ban := range emitted {
		if ban == "198.51.100.0/24" {
			survived = true
		}
	}
	if !survived {
		t.Errorf("expected non-whitelisted manual blacklist entry 198.51.100.0/24 to be published; emitted=%v", emitted)
	}

	// The whitelisted-and-blacklisted range must NOT appear.
	assertNoWhitelistedAddressBanned(t, emitted, whitelist)
}

// (c2) A whitelisted /25 inside a blacklisted /24 — partial overlap: the
// whitelisted half must be carved out of the manual blacklist too.
func TestPublishedBanFile_WhitelistCarvesManualBlacklist(t *testing.T) {
	dir := t.TempDir()
	banFile := filepath.Join(dir, "bans.conf")

	blacklist := []string{"10.20.30.0/24"}
	whitelist := []string{"10.20.30.0/25"} // lower half whitelisted

	j := jail.NewJail()
	emitted := publishToBanFile(t, &j, banFile, nil, blacklist, whitelist)

	if len(emitted) == 0 {
		t.Fatalf("expected the non-whitelisted half of the blacklist /24 to be published")
	}
	assertNoWhitelistedAddressBanned(t, emitted, whitelist)
}

// ---------------------------------------------------------------------------
// (d) Cross-run persistence: a jail holding a whole range with whitelisted
// holes is written to disk, reloaded via FileToJail, and republished — the
// whitelisted addresses must still be excluded.
// ---------------------------------------------------------------------------

func TestPublishedBanFile_WhitelistReappliedAfterJailReload(t *testing.T) {
	dir := t.TempDir()
	jailFile := filepath.Join(dir, "jail.json")
	banFile := filepath.Join(dir, "bans.conf")

	// Run 1: a whole /16 enters the jail (it is only partially whitelisted,
	// so DropFullyWhitelisted keeps it whole). The whitelist subtraction is
	// applied ONLY at publish, NOT persisted into the jail.
	jailCIDRs := []string{"172.16.0.0/16"}
	whitelist := []string{
		"172.16.0.0/24",   // a whole /24 whitelisted
		"172.16.5.42/32",  // a scattered /32
		"172.16.200.0/25", // a /25 deep in the range
	}

	j1 := jail.NewJail()
	filtered, _ := cidr.DropFullyWhitelisted(jailCIDRs, whitelist)
	if err := j1.Update(filtered); err != nil {
		t.Fatalf("run1 Update: %v", err)
	}
	if err := jail.JailToFile(j1, jailFile); err != nil {
		t.Fatalf("JailToFile: %v", err)
	}

	// Sanity: the jail file persists the WHOLE range (proves the subtraction is
	// not baked into persistence — the next run must re-apply the whitelist).
	persisted, err := os.ReadFile(jailFile)
	if err != nil {
		t.Fatalf("read jail file: %v", err)
	}
	if !strings.Contains(string(persisted), "172.16.0.0/16") {
		t.Fatalf("expected the whole range 172.16.0.0/16 to be persisted in the jail; got: %s", persisted)
	}

	// Run 2: a fresh process reloads the jail from disk and publishes again,
	// with NO new jail activity. The whitelist must still be excluded from the
	// emitted ban file purely by the publish-time ComposeBanLists.
	j2, err := jail.FileToJail(jailFile)
	if err != nil {
		t.Fatalf("FileToJail: %v", err)
	}
	activeBans := j2.ListActiveBans()
	publishBans, publishBlacklist := cidr.ComposeBanLists(activeBans, nil, whitelist)
	if err := jail.WriteBanFileWithBlacklist(banFile, publishBans, publishBlacklist); err != nil {
		t.Fatalf("WriteBanFileWithBlacklist: %v", err)
	}
	emitted := parseBanFile(t, banFile)

	if len(emitted) == 0 {
		t.Fatalf("expected the reloaded /16 to be published (carved around the holes), got nothing")
	}
	assertNoWhitelistedAddressBanned(t, emitted, whitelist)

	// Extra: every individual whitelisted /32-equivalent address inside the
	// whitelisted sub-ranges must be uncovered (spot-check the /24 and /25).
	for _, addr := range []string{
		"172.16.0.0/32", "172.16.0.255/32", // inside whitelisted /24
		"172.16.5.42/32",                       // the scattered /32
		"172.16.200.0/32", "172.16.200.127/32", // inside whitelisted /25
	} {
		if cidr.IsWhitelisted(addr, emitted) {
			t.Errorf("INVARIANT VIOLATED after reload: whitelisted address %q is covered by an emitted ban", addr)
		}
		aS, aE := cidrBounds(t, addr)
		for _, ban := range emitted {
			bS, bE := cidrBounds(t, ban)
			if rangesOverlap(aS, aE, bS, bE) {
				t.Errorf("INVARIANT VIOLATED after reload: whitelisted address %q is inside emitted ban %q", addr, ban)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Guard regression: this asserts ComposeBanLists is a REAL guard, not a no-op.
// If ComposeBanLists/DropFullyWhitelisted were reverted to publish active bans
// verbatim (no whitelist applied at publish), the "guarded" emission below
// would cover the whitelisted addresses and assertNoWhitelistedAddressBanned
// would fail. We demonstrate both:
//   - the BUGGY publish (active bans verbatim) DOES leak — proving the test is
//     sensitive to the regression;
//   - the REAL publish (ComposeBanLists) does NOT leak.
// ---------------------------------------------------------------------------

func TestComposeBanLists_IsARealGuard(t *testing.T) {
	jailCIDRs := []string{"100.64.0.0/16"}
	whitelist := []string{"100.64.7.0/24", "100.64.250.0/24"}

	j := jail.NewJail()
	filtered, _ := cidr.DropFullyWhitelisted(jailCIDRs, whitelist)
	if err := j.Update(filtered); err != nil {
		t.Fatalf("Update: %v", err)
	}
	activeBans := j.ListActiveBans()

	// Buggy publish: active bans verbatim (simulating a reverted guard). The
	// whole /16 stays, so the whitelisted /24s ARE covered. Confirm a leak
	// exists in that world — this is what the real guard prevents.
	leaked := false
	for _, w := range whitelist {
		wS, wE := cidrBounds(t, w)
		for _, ban := range activeBans { // verbatim, NO ComposeBanLists
			bS, bE := cidrBounds(t, ban)
			if rangesOverlap(wS, wE, bS, bE) {
				leaked = true
			}
		}
	}
	if !leaked {
		t.Fatalf("test setup is not sensitive: the buggy (verbatim) publish should leak whitelisted ranges but did not")
	}

	// Real publish: ComposeBanLists must close that leak.
	publishBans, _ := cidr.ComposeBanLists(activeBans, nil, whitelist)
	assertNoWhitelistedAddressBanned(t, publishBans, whitelist)
}
