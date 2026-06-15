package cli

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ChristianF88/flokbn/config"
	"github.com/ChristianF88/flokbn/ingestor"
	"github.com/ChristianF88/flokbn/jail"
)

// Log messages the live loop emits for list handling; the tests below assert
// on them instead of the former JSON warning types.
const (
	whitelistAppliedMsg = "whitelist filtering prevented CIDRs from being added to jail"
	blacklistAppliedMsg = "added manual blacklist entries to ban file"
)

// ============================================================================
// Whitelist/blacklist helpers
// ============================================================================

// writeListFile writes one CIDR per line into name under a fresh temp dir and
// returns the file path.
func writeListFile(t *testing.T, name string, cidrs []string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(strings.Join(cidrs, "\n")+"\n"), 0644); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
	return path
}

// newLiveConfigWithLists wraps newLiveConfig and wires whitelist/blacklist
// files into the global config. nil lists leave the corresponding field unset.
func newLiveConfigWithLists(t *testing.T, windows map[string]*config.SlidingTrieConfig, whitelist, blacklist []string) *config.Config {
	t.Helper()
	cfg := newLiveConfig(t, windows)
	if whitelist != nil {
		cfg.Global.Whitelist = writeListFile(t, "whitelist.txt", whitelist)
	}
	if blacklist != nil {
		cfg.Global.Blacklist = writeListFile(t, "blacklist.txt", blacklist)
	}
	return cfg
}

func detectedCIDRSet(snap *statsSnapshot) map[string]bool {
	set := map[string]bool{}
	for _, d := range detectedNow(snap) {
		set[d.CIDR] = true
	}
	return set
}

// ============================================================================
// Tests
// ============================================================================

func TestRunLiveLoop_WhitelistPreventsBan(t *testing.T) {
	t.Run("FullBlock", func(t *testing.T) {
		now := time.Now()
		batch := append(hotBlock(10, 5, 5, now, "/api/item"), noiseRequests(now, "/api/item")...)
		fake := &fakeIngestor{batches: [][]ingestor.Request{batch}, closeAfterDrain: true}
		cfg := newLiveConfigWithLists(t, map[string]*config.SlidingTrieConfig{
			"w": newWindowConfig(t, "", true),
		}, []string{"10.5.5.0/24"}, nil)

		h := startLoop(t, fake, cfg)
		if err := h.wait(5 * time.Second); err != nil {
			t.Fatalf("runLiveLoop returned error: %v", err)
		}
		events := h.drainEvents()

		iters := iterationEvents(events)
		if len(iters) == 0 {
			t.Fatal("no iteration log records emitted")
		}
		it, snap := parseIteration(t, iters[0].rec), iters[0].snap
		if !detectedCIDRSet(snap)["10.5.5.0/24"] {
			t.Errorf("detected CIDRs = %+v, want 10.5.5.0/24 detected (detection is unfiltered)", detectedNow(snap))
		}
		if it.ActiveBans != 0 {
			t.Errorf("iteration active_bans = %d, want 0 (whitelisted)", it.ActiveBans)
		}
		if bans := banCIDRs(t, cfg.GetBanFile()); len(bans) != 0 {
			t.Errorf("ban file CIDRs = %v, want none", bans)
		}
		if _, _, found := findPrisoner(t, cfg.GetJailFile(), "10.5.5.0/24"); found {
			t.Error("whitelisted 10.5.5.0/24 must not be jailed")
		}
		if countMessages(events, whitelistAppliedMsg) == 0 {
			t.Error("missing whitelist-applied log record")
		}
	})

	t.Run("PartialOverlapJailsWholeFiltersAtPublish", func(t *testing.T) {
		// A detected /24 whose lower half (/25) is whitelisted. The jail stores
		// the range WHOLE (it is only partially whitelisted) and the whitelist
		// is applied at the publish choke point, so the emitted ban file still
		// excludes the whitelisted half. The pre-jail path deliberately does NOT
		// fragment the range around the whitelist: doing so for many scattered
		// /32s explodes a handful of ranges into tens of thousands of fragments
		// and stalls the jail update super-linearly.
		now := time.Now()
		batch := append(hotBlock(10, 5, 5, now, "/api/item"), noiseRequests(now, "/api/item")...)
		fake := &fakeIngestor{batches: [][]ingestor.Request{batch}, closeAfterDrain: true}
		cfg := newLiveConfigWithLists(t, map[string]*config.SlidingTrieConfig{
			"w": newWindowConfig(t, "", true),
		}, []string{"10.5.5.0/25"}, nil)

		h := startLoop(t, fake, cfg)
		if err := h.wait(5 * time.Second); err != nil {
			t.Fatalf("runLiveLoop returned error: %v", err)
		}
		events := h.drainEvents()

		iters := iterationEvents(events)
		if len(iters) == 0 {
			t.Fatal("no iteration log records emitted")
		}
		snap := iters[0].snap
		// Jail keeps the range whole — no fragmentation.
		if bans := jailActiveCIDRs(snap); len(bans) != 1 || bans[0] != "10.5.5.0/24" {
			t.Errorf("jail active bans = %v, want [10.5.5.0/24] (range kept whole)", bans)
		}
		// Enforcement still honors the whitelist: the published ban file
		// excludes the whitelisted /25 half.
		bans := banCIDRs(t, cfg.GetBanFile())
		if len(bans) != 1 || bans[0] != "10.5.5.128/25" {
			t.Errorf("ban file CIDRs = %v, want [10.5.5.128/25] (whitelist applied at publish)", bans)
		}
		if _, _, found := findPrisoner(t, cfg.GetJailFile(), "10.5.5.0/24"); !found {
			t.Error("10.5.5.0/24 should be jailed whole")
		}
		if _, _, found := findPrisoner(t, cfg.GetJailFile(), "10.5.5.0/25"); found {
			t.Error("jail must not be fragmented into /25 halves")
		}
	})
}

func TestRunLiveLoop_BlacklistAppearsInBanFile(t *testing.T) {
	now := time.Now()
	fake := &fakeIngestor{
		batches: [][]ingestor.Request{
			hotBlock(10, 5, 5, now, "/api/item"),
			noiseRequests(now, "/api/item"),
		},
		closeAfterDrain: true,
	}
	cfg := newLiveConfigWithLists(t, map[string]*config.SlidingTrieConfig{
		"w": newWindowConfig(t, "", true),
	}, nil, []string{"203.0.113.0/24"})

	h := startLoop(t, fake, cfg)
	if err := h.wait(5 * time.Second); err != nil {
		t.Fatalf("runLiveLoop returned error: %v", err)
	}
	events := h.drainEvents()

	if got := len(iterationEvents(events)); got != 2 {
		t.Fatalf("iteration log records = %d, want 2 (two iterations)", got)
	}

	banned := map[string]bool{}
	for _, c := range banCIDRs(t, cfg.GetBanFile()) {
		banned[c] = true
	}
	if !banned["10.5.5.0/24"] || !banned["203.0.113.0/24"] {
		t.Errorf("ban file CIDRs = %v, want detected 10.5.5.0/24 and blacklisted 203.0.113.0/24", banned)
	}

	raw, err := os.ReadFile(cfg.GetBanFile())
	if err != nil {
		t.Fatalf("reading ban file: %v", err)
	}
	if !strings.Contains(string(raw), "# Manual blacklist entries:") {
		t.Errorf("ban file missing blacklist section marker, got:\n%s", raw)
	}

	if got := countMessages(events, blacklistAppliedMsg); got != 1 {
		t.Errorf("blacklist-applied log records = %d, want exactly 1 across the run", got)
	}
}

func TestRunLiveLoop_PreexistingWhitelistedBanExcludedFromBanFile(t *testing.T) {
	now := time.Now()
	fake := &fakeIngestor{
		batches:         [][]ingestor.Request{noiseRequests(now, "/api/item")},
		closeAfterDrain: true,
	}
	cfg := newLiveConfigWithLists(t, map[string]*config.SlidingTrieConfig{
		"w": newWindowConfig(t, "", true),
	}, []string{"192.168.0.0/24"}, nil)

	// Pre-seed the jail: 192.168.0.0/24 is an active prisoner whose ban just
	// started, so it stays active throughout the run.
	seeded := jail.NewJail()
	seeded.Cells[0].Prisoners = append(seeded.Cells[0].Prisoners, jail.Prisoner{
		CIDR:      "192.168.0.0/24",
		BanStart:  now,
		BanActive: true,
	})
	seeded.AllCIDRs = append(seeded.AllCIDRs, "192.168.0.0/24")
	if err := jail.JailToFile(seeded, cfg.GetJailFile()); err != nil {
		t.Fatalf("seeding jail file: %v", err)
	}

	h := startLoop(t, fake, cfg)
	if err := h.wait(5 * time.Second); err != nil {
		t.Fatalf("runLiveLoop returned error: %v", err)
	}
	events := h.drainEvents()

	if bans := banCIDRs(t, cfg.GetBanFile()); len(bans) != 0 {
		t.Errorf("ban file CIDRs = %v, want none (active ban is whitelisted)", bans)
	}
	if _, active, found := findPrisoner(t, cfg.GetJailFile(), "192.168.0.0/24"); !found || !active {
		t.Errorf("prisoner 192.168.0.0/24 found=%v active=%v, want it to stay in jail active", found, active)
	}
	// The whitelisted prisoner stays in jail truth but must never reach the
	// ban-file view (what /bans serves and the iteration counts as active).
	for _, ev := range iterationEvents(events) {
		it := parseIteration(t, ev.rec)
		if it.ActiveBans != 0 {
			t.Errorf("iteration active_bans = %d, want 0 (whitelisted)", it.ActiveBans)
		}
		if strings.Contains(ev.snap.banFileContent, "192.168.0.0/24") {
			t.Errorf("ban file content must exclude whitelisted 192.168.0.0/24:\n%s", ev.snap.banFileContent)
		}
	}
}

func TestRunLiveLoop_WhitelistLoadFailureFailsLoud(t *testing.T) {
	windows := func() map[string]*config.SlidingTrieConfig {
		return map[string]*config.SlidingTrieConfig{"w": newWindowConfig(t, "", true)}
	}

	cases := []struct {
		name    string
		setup   func(cfg *config.Config)
		wantSub string
	}{
		{
			name: "WhitelistMissingFile",
			setup: func(cfg *config.Config) {
				cfg.Global.Whitelist = filepath.Join(t.TempDir(), "does-not-exist.txt")
			},
			wantSub: "whitelist",
		},
		{
			name: "WhitelistInvalidCIDR",
			setup: func(cfg *config.Config) {
				cfg.Global.Whitelist = writeListFile(t, "whitelist.txt", []string{"not-a-cidr"})
			},
			wantSub: "whitelist",
		},
		{
			name: "BlacklistMissingFile",
			setup: func(cfg *config.Config) {
				cfg.Global.Blacklist = filepath.Join(t.TempDir(), "does-not-exist.txt")
			},
			wantSub: "blacklist",
		},
		{
			name: "BlacklistInvalidCIDR",
			setup: func(cfg *config.Config) {
				cfg.Global.Blacklist = writeListFile(t, "blacklist.txt", []string{"not-a-cidr"})
			},
			wantSub: "blacklist",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeIngestor{}
			cfg := newLiveConfig(t, windows())
			tc.setup(cfg)

			err := runLiveLoop(context.Background(), fake, cfg, discardLogger(t), nil)
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("err = %v, want error mentioning %q", err, tc.wantSub)
			}
			if got := fake.acceptCallCount(); got != 0 {
				t.Errorf("Accept calls = %d, want 0 (must fail before accepting)", got)
			}
		})
	}
}

// ============================================================================
// User-Agent lists (live parity) + whitelist-always-wins combinations
// ============================================================================

// newLiveConfigWithUALists additionally wires User-Agent whitelist/blacklist
// pattern files (one exact UA string per line) into the global config.
func newLiveConfigWithUALists(t *testing.T, windows map[string]*config.SlidingTrieConfig, cidrWhitelist, cidrBlacklist, uaWhitelist, uaBlacklist []string) *config.Config {
	t.Helper()
	cfg := newLiveConfigWithLists(t, windows, cidrWhitelist, cidrBlacklist)
	if uaWhitelist != nil {
		cfg.Global.UserAgentWhitelist = writeListFile(t, "ua_whitelist.txt", uaWhitelist)
	}
	if uaBlacklist != nil {
		cfg.Global.UserAgentBlacklist = writeListFile(t, "ua_blacklist.txt", uaBlacklist)
	}
	return cfg
}

// assertNoBanCovers fails if any ban-file CIDR contains ip.
func assertNoBanCovers(t *testing.T, cidrs []string, ip string) {
	t.Helper()
	parsed := net.ParseIP(ip)
	for _, c := range cidrs {
		_, ipNet, err := net.ParseCIDR(c)
		if err != nil {
			t.Fatalf("ban file contains invalid CIDR %q: %v", c, err)
		}
		if ipNet.Contains(parsed) {
			t.Errorf("ban file CIDR %s covers whitelisted IP %s", c, ip)
		}
	}
}

func TestRunLiveLoop_UABlacklistForceJails(t *testing.T) {
	now := time.Now()
	evil := mkRequest(198, 51, 100, 7, now, "/login")
	evil.UserAgent = "EvilBot/1.0"
	batch := append(noiseRequests(now, "/api/item"), evil)
	fake := &fakeIngestor{batches: [][]ingestor.Request{batch}, closeAfterDrain: true}
	cfg := newLiveConfigWithUALists(t, map[string]*config.SlidingTrieConfig{
		"w": newWindowConfig(t, "", true),
	}, nil, nil, nil, []string{"EvilBot/1.0"})

	h := startLoop(t, fake, cfg)
	if err := h.wait(5 * time.Second); err != nil {
		t.Fatalf("runLiveLoop returned error: %v", err)
	}
	events := h.drainEvents()

	iters := iterationEvents(events)
	if len(iters) == 0 {
		t.Fatal("no iteration log records emitted")
	}
	banned := map[string]bool{}
	for _, c := range banCIDRs(t, cfg.GetBanFile()) {
		banned[c] = true
	}
	if !banned["198.51.100.7/32"] {
		t.Errorf("ban file CIDRs = %v, want UA-blacklisted 198.51.100.7/32", banned)
	}
	if _, active, found := findPrisoner(t, cfg.GetJailFile(), "198.51.100.7/32"); !found || !active {
		t.Errorf("prisoner 198.51.100.7/32 found=%v active=%v, want jailed and active", found, active)
	}
	ua := iters[0].snap.Lists.UserAgentLists
	if ua.BlacklistHitsTotal != 1 || ua.ActiveBlacklistIPs != 1 {
		t.Errorf("ua stats = %+v, want 1 blacklist hit and 1 active blacklist IP", ua)
	}
}

func TestRunLiveLoop_UAWhitelistImmunizesClusteredIP(t *testing.T) {
	now := time.Now()
	good := mkRequest(10, 5, 5, 10, now, "/health")
	good.UserAgent = "GoodBot/1.0"
	batch := append(hotBlock(10, 5, 5, now, "/api/item"), good)
	fake := &fakeIngestor{batches: [][]ingestor.Request{batch}, closeAfterDrain: true}
	cfg := newLiveConfigWithUALists(t, map[string]*config.SlidingTrieConfig{
		"w": newWindowConfig(t, "", true),
	}, nil, nil, []string{"GoodBot/1.0"}, nil)

	h := startLoop(t, fake, cfg)
	if err := h.wait(5 * time.Second); err != nil {
		t.Fatalf("runLiveLoop returned error: %v", err)
	}
	events := h.drainEvents()

	iters := iterationEvents(events)
	if len(iters) == 0 {
		t.Fatal("no iteration log records emitted")
	}
	bans := banCIDRs(t, cfg.GetBanFile())
	if len(bans) == 0 {
		t.Fatal("ban file empty, want hot /24 minus the UA-whitelisted IP")
	}
	// 10.5.5.10 sent one request with a whitelisted UA: it must be immune,
	// while the rest of the clustered /24 stays banned.
	assertNoBanCovers(t, bans, "10.5.5.10")
	covered := false
	target := net.ParseIP("10.5.5.11")
	for _, c := range bans {
		if _, ipNet, err := net.ParseCIDR(c); err == nil && ipNet.Contains(target) {
			covered = true
		}
	}
	if !covered {
		t.Errorf("ban file %v must still cover 10.5.5.11 (not whitelisted)", bans)
	}
	ua := iters[0].snap.Lists.UserAgentLists
	if ua.WhitelistHitsTotal != 1 || ua.ActiveWhitelistIPs != 1 {
		t.Errorf("ua stats = %+v, want 1 whitelist hit and 1 active whitelist IP", ua)
	}
}

func TestRunLiveLoop_ManualBlacklistRespectsWhitelist(t *testing.T) {
	now := time.Now()
	fake := &fakeIngestor{
		batches:         [][]ingestor.Request{noiseRequests(now, "/api/item")},
		closeAfterDrain: true,
	}
	cfg := newLiveConfigWithLists(t, map[string]*config.SlidingTrieConfig{
		"w": newWindowConfig(t, "", true),
	}, []string{"203.0.113.0/25"}, []string{"203.0.113.0/24"})

	h := startLoop(t, fake, cfg)
	if err := h.wait(5 * time.Second); err != nil {
		t.Fatalf("runLiveLoop returned error: %v", err)
	}
	h.drainEvents()

	bans := banCIDRs(t, cfg.GetBanFile())
	banned := map[string]bool{}
	for _, c := range bans {
		banned[c] = true
	}
	if banned["203.0.113.0/24"] || banned["203.0.113.0/25"] {
		t.Errorf("ban file %v must not cover the whitelisted half 203.0.113.0/25", bans)
	}
	if !banned["203.0.113.128/25"] {
		t.Errorf("ban file %v missing the non-whitelisted half 203.0.113.128/25", bans)
	}
	assertNoBanCovers(t, bans, "203.0.113.5")
}

func TestRunLiveLoop_UAWhitelistBeatsManualBlacklist(t *testing.T) {
	now := time.Now()
	good := mkRequest(203, 0, 113, 9, now, "/health")
	good.UserAgent = "GoodBot/1.0"
	batch := append(noiseRequests(now, "/api/item"), good)
	fake := &fakeIngestor{batches: [][]ingestor.Request{batch}, closeAfterDrain: true}
	cfg := newLiveConfigWithUALists(t, map[string]*config.SlidingTrieConfig{
		"w": newWindowConfig(t, "", true),
	}, nil, []string{"203.0.113.0/24"}, []string{"GoodBot/1.0"}, nil)

	h := startLoop(t, fake, cfg)
	if err := h.wait(5 * time.Second); err != nil {
		t.Fatalf("runLiveLoop returned error: %v", err)
	}
	h.drainEvents()

	bans := banCIDRs(t, cfg.GetBanFile())
	if len(bans) == 0 {
		t.Fatal("ban file empty, want manual blacklist remainder")
	}
	// 203.0.113.9 sent a whitelisted UA: the manual blacklist /24 must be
	// published with that IP punched out.
	assertNoBanCovers(t, bans, "203.0.113.9")
	covered := false
	target := net.ParseIP("203.0.113.10")
	for _, c := range bans {
		if _, ipNet, err := net.ParseCIDR(c); err == nil && ipNet.Contains(target) {
			covered = true
		}
	}
	if !covered {
		t.Errorf("ban file %v must still cover 203.0.113.10 (not whitelisted)", bans)
	}
}

func TestRunLiveLoop_UAListLoadFailureFailsLoud(t *testing.T) {
	fake := &fakeIngestor{}
	cfg := newLiveConfig(t, map[string]*config.SlidingTrieConfig{
		"w": newWindowConfig(t, "", true),
	})
	cfg.Global.UserAgentWhitelist = filepath.Join(t.TempDir(), "does-not-exist.txt")

	err := runLiveLoop(context.Background(), fake, cfg, discardLogger(t), nil)
	if err == nil || !strings.Contains(err.Error(), "user-agent whitelist") {
		t.Fatalf("err = %v, want error mentioning user-agent whitelist", err)
	}
	if got := fake.acceptCallCount(); got != 0 {
		t.Errorf("Accept calls = %d, want 0 (must fail before accepting)", got)
	}
}

func TestPurgeExpired(t *testing.T) {
	now := time.Now()
	m := map[uint32]time.Time{
		1: now.Add(-2 * time.Minute), // expired
		2: now.Add(-30 * time.Second),
		3: now,
	}
	purgeExpired(m, now.Add(-time.Minute))
	if _, ok := m[1]; ok {
		t.Error("entry 1 expired, want purged")
	}
	if len(m) != 2 {
		t.Errorf("map size = %d, want 2 (entries 2 and 3 kept)", len(m))
	}
}
