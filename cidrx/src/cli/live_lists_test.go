package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ChristianF88/cidrx/config"
	"github.com/ChristianF88/cidrx/ingestor"
	"github.com/ChristianF88/cidrx/jail"
	"github.com/ChristianF88/cidrx/output"
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

// liveStatsFrom extracts every LiveStats from a drained output slice.
func liveStatsFrom(outs []*output.JSONOutput) []*output.LiveStats {
	var stats []*output.LiveStats
	for _, o := range outs {
		if o.LiveStats != nil {
			stats = append(stats, o.LiveStats)
		}
	}
	return stats
}

// countWarnings counts warnings of the given type across all outputs.
func countWarnings(outs []*output.JSONOutput, warningType string) int {
	n := 0
	for _, o := range outs {
		for _, w := range o.Warnings {
			if w.Type == warningType {
				n++
			}
		}
	}
	return n
}

func detectedCIDRSet(stats *output.LiveStats) map[string]bool {
	set := map[string]bool{}
	for _, d := range stats.DetectedCIDRs {
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
		outs := h.drainOutputs()

		allStats := liveStatsFrom(outs)
		if len(allStats) == 0 {
			t.Fatal("no LiveStats outputs emitted")
		}
		stats := allStats[0]
		if !detectedCIDRSet(stats)["10.5.5.0/24"] {
			t.Errorf("DetectedCIDRs = %+v, want 10.5.5.0/24 detected (detection is unfiltered)", stats.DetectedCIDRs)
		}
		if len(stats.ActiveBans) != 0 {
			t.Errorf("ActiveBans = %v, want empty (whitelisted)", stats.ActiveBans)
		}
		if bans := banCIDRs(t, cfg.GetBanFile()); len(bans) != 0 {
			t.Errorf("ban file CIDRs = %v, want none", bans)
		}
		if _, _, found := findPrisoner(t, cfg.GetJailFile(), "10.5.5.0/24"); found {
			t.Error("whitelisted 10.5.5.0/24 must not be jailed")
		}
		if countWarnings(outs, "whitelist_applied") == 0 {
			t.Error("missing whitelist_applied warning")
		}
	})

	t.Run("SubtractionSplit", func(t *testing.T) {
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
		outs := h.drainOutputs()

		allStats := liveStatsFrom(outs)
		if len(allStats) == 0 {
			t.Fatal("no LiveStats outputs emitted")
		}
		stats := allStats[0]
		if len(stats.ActiveBans) != 1 || stats.ActiveBans[0] != "10.5.5.128/25" {
			t.Errorf("ActiveBans = %v, want [10.5.5.128/25]", stats.ActiveBans)
		}
		bans := banCIDRs(t, cfg.GetBanFile())
		if len(bans) != 1 || bans[0] != "10.5.5.128/25" {
			t.Errorf("ban file CIDRs = %v, want [10.5.5.128/25]", bans)
		}
		if _, _, found := findPrisoner(t, cfg.GetJailFile(), "10.5.5.128/25"); !found {
			t.Error("10.5.5.128/25 not found in jail file")
		}
		if _, _, found := findPrisoner(t, cfg.GetJailFile(), "10.5.5.0/25"); found {
			t.Error("whitelisted half 10.5.5.0/25 must not be jailed")
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
	outs := h.drainOutputs()

	if got := len(liveStatsFrom(outs)); got != 2 {
		t.Fatalf("LiveStats outputs = %d, want 2 (two iterations)", got)
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

	if got := countWarnings(outs, "blacklist_applied"); got != 1 {
		t.Errorf("blacklist_applied warnings = %d, want exactly 1 across all outputs", got)
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
	outs := h.drainOutputs()

	if bans := banCIDRs(t, cfg.GetBanFile()); len(bans) != 0 {
		t.Errorf("ban file CIDRs = %v, want none (active ban is whitelisted)", bans)
	}
	if _, active, found := findPrisoner(t, cfg.GetJailFile(), "192.168.0.0/24"); !found || !active {
		t.Errorf("prisoner 192.168.0.0/24 found=%v active=%v, want it to stay in jail active", found, active)
	}
	for _, stats := range liveStatsFrom(outs) {
		for _, b := range stats.ActiveBans {
			if b == "192.168.0.0/24" {
				t.Errorf("ActiveBans = %v, must exclude whitelisted 192.168.0.0/24", stats.ActiveBans)
			}
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

			err := runLiveLoop(context.Background(), fake, cfg, func(*output.JSONOutput) {}, nil)
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("err = %v, want error mentioning %q", err, tc.wantSub)
			}
			if got := fake.acceptCallCount(); got != 0 {
				t.Errorf("Accept calls = %d, want 0 (must fail before accepting)", got)
			}
		})
	}
}
