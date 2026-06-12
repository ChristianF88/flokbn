package cli

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/ChristianF88/cidrx/config"
	"github.com/ChristianF88/cidrx/jail"
	"github.com/ChristianF88/cidrx/output"
	"github.com/ChristianF88/cidrx/sliding"
)

func cidrList(n int) []string {
	cidrs := make([]string, n)
	for i := range cidrs {
		cidrs[i] = fmt.Sprintf("10.%d.%d.0/24", i/256, i%256)
	}
	return cidrs
}

func jailWithActivePrisoners(n int, banStart time.Time) jail.Jail {
	j := jail.NewJail()
	for i := 0; i < n; i++ {
		j.Cells[0].Prisoners = append(j.Cells[0].Prisoners, jail.Prisoner{
			CIDR:      fmt.Sprintf("172.%d.%d.0/24", i/256, i%256),
			BanStart:  banStart,
			BanActive: true,
		})
	}
	return j
}

func TestBuildSnapshot_ActiveBansCappedAt500(t *testing.T) {
	cfg := newLiveConfig(t, map[string]*config.SlidingTrieConfig{})
	st := newLiveStatsState(cfg, nil, nil)
	j := jailWithActivePrisoners(600, time.Now())

	snap := buildSnapshot(st, &fakeIngestor{}, cfg, nil, nil, &j, 5*time.Millisecond, 0, false)

	if snap.Jail.TotalActive != 600 {
		t.Errorf("jail.total_active = %d, want 600 (always the full count)", snap.Jail.TotalActive)
	}
	if len(snap.Jail.ActiveBans) != 500 {
		t.Errorf("jail.active_bans len = %d, want 500", len(snap.Jail.ActiveBans))
	}
	if !snap.Jail.Truncated {
		t.Error("jail.active_bans_truncated = false, want true")
	}
	if len(snap.Jail.Stages) != 5 || snap.Jail.Stages[0].Active != 600 {
		t.Errorf("jail.stages = %+v, want 5 stages with stage 1 active = 600", snap.Jail.Stages)
	}
}

func TestBuildSnapshot_ListCIDRsCappedAt1000(t *testing.T) {
	cfg := newLiveConfig(t, map[string]*config.SlidingTrieConfig{})
	wl := cidrList(1500)
	bl := cidrList(3)
	st := newLiveStatsState(cfg, wl, bl)
	j := jail.NewJail()

	snap := buildSnapshot(st, &fakeIngestor{}, cfg, nil, nil, &j, time.Millisecond, 0, false)

	if snap.Lists.Whitelist.Entries != 1500 {
		t.Errorf("whitelist.entries = %d, want 1500 (exact count)", snap.Lists.Whitelist.Entries)
	}
	if len(snap.Lists.Whitelist.CIDRs) != 1000 {
		t.Errorf("whitelist.cidrs len = %d, want 1000 (capped)", len(snap.Lists.Whitelist.CIDRs))
	}
	if snap.Lists.Blacklist.Entries != 3 || len(snap.Lists.Blacklist.CIDRs) != 3 {
		t.Errorf("blacklist = %d entries / %d cidrs, want 3/3", snap.Lists.Blacklist.Entries, len(snap.Lists.Blacklist.CIDRs))
	}
}

func TestBuildSnapshot_IterationsAndTopTalkerCadence(t *testing.T) {
	cfg := newLiveConfig(t, map[string]*config.SlidingTrieConfig{})
	cfg.Live.TopTalkers = 1
	st := newLiveStatsState(cfg, nil, nil)
	j := jail.NewJail()

	w := sliding.NewSlidingWindowTrie(24*time.Hour, 1000)
	now := time.Now()
	w.InsertNew([]sliding.TimedIP{{IP: net.IPv4(10, 0, 0, 1), Time: now}})
	windows := []slidingWindowInstance{{name: "w", window: w, config: &config.SlidingTrieConfig{}}}

	// Iteration 1 computes top talkers.
	snap := buildSnapshot(st, &fakeIngestor{}, cfg, windows, nil, &j, time.Millisecond, 0, false)
	if snap.Loop.Iterations != 1 {
		t.Errorf("iterations = %d, want 1", snap.Loop.Iterations)
	}
	if len(snap.Windows) != 1 || len(snap.Windows[0].TopTalkers) != 1 || snap.Windows[0].TopTalkers[0].IP != "10.0.0.1" {
		t.Fatalf("iteration 1 top_talkers = %+v, want [{10.0.0.1 1}]", snap.Windows)
	}
	first := snap.Windows[0].TopTalkers

	// Iterations 2..5 serve the cached slice; iteration 6 recomputes.
	for i := 2; i <= 5; i++ {
		snap = buildSnapshot(st, &fakeIngestor{}, cfg, windows, nil, &j, time.Millisecond, 0, false)
		if got := snap.Windows[0].TopTalkers; len(got) != 1 || &got[0] != &first[0] {
			t.Errorf("iteration %d: top talkers recomputed, want cached slice reused", i)
		}
	}
	snap = buildSnapshot(st, &fakeIngestor{}, cfg, windows, nil, &j, time.Millisecond, 0, false)
	if got := snap.Windows[0].TopTalkers; len(got) != 1 || &got[0] == &first[0] {
		t.Error("iteration 6: top talkers not recomputed, want fresh slice")
	}
	if snap.Loop.Iterations != 6 {
		t.Errorf("iterations = %d, want 6", snap.Loop.Iterations)
	}
}

func BenchmarkBuildSnapshot(b *testing.B) {
	dir := b.TempDir()
	cfg := &config.Config{
		Global: &config.GlobalConfig{
			JailFile: dir + "/jail.json",
			BanFile:  dir + "/ban.txt",
		},
		Live: &config.LiveConfig{Port: "0"},
	}

	// Window pre-filled with 10k entries.
	w := sliding.NewSlidingWindowTrie(24*time.Hour, 1<<20)
	now := time.Now()
	timed := make([]sliding.TimedIP, 0, 10000)
	for i := 0; i < 10000; i++ {
		timed = append(timed, sliding.TimedIP{
			IP:   net.IPv4(10, byte(i>>16), byte(i>>8), byte(i)),
			Time: now,
		})
	}
	w.Update(timed)
	stc := &config.SlidingTrieConfig{
		ClusterArgSets: []config.ClusterArgSet{
			{MinClusterSize: 100, MinDepth: 24, MaxDepth: 32, MeanSubnetDifference: 0.5},
			{MinClusterSize: 1000, MinDepth: 16, MaxDepth: 24, MeanSubnetDifference: 0.2},
		},
	}
	windows := []slidingWindowInstance{{name: "w", window: w, config: stc}}

	winClusterStats := [][]clusterSetStats{{
		newClusterSetStats(stc.ClusterArgSets[0], true, 95*time.Microsecond, []output.LiveCIDR{
			{CIDR: "10.0.0.0/24", Count: 256},
			{CIDR: "10.0.1.0/24", Count: 256},
		}),
		newClusterSetStats(stc.ClusterArgSets[1], false, 4*time.Microsecond, []output.LiveCIDR{
			{CIDR: "10.0.0.0/16", Count: 10000},
		}),
	}}

	j := jailWithActivePrisoners(100, now)
	st := newLiveStatsState(cfg, cidrList(10), cidrList(5))
	st.recordBanFileWrite("# header\n10.0.0.0/24\n", 1)
	ing := &fakeIngestor{}
	srv := &statsServer{} // publish only touches the atomic pointer

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		srv.publish(buildSnapshot(st, ing, cfg, windows, winClusterStats, &j, time.Millisecond, 1, false))
	}
}
