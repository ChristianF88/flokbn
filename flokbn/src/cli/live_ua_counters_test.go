package cli

import (
	"testing"
	"time"

	"github.com/ChristianF88/flokbn/accesslog"
	"github.com/ChristianF88/flokbn/config"
)

// TestRunLiveLoop_HeartbeatRefreshesUserAgentIPCounters: the IPs seen with a
// listed User-Agent are forgotten once they have not been seen for the largest
// window duration, and the idle path does that too. The two /stats counters
// active_whitelist_ips and active_blacklist_ips were only refreshed by an
// iteration though, so heartbeat snapshots kept reporting the IPs of the last
// busy moment for as long as the loop stayed idle.
//
// The window is 2s long: the iteration still tracks both IPs, a heartbeat a
// few seconds later must report none.
func TestRunLiveLoop_HeartbeatRefreshesUserAgentIPCounters(t *testing.T) {
	now := time.Now()
	good := mkRequest(203, 0, 113, 9, now, "/health")
	good.UserAgent = "GoodBot/1.0"
	evil := mkRequest(198, 51, 100, 7, now, "/login")
	evil.UserAgent = "EvilBot/1.0"
	fake := &fakeIngestor{ // stays open: the loop goes idle after one batch
		batches: [][]accesslog.Request{{good, evil}},
	}
	cfg := newLiveConfigWithUALists(t, map[string]*config.SlidingTrieConfig{
		"w": newWindowConfigSized(t, "", true, 2*time.Second, 100000),
	}, nil, nil, []string{"GoodBot/1.0"}, []string{"EvilBot/1.0"})

	h := startLoop(t, fake, cfg)

	_, snap := h.nextIteration()
	ua := snap.Lists.UserAgentLists
	if ua.ActiveWhitelistIPs != 1 || ua.ActiveBlacklistIPs != 1 {
		t.Fatalf("iteration ua stats = %+v, want 1 active whitelist IP and 1 active blacklist IP", ua)
	}

	// Heartbeats fire about once per second; both IPs are forgotten ~2s in.
	// The bound is a failure limit, not a synchronization sleep.
	var idle *statsSnapshot
	for i := 0; i < 10; i++ {
		_, idle = h.nextHeartbeat()
		ua = idle.Lists.UserAgentLists
		if ua.ActiveWhitelistIPs == 0 && ua.ActiveBlacklistIPs == 0 {
			break
		}
	}
	if ua.ActiveWhitelistIPs != 0 || ua.ActiveBlacklistIPs != 0 {
		t.Errorf("idle ua stats = %+v, want 0 active IPs on both lists (forgotten after the window duration)", ua)
	}
	// The lifetime hit counters are not affected by the expiry.
	if ua.WhitelistHitsTotal != 1 || ua.BlacklistHitsTotal != 1 {
		t.Errorf("idle ua hit totals = %d/%d, want 1/1", ua.WhitelistHitsTotal, ua.BlacklistHitsTotal)
	}
	if idle.Loop.Iterations != 1 {
		t.Errorf("Loop.Iterations = %d, want 1: the counters must drop without another iteration", idle.Loop.Iterations)
	}
}
