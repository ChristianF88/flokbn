package cli

import (
	"testing"
	"time"

	"github.com/ChristianF88/flokbn/accesslog"
	"github.com/ChristianF88/flokbn/config"
)

// TestRunLiveLoop_HeartbeatExpiresWindowsWhenIdle: windows used to be expired
// only inside Update, which runs only when a batch arrives. After an attack
// stopped and traffic went quiet, /stats and /metrics kept reporting the
// attack-time window size, unique IPs, detections and top talkers forever.
// The idle heartbeat must expire the windows and refresh what it publishes.
//
// The hot block is stamped so that it leaves the 1h window about 3s after the
// test starts: iteration 1 still sees it, a later heartbeat must not.
func TestRunLiveLoop_HeartbeatExpiresWindowsWhenIdle(t *testing.T) {
	const window = time.Hour
	ts := time.Now().Add(-window + 3*time.Second)
	fake := &fakeIngestor{ // stays open: the loop goes idle after one batch
		batches: [][]accesslog.Request{hotBlock(10, 5, 5, ts, "/api/item")},
	}
	cfg := newLiveConfig(t, map[string]*config.SlidingTrieConfig{
		"w": newWindowConfigSized(t, "", true, window, 100000),
	})
	cfg.Live.TopTalkers = 3

	h := startLoop(t, fake, cfg)

	it, snap := h.nextIteration()
	assertSingleCIDRState(t, it, snap, "10.5.5.0/24", 256)
	if w := snap.Windows[0]; w.Requests != 256 || w.SizeIPs != 256 || len(w.TopTalkers) != 3 {
		t.Fatalf("iteration window requests/unique/top_talkers = %d/%d/%d, want 256/256/3",
			w.Requests, w.SizeIPs, len(w.TopTalkers))
	}

	// Heartbeats fire about once per second; the entries expire ~3s in. The
	// bound is a failure limit, not a synchronization sleep.
	var idle *statsSnapshot
	for i := 0; i < 10; i++ {
		_, hb := h.nextHeartbeat()
		idle = hb
		if hb.Windows[0].Requests == 0 {
			break
		}
	}
	w := idle.Windows[0]
	if w.Requests != 0 || w.SizeIPs != 0 {
		t.Errorf("idle window requests/unique = %d/%d, want 0/0 (expired by the heartbeat)", w.Requests, w.SizeIPs)
	}
	if detected := detectedNow(idle); len(detected) != 0 {
		t.Errorf("idle detected_now = %+v, want empty (window is empty)", detected)
	}
	if len(w.TopTalkers) != 0 {
		t.Errorf("idle top_talkers = %+v, want empty (window is empty)", w.TopTalkers)
	}
	if len(w.ClusterSets) != 1 {
		t.Errorf("idle cluster_sets = %d, want 1 (the arg set stays listed)", len(w.ClusterSets))
	}
	// Refreshing the published view must not touch the jail: the 10 minute
	// ban from iteration 1 is still running.
	if idle.Jail.TotalActive != 1 {
		t.Errorf("jail.total_active = %d, want 1 (window expiry must not lift or add bans)", idle.Jail.TotalActive)
	}
	if idle.Loop.Iterations != 1 {
		t.Errorf("loop.iterations = %d, want 1 (heartbeats are not iterations)", idle.Loop.Iterations)
	}
	// Published snapshots are immutable: the refresh must not have rewritten
	// the iteration's snapshot in place.
	if w := snap.Windows[0]; len(w.ClusterSets) != 1 || len(w.ClusterSets[0].DetectedNow) != 1 || len(w.TopTalkers) != 3 {
		t.Errorf("iteration snapshot was mutated by the heartbeat: cluster_sets %+v, top_talkers %+v", w.ClusterSets, w.TopTalkers)
	}
}
