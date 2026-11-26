package cli

import (
	"strings"
	"testing"
	"time"

	v2 "github.com/elastic/go-lumber/client/v2"

	"github.com/ChristianF88/flokbn/config"
)

// ============================================================================
// A3: ingest.connected / flokbn_ingest_connected follow real connections
// ============================================================================

// awaitHeartbeatWhere consumes heartbeats until one's snapshot satisfies cond.
func (h *loopHarness) awaitHeartbeatWhere(desc string, cond func(*statsSnapshot) bool) *statsSnapshot {
	h.t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		_, snap := h.nextHeartbeat()
		if cond(snap) {
			return snap
		}
	}
	h.t.Fatalf("no heartbeat snapshot with %s within 15s", desc)
	return nil
}

// TestLiveLoop_ConnectedFollowsRealConnections: Accept only starts the
// listener, so "connected" used to be reported the moment the loop started and
// stayed 1 for the life of the process. It must be false until a shipper
// actually connects and false again after it leaves.
func TestLiveLoop_ConnectedFollowsRealConnections(t *testing.T) {
	ing := newE2EIngestor(t)
	cfg := newLiveConfig(t, map[string]*config.SlidingTrieConfig{
		"w": newWindowConfig(t, "", true),
	})
	h := startLoop(t, ing, cfg)
	h.awaitMessage(liveAcceptingMsg)

	_, idle := h.nextHeartbeat()
	if idle.Ingest.Connected || idle.Ingest.OpenConnections != 0 {
		t.Fatalf("ingest = {connected:%v open_connections:%d} with no shipper connected, want {false 0}",
			idle.Ingest.Connected, idle.Ingest.OpenConnections)
	}
	if got := string(renderMetrics(idle)); !strings.Contains(got, "flokbn_ingest_connected 0\n") {
		t.Errorf("metrics report a connection with no shipper connected:\n%s", got)
	}

	client, err := v2.SyncDial(ing.Addr().String())
	if err != nil {
		t.Fatalf("SyncDial: %v", err)
	}
	defer client.Close()
	up := h.awaitHeartbeatWhere("connected=true", func(s *statsSnapshot) bool { return s.Ingest.Connected })
	if up.Ingest.OpenConnections != 1 {
		t.Errorf("open_connections = %d with one shipper connected, want 1", up.Ingest.OpenConnections)
	}
	metrics := string(renderMetrics(up))
	for _, want := range []string{"flokbn_ingest_connected 1\n", "flokbn_ingest_open_connections 1\n"} {
		if !strings.Contains(metrics, want) {
			t.Errorf("metrics lack %q:\n%s", want, metrics)
		}
	}

	client.Close()
	h.awaitHeartbeatWhere("connected=false after disconnect", func(s *statsSnapshot) bool {
		return !s.Ingest.Connected && s.Ingest.OpenConnections == 0
	})
}

// The loop itself must not claim a connection: "Filebeat connected" is logged
// by the ingestor when a client really connects, never by the loop on start.
func TestRunLiveLoop_DoesNotLogConnectedOnStart(t *testing.T) {
	fake := &fakeIngestor{}
	cfg := newLiveConfig(t, map[string]*config.SlidingTrieConfig{
		"w": newWindowConfig(t, "", true),
	})
	h := startLoop(t, fake, cfg)
	h.nextHeartbeat()
	h.cancel()
	if err := h.wait(5 * time.Second); err != nil {
		t.Fatalf("runLiveLoop returned error: %v", err)
	}
	if eventsHaveMessage(h.drainEvents(), "Filebeat connected") {
		t.Error(`loop logged "Filebeat connected" although no client connected`)
	}
}
