package cli

import (
	"fmt"
	"testing"
	"time"

	v2 "github.com/elastic/go-lumber/client/v2"

	"github.com/ChristianF88/cidrx/config"
	"github.com/ChristianF88/cidrx/ingestor"
)

// apacheLogLine builds a combined-log-format line the TCP ingestor parses.
func apacheLogLine(ip string, ts time.Time, uri string) string {
	return fmt.Sprintf(`%s - - [%s] "GET %s HTTP/1.1" 200 123 "-" "TestUA"`,
		ip, ts.Format("02/Jan/2006:15:04:05 -0700"), uri)
}

func lumberLogEvent(ip string, ts time.Time, uri string) interface{} {
	return map[string]interface{}{"message": apacheLogLine(ip, ts, uri)}
}

// hotLogEvents returns lumberjack events for IPs 10.5.5.lo .. 10.5.5.hi-1.
func hotLogEvents(ts time.Time, lo, hi int) []interface{} {
	events := make([]interface{}, 0, hi-lo)
	for i := lo; i < hi; i++ {
		events = append(events, lumberLogEvent(fmt.Sprintf("10.5.5.%d", i), ts, "/api/item"))
	}
	return events
}

// noiseLogEvents returns 20 singleton-IP lumberjack events across distinct /8s.
func noiseLogEvents(ts time.Time) []interface{} {
	events := make([]interface{}, 0, 20)
	for i := 0; i < 20; i++ {
		events = append(events, lumberLogEvent(
			fmt.Sprintf("%d.%d.%d.%d", 20+i, i+1, i+2, i+3), ts, "/api/item"))
	}
	return events
}

// newE2EIngestor binds a real TCP ingestor to an ephemeral localhost port.
// The read timeout is generous on purpose: it is a dead-connection guard,
// never a synchronization mechanism, and a short value could drop the test
// client between dial and send on a loaded machine.
func newE2EIngestor(t *testing.T) *ingestor.TCPIngestor {
	t.Helper()
	ing, err := ingestor.NewTCPIngestor("127.0.0.1:0", 5*time.Second)
	if err != nil {
		t.Fatalf("NewTCPIngestor: %v", err)
	}
	t.Cleanup(func() { ing.Close() })
	return ing
}

func TestLiveLoop_EndToEnd_LumberjackToBanFile(t *testing.T) {
	ing := newE2EIngestor(t)
	addr := ing.Addr().String()
	cfg := newLiveConfig(t, map[string]*config.SlidingTrieConfig{
		"w": newWindowConfig(t, "", true),
	})

	h := startLoop(t, ing, cfg)
	// Deterministic readiness: the loop emits this right after Accept.
	h.awaitMessage("Filebeat connected")

	now := time.Now()
	events := append(hotLogEvents(now, 0, 256), noiseLogEvents(now)...)

	client, err := v2.SyncDial(addr)
	if err != nil {
		t.Fatalf("SyncDial: %v", err)
	}
	defer client.Close()

	seq, err := client.Send(events)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if seq != 276 {
		t.Fatalf("Send seq = %d, want 276", seq)
	}

	stats := h.nextStats()
	if stats.ProcessedBatch != 276 {
		t.Errorf("ProcessedBatch = %d, want 276", stats.ProcessedBatch)
	}
	if stats.WindowSize != 276 {
		t.Errorf("WindowSize = %d, want 276", stats.WindowSize)
	}
	assertSingleCIDRStats(t, stats, "10.5.5.0/24", 256)

	// Files are written before the stats emission, so they are final here.
	bans := banCIDRs(t, cfg.GetBanFile())
	if len(bans) != 1 || bans[0] != "10.5.5.0/24" {
		t.Errorf("ban file CIDRs = %v, want [10.5.5.0/24]", bans)
	}
	cellID, active, found := findPrisoner(t, cfg.GetJailFile(), "10.5.5.0/24")
	if !found {
		t.Fatal("10.5.5.0/24 not found in jail file")
	}
	if cellID != 1 || !active {
		t.Errorf("prisoner cell ID = %d active = %v, want cell 1 active", cellID, active)
	}

	client.Close()
	h.cancel()
	if err := h.wait(5 * time.Second); err != nil {
		t.Fatalf("runLiveLoop returned error: %v", err)
	}
}

func TestLiveLoop_EndToEnd_TwoBatchesAccumulate(t *testing.T) {
	ing := newE2EIngestor(t)
	addr := ing.Addr().String()
	cfg := newLiveConfig(t, map[string]*config.SlidingTrieConfig{
		"w": newWindowConfig(t, "", true),
	})

	h := startLoop(t, ing, cfg)
	h.awaitMessage("Filebeat connected")

	client, err := v2.SyncDial(addr)
	if err != nil {
		t.Fatalf("SyncDial: %v", err)
	}
	defer client.Close()

	now := time.Now()

	// Batch 1: 99 hot IPs — below MinClusterSize 100, so nothing detected.
	if _, err := client.Send(hotLogEvents(now, 0, 99)); err != nil {
		t.Fatalf("first Send: %v", err)
	}
	stats1 := h.nextStats()
	if stats1.ProcessedBatch != 99 {
		t.Errorf("iter1 ProcessedBatch = %d, want 99", stats1.ProcessedBatch)
	}
	if stats1.WindowSize != 99 {
		t.Errorf("iter1 WindowSize = %d, want 99", stats1.WindowSize)
	}
	if len(stats1.DetectedCIDRs) != 0 {
		t.Errorf("iter1 DetectedCIDRs = %+v, want empty (below min cluster size)", stats1.DetectedCIDRs)
	}
	if len(stats1.ActiveBans) != 0 {
		t.Errorf("iter1 ActiveBans = %v, want empty", stats1.ActiveBans)
	}

	// Waiting for stats1 above guarantees batch 1 was consumed, so this
	// second send lands in its own loop iteration.
	batch2 := append(hotLogEvents(now, 99, 256), noiseLogEvents(now)...)
	if _, err := client.Send(batch2); err != nil {
		t.Fatalf("second Send: %v", err)
	}
	stats2 := h.nextStats()
	if stats2.ProcessedBatch != 177 {
		t.Errorf("iter2 ProcessedBatch = %d, want 177", stats2.ProcessedBatch)
	}
	if stats2.WindowSize != 276 {
		t.Errorf("iter2 WindowSize = %d, want 276", stats2.WindowSize)
	}
	assertSingleCIDRStats(t, stats2, "10.5.5.0/24", 256)

	bans := banCIDRs(t, cfg.GetBanFile())
	if len(bans) != 1 || bans[0] != "10.5.5.0/24" {
		t.Errorf("ban file CIDRs = %v, want [10.5.5.0/24]", bans)
	}

	client.Close()
	h.cancel()
	if err := h.wait(5 * time.Second); err != nil {
		t.Fatalf("runLiveLoop returned error: %v", err)
	}
}
