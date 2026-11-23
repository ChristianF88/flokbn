package cli

import (
	"testing"
	"time"

	"github.com/ChristianF88/flokbn/config"
	"github.com/ChristianF88/flokbn/ingestor"
)

// timestampSkewWarnings returns the "outside the sliding window" warnings in
// a drained event slice.
func timestampSkewWarnings(events []logEvent) []logEvent {
	var warns []logEvent
	for _, ev := range events {
		if ev.rec.Message == liveTimestampSkewMsg {
			warns = append(warns, ev)
		}
	}
	return warns
}

// TestRunLiveLoop_WarnsWhenBatchIsStaleOnArrival: zone-less timestamps are
// read as UTC, so a log host west of UTC produces requests that are hours old
// on arrival and expire before clustering ever sees them. That used to be
// completely silent (window 0, nothing detected, no hint why). The warning is
// rate-limited: two such batches in a row produce one line.
func TestRunLiveLoop_WarnsWhenBatchIsStaleOnArrival(t *testing.T) {
	stale := time.Now().Add(-5 * time.Hour) // e.g. UTC-5 local time read as UTC
	fake := &fakeIngestor{
		batches: [][]ingestor.Request{
			hotBlock(10, 5, 5, stale, "/api/item"),
			hotBlock(10, 5, 6, stale, "/api/item"),
		},
		closeAfterDrain: true,
	}
	cfg := newLiveConfig(t, map[string]*config.SlidingTrieConfig{
		"w": newWindowConfigSized(t, "", true, time.Hour, 100000),
	})

	h := startLoop(t, fake, cfg)
	if err := h.wait(10 * time.Second); err != nil {
		t.Fatalf("runLiveLoop returned error: %v", err)
	}
	events := h.drainEvents()

	iters := iterationEvents(events)
	if len(iters) != 2 {
		t.Fatalf("iterations = %d, want 2", len(iters))
	}
	for i, ev := range iters {
		if it := parseIteration(t, ev.rec); it.Window != 0 || it.Detected != 0 {
			t.Errorf("iteration %d window/detected = %d/%d, want 0/0 (everything expired on arrival)", i+1, it.Window, it.Detected)
		}
	}

	warns := timestampSkewWarnings(events)
	if len(warns) != 1 {
		t.Fatalf("timestamp warnings = %d, want exactly 1 (rate-limited across the two batches)", len(warns))
	}
	attrs := recordAttrs(warns[0].rec)
	if got := attrs["window"].String(); got != "w" {
		t.Errorf("warning window = %q, want %q", got, "w")
	}
	if got := attrs["batch"].Int64(); got != 256 {
		t.Errorf("warning batch = %d, want 256", got)
	}
	if got := attrs["stale"].Int64(); got != 256 {
		t.Errorf("warning stale = %d, want 256", got)
	}
	if got := attrs["future"].Int64(); got != 0 {
		t.Errorf("warning future = %d, want 0", got)
	}
}

// TestRunLiveLoop_FutureTimestampsAreClampedAndWarned: a log host east of UTC
// with zone-less timestamps stamps requests hours ahead. They are clamped to
// the arrival time, so they still cluster (and will expire one window later
// instead of blocking the queue head), and the mismatch is reported.
func TestRunLiveLoop_FutureTimestampsAreClampedAndWarned(t *testing.T) {
	future := time.Now().Add(5 * time.Hour)
	fake := &fakeIngestor{
		batches:         [][]ingestor.Request{hotBlock(10, 5, 5, future, "/api/item")},
		closeAfterDrain: true,
	}
	cfg := newLiveConfig(t, map[string]*config.SlidingTrieConfig{
		"w": newWindowConfigSized(t, "", true, time.Hour, 100000),
	})

	h := startLoop(t, fake, cfg)
	if err := h.wait(10 * time.Second); err != nil {
		t.Fatalf("runLiveLoop returned error: %v", err)
	}
	events := h.drainEvents()

	iters := iterationEvents(events)
	if len(iters) != 1 {
		t.Fatalf("iterations = %d, want 1", len(iters))
	}
	assertSingleCIDRState(t, parseIteration(t, iters[0].rec), iters[0].snap, "10.5.5.0/24", 256)

	warns := timestampSkewWarnings(events)
	if len(warns) != 1 {
		t.Fatalf("timestamp warnings = %d, want 1", len(warns))
	}
	attrs := recordAttrs(warns[0].rec)
	if got := attrs["future"].Int64(); got != 256 {
		t.Errorf("warning future = %d, want 256", got)
	}
	if got := attrs["stale"].Int64(); got != 0 {
		t.Errorf("warning stale = %d, want 0", got)
	}
}

// TestRunLiveLoop_NoTimestampWarningForCurrentTraffic: a batch that is mostly
// inside the window stays quiet, even with a stale minority (a Filebeat
// catching up on a few old lines is normal).
func TestRunLiveLoop_NoTimestampWarningForCurrentTraffic(t *testing.T) {
	now := time.Now()
	batch := append(hotBlock(10, 5, 5, now, "/api/item"), noiseRequests(now.Add(-5*time.Hour), "/api/item")...)
	fake := &fakeIngestor{batches: [][]ingestor.Request{batch}, closeAfterDrain: true}
	cfg := newLiveConfig(t, map[string]*config.SlidingTrieConfig{
		"w": newWindowConfigSized(t, "", true, time.Hour, 100000),
	})

	h := startLoop(t, fake, cfg)
	if err := h.wait(10 * time.Second); err != nil {
		t.Fatalf("runLiveLoop returned error: %v", err)
	}
	events := h.drainEvents()

	if len(iterationEvents(events)) != 1 {
		t.Fatalf("iterations = %d, want 1", len(iterationEvents(events)))
	}
	if warns := timestampSkewWarnings(events); len(warns) != 0 {
		t.Errorf("timestamp warnings = %d, want 0 (20 stale of 276 is a minority)", len(warns))
	}
}
