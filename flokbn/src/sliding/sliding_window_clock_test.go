package sliding

import (
	"testing"
	"time"
)

// TestSlidingWindow_FutureTimestampDoesNotBlockExpiry is the regression test
// for head-of-line blocking: DropOld pops from the queue head while the head
// is older than the cutoff, so a single future-stamped entry at the head used
// to keep every entry behind it in the window until the future stamp itself
// aged out (never, for a badly wrong clock or timezone).
func TestSlidingWindow_FutureTimestampDoesNotBlockExpiry(t *testing.T) {
	const window = 50 * time.Millisecond
	s := NewSlidingWindowTrie(window, 100)
	now := time.Now()

	// InsertNew, not Update: no eviction pass runs before the sleep, so a
	// slow machine cannot expire the fresh entries early.
	s.InsertNew([]TimedIP{
		{IP: ipU32(10, 0, 0, 1), Time: now.Add(24 * time.Hour)}, // future-stamped head
		{IP: ipU32(10, 0, 0, 2), Time: now},
		{IP: ipU32(10, 0, 0, 3), Time: now},
	})
	if len(s.IPQueue) != 3 {
		t.Fatalf("queue length after insert = %d, want 3", len(s.IPQueue))
	}

	// Sleeping longer only makes the expectation more certain.
	time.Sleep(2 * window)
	s.DropOld()

	if len(s.IPQueue) != 0 {
		t.Errorf("queue length after the window elapsed = %d, want 0 (future-stamped head must not block expiry)", len(s.IPQueue))
	}
	if got := s.Trie.CountAll(); got != 0 {
		t.Errorf("trie count after the window elapsed = %d, want 0", got)
	}
	if got := s.IPStats.Len(); got != 0 {
		t.Errorf("IPStats entries after the window elapsed = %d, want 0", got)
	}
}

// TestSlidingWindow_InsertClampsFutureTimestamps pins the clock: every stamp
// ahead of now lands in the queue as exactly now, past stamps are untouched,
// and the caller's slice is never modified.
func TestSlidingWindow_InsertClampsFutureTimestamps(t *testing.T) {
	s := NewSlidingWindowTrie(time.Hour, 100)
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	past := now.Add(-10 * time.Minute)

	in := []TimedIP{
		{IP: ipU32(10, 0, 0, 1), Time: now.Add(5 * time.Hour)},   // wrong zone
		{IP: ipU32(10, 0, 0, 2), Time: now.Add(2 * time.Second)}, // ordinary skew
		{IP: ipU32(10, 0, 0, 3), Time: past},
		{IP: ipU32(10, 0, 0, 4), Time: now},
	}
	orig := append([]TimedIP(nil), in...)
	s.insertAt(in, now)

	want := []time.Time{now, now, past, now}
	if len(s.IPQueue) != len(want) {
		t.Fatalf("queue length = %d, want %d", len(s.IPQueue), len(want))
	}
	for i, w := range want {
		if !s.IPQueue[i].Time.Equal(w) {
			t.Errorf("queue[%d].Time = %v, want %v", i, s.IPQueue[i].Time, w)
		}
	}
	for i := range in {
		if in[i] != orig[i] {
			t.Errorf("caller slice entry %d was modified: %+v, want %+v", i, in[i], orig[i])
		}
	}
	// IPStats.Last follows the clamped time, so it never points at the future.
	if stat, ok := s.IPStats.Get(ipU32(10, 0, 0, 1)); !ok || !stat.Last.Equal(now) {
		t.Errorf("IPStats.Last for the future-stamped IP = %v (present %v), want %v", stat.Last, ok, now)
	}
}

// TestSlidingWindow_ClampBoundsRetentionToWindow: with a pinned clock, a
// queue headed by a far-future stamp is fully expired one window after
// arrival. Just before that point nothing is evicted.
func TestSlidingWindow_ClampBoundsRetentionToWindow(t *testing.T) {
	const window = time.Hour
	s := NewSlidingWindowTrie(window, 100)
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

	s.insertAt([]TimedIP{
		{IP: ipU32(10, 0, 0, 1), Time: now.Add(365 * 24 * time.Hour)},
		{IP: ipU32(10, 0, 0, 2), Time: now},
		{IP: ipU32(10, 0, 0, 3), Time: now},
	}, now)

	s.dropOldAt(now.Add(window))
	if len(s.IPQueue) != 3 {
		t.Fatalf("queue length exactly one window after arrival = %d, want 3 (cutoff is exclusive)", len(s.IPQueue))
	}
	s.dropOldAt(now.Add(window + time.Nanosecond))
	if len(s.IPQueue) != 0 {
		t.Errorf("queue length past one window after arrival = %d, want 0", len(s.IPQueue))
	}
	if got := s.Trie.CountAll(); got != 0 {
		t.Errorf("trie count = %d, want 0", got)
	}
}

// TestSlidingWindow_LastArrival checks the per-batch timestamp accounting the
// live loop uses to warn about log time and wall clock disagreeing.
func TestSlidingWindow_LastArrival(t *testing.T) {
	s := NewSlidingWindowTrie(time.Hour, 100)
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

	s.insertAt([]TimedIP{
		{IP: ipU32(10, 0, 0, 1), Time: now.Add(-5 * time.Hour)},                  // stale: wrong zone, west of UTC
		{IP: ipU32(10, 0, 0, 2), Time: now.Add(-time.Hour - time.Nanosecond)},    // stale: just outside
		{IP: ipU32(10, 0, 0, 3), Time: now.Add(-time.Hour)},                      // on the cutoff: in window
		{IP: ipU32(10, 0, 0, 4), Time: now},                                      // in window
		{IP: ipU32(10, 0, 0, 5), Time: now.Add(futureSkewTolerance)},             // skew within tolerance
		{IP: ipU32(10, 0, 0, 6), Time: now.Add(futureSkewTolerance + time.Hour)}, // future: wrong zone, east of UTC
	}, now)

	want := ArrivalStats{Inserted: 6, Future: 1, Stale: 2}
	if got := s.LastArrival(); got != want {
		t.Errorf("LastArrival() = %+v, want %+v", got, want)
	}

	// Stats describe the latest batch only, including an empty one.
	s.insertAt(nil, now)
	if got := s.LastArrival(); got != (ArrivalStats{}) {
		t.Errorf("LastArrival() after an empty batch = %+v, want zero", got)
	}
}
