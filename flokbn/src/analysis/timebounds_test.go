package analysis

import (
	"testing"
	"time"

	"github.com/ChristianF88/flokbn/config"
)

// TestTimeBounds_WallClockVsInstant is the URGENT-09 bound-comparison repro.
// Because the static parser now RETAINS a log line's timezone offset, a
// zone-less bound (parsed as UTC) must compare wall-clock-to-wall-clock so a
// bound "06:00" matches a log line whose LOCAL clock reads 06:00 regardless of
// the log's offset. A bound that carries an EXPLICIT offset compares as a true
// instant instead.
func TestTimeBounds_WallClockVsInstant(t *testing.T) {
	// A log line whose wall-clock is 2025-07-06 06:00:00 in +0100.
	plusOne := time.FixedZone("+0100", 3600)
	logTS := time.Date(2025, 7, 6, 6, 0, 0, 0, plusOne)

	// Same wall-clock but in -0700: a different absolute instant.
	minusSeven := time.FixedZone("-0700", -7*3600)
	logTSMinus7 := time.Date(2025, 7, 6, 6, 0, 0, 0, minusSeven)

	t.Run("zone-less start bound matches by wall-clock", func(t *testing.T) {
		// Bound start = 06:00 UTC (zone-less). Wall-clock of logTS is also 06:00,
		// so it must NOT be excluded — even though as a true instant logTS (05:00
		// UTC) is before 06:00 UTC.
		start := time.Date(2025, 7, 6, 6, 0, 0, 0, time.UTC)
		tc := &config.TrieConfig{StartTime: &start, StartTimeHasOffset: false}
		tb := makeTimeBounds(tc)
		if tb.excluded(logTS) {
			t.Errorf("+0100 06:00 line excluded by zone-less start 06:00 — wall-clock match expected")
		}
		if tb.excluded(logTSMinus7) {
			t.Errorf("-0700 06:00 line excluded by zone-less start 06:00 — wall-clock match expected")
		}
		// A 05:00 wall-clock line is before the bound and must be excluded.
		before := time.Date(2025, 7, 6, 5, 0, 0, 0, plusOne)
		if !tb.excluded(before) {
			t.Errorf("05:00 wall-clock line not excluded by zone-less start 06:00")
		}
	})

	t.Run("zone-less end bound matches by wall-clock", func(t *testing.T) {
		end := time.Date(2025, 7, 6, 6, 0, 0, 0, time.UTC)
		tc := &config.TrieConfig{EndTime: &end, EndTimeHasOffset: false}
		tb := makeTimeBounds(tc)
		if tb.excluded(logTS) {
			t.Errorf("+0100 06:00 line excluded by zone-less end 06:00 — should be within (== boundary)")
		}
		after := time.Date(2025, 7, 6, 7, 0, 0, 0, plusOne)
		if !tb.excluded(after) {
			t.Errorf("07:00 wall-clock line not excluded by zone-less end 06:00")
		}
	})

	t.Run("explicit-offset start bound compares as true instant", func(t *testing.T) {
		// Bound start = 06:00 +0100 == 05:00 UTC, explicit offset → instant.
		start := time.Date(2025, 7, 6, 6, 0, 0, 0, plusOne)
		tc := &config.TrieConfig{StartTime: &start, StartTimeHasOffset: true}
		tb := makeTimeBounds(tc)
		// logTS is exactly 06:00 +0100 (== the bound instant) → not excluded.
		if tb.excluded(logTS) {
			t.Errorf("06:00 +0100 line excluded by explicit-offset start 06:00 +0100")
		}
		// The -0700 06:00 line is 13:00 UTC, which is AFTER 05:00 UTC → not excluded.
		if tb.excluded(logTSMinus7) {
			t.Errorf("-0700 06:00 line (13:00 UTC) wrongly excluded by start 05:00 UTC")
		}
		// A line at 05:00 +0100 (04:00 UTC) is a true instant before the bound.
		earlier := time.Date(2025, 7, 6, 5, 0, 0, 0, plusOne)
		if !tb.excluded(earlier) {
			t.Errorf("04:00 UTC line not excluded by explicit-offset start 05:00 UTC")
		}
	})

	t.Run("explicit-offset end bound compares as true instant", func(t *testing.T) {
		// Bound end = 06:00 +0100 == 05:00 UTC, explicit → instant.
		end := time.Date(2025, 7, 6, 6, 0, 0, 0, plusOne)
		tc := &config.TrieConfig{EndTime: &end, EndTimeHasOffset: true}
		tb := makeTimeBounds(tc)
		// logTSMinus7 = 13:00 UTC, after 05:00 UTC → excluded.
		if !tb.excluded(logTSMinus7) {
			t.Errorf("-0700 06:00 line (13:00 UTC) not excluded by explicit-offset end 05:00 UTC")
		}
		if tb.excluded(logTS) {
			t.Errorf("06:00 +0100 line (== bound instant) wrongly excluded by end bound")
		}
	})

	t.Run("no bounds set never excludes", func(t *testing.T) {
		tb := makeTimeBounds(&config.TrieConfig{})
		if tb.excluded(logTS) || tb.excluded(logTSMinus7) {
			t.Errorf("unset bounds excluded a request")
		}
	})
}

// TestWallClockKey_Ordering checks the zone-agnostic key preserves ordering of
// successive wall-clock fields across each boundary.
func TestWallClockKey_Ordering(t *testing.T) {
	base := time.Date(2025, 7, 6, 6, 0, 0, 0, time.UTC)
	steps := []time.Duration{time.Second, time.Minute, time.Hour, 24 * time.Hour, 31 * 24 * time.Hour, 366 * 24 * time.Hour}
	prev := wallClockKey(base)
	cur := base
	for _, step := range steps {
		cur = cur.Add(step)
		k := wallClockKey(cur)
		if k <= prev {
			t.Errorf("wallClockKey not monotonic at %v: %d <= %d", cur, k, prev)
		}
		prev = k
	}
}
