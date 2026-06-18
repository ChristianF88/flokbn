package logparser

import (
	"testing"
	"time"
)

// TestStaticTimestampParity_OffsetAndOffsetless is the static half of the
// AUDIT-07 live<->static timestamp parity contract. parseTimestamp (static) and
// ingestor.parseEvent (live) live in different packages and are both unexported,
// so neither test package can call both production functions in one body.
// Instead, each side is independently pinned to the SAME documented oracle for
// IDENTICAL bracket-interior content:
//
//   - offset-less "06/Jul/2025:19:57:26" (20 bytes) -> time.Date(...,time.UTC)
//   - offset-bearing "06/Jul/2025:06:00:00 -0700"   -> 06:00 wall-clock, -0700
//
// The live half (ingestor.TestParseEvent_AcceptsOffsetlessTimestampAsUTC and
// TestParseEvent_RetainsTimezoneOffset) asserts the live ingestor produces the
// same instants and zone offsets. Pinning both implementations to one oracle is
// what guarantees parity: if either side drifts, its package test fails.
//
// parseTimestamp takes the bracket *interior* via [start,end); live parseEvent
// slices the identical interior as msg[start+1:end], so both see the same bytes.
func TestStaticTimestampParity_OffsetAndOffsetless(t *testing.T) {
	cases := []struct {
		name      string
		field     string // bracket interior, exactly what both paths receive
		want      time.Time
		offsetSec int
	}{
		{
			name:      "offset-less -> UTC (matches live fallback)",
			field:     "06/Jul/2025:19:57:26",
			want:      time.Date(2025, time.July, 6, 19, 57, 26, 0, time.UTC),
			offsetSec: 0,
		},
		{
			name:      "offset-bearing -> retains -0700 (matches live)",
			field:     "06/Jul/2025:06:00:00 -0700",
			want:      time.Date(2025, time.July, 6, 6, 0, 0, 0, time.FixedZone("", -7*3600)),
			offsetSec: -7 * 3600,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseTimestamp([]byte(tc.field), 0, len(tc.field))
			if !got.Equal(tc.want) {
				t.Errorf("static parseTimestamp(%q) instant = %v, want %v", tc.field, got.UTC(), tc.want.UTC())
			}
			if _, off := got.Zone(); off != tc.offsetSec {
				t.Errorf("static parseTimestamp(%q) zone offset = %ds, want %ds", tc.field, off, tc.offsetSec)
			}
			// Wall-clock digits must be preserved on both sides.
			if got.Hour() != tc.want.Hour() || got.Minute() != tc.want.Minute() || got.Second() != tc.want.Second() {
				t.Errorf("static parseTimestamp(%q) wall-clock = %02d:%02d:%02d, want %02d:%02d:%02d",
					tc.field, got.Hour(), got.Minute(), got.Second(),
					tc.want.Hour(), tc.want.Minute(), tc.want.Second())
			}
		})
	}
}
