package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/ChristianF88/flokbn/config"
)

// metricsFor renders /metrics for a jail holding n active bans.
func metricsFor(t *testing.T, n int) string {
	t.Helper()
	cfg := newLiveConfig(t, map[string]*config.SlidingTrieConfig{})
	st := newLiveStatsState(cfg, nil, nil)
	j := jailWithActivePrisoners(n, time.Now())
	snap := buildSnapshot(st, &fakeIngestor{}, cfg, nil, nil, j, 5*time.Millisecond, 0, false)
	return string(renderMetrics(snap))
}

// TestRenderMetrics_BanActiveTruncatedGauge: flokbn_ban_active is one series
// per ban, capped at maxActiveBansInSnapshot. A scraper counting those series
// used to see exactly 500 with nothing telling it the list was cut off.
func TestRenderMetrics_BanActiveTruncatedGauge(t *testing.T) {
	over := maxActiveBansInSnapshot + 100
	cases := []struct {
		name          string
		bans          int
		wantSeries    int
		wantTruncated string
	}{
		{"below the cap", 3, 3, "flokbn_ban_active_truncated 0"},
		{"exactly at the cap", maxActiveBansInSnapshot, maxActiveBansInSnapshot, "flokbn_ban_active_truncated 0"},
		{"above the cap", over, maxActiveBansInSnapshot, "flokbn_ban_active_truncated 1"},
		{"no bans", 0, 0, "flokbn_ban_active_truncated 0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := metricsFor(t, tc.bans)

			if series := strings.Count(got, "\nflokbn_ban_active{"); series != tc.wantSeries {
				t.Errorf("flokbn_ban_active series = %d, want %d", series, tc.wantSeries)
			}
			if !strings.Contains(got, "\n"+tc.wantTruncated+"\n") {
				t.Errorf("metrics output missing line %q", tc.wantTruncated)
			}
			for _, header := range []string{
				"# HELP flokbn_ban_active_truncated ",
				"# TYPE flokbn_ban_active_truncated gauge\n",
			} {
				if !strings.Contains(got, header) {
					t.Errorf("metrics output missing %q", header)
				}
			}
		})
	}

	// The exact total stays available next to the capped series.
	if got := metricsFor(t, over); !strings.Contains(got, "\nflokbn_jail_active 600\n") {
		t.Errorf("flokbn_jail_active must report the full count (600) when the series are truncated")
	}
}
