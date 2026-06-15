package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/ChristianF88/flokbn/config"
	"github.com/ChristianF88/flokbn/output"
)

// TestBuildSummaryTextStatsOwnLines guards against horizontal clipping of the
// three global parse stats in the (narrow) Summary panel: each of "Parse Rate",
// "Amount of IPs Read", and "Parsing Time" must live on its own line so none
// can be cut off when the TextView is narrower than the combined width.
func TestBuildSummaryTextStatsOwnLines(t *testing.T) {
	jo := output.NewJSONOutput("static", time.Time{})
	jo.General.Parsing.RatePerSecond = 1373322
	jo.General.TotalRequests = 500000
	jo.General.Parsing.DurationMS = 762
	jo.Tries = []output.TrieResult{{Name: "cli_trie"}}

	a := &App{cfg: &config.Config{}, multiTrieResult: jo, currentTrie: 0}

	out := a.buildSummaryText()

	// All three labels (and their formatted values) must be present.
	for _, want := range []string{
		"Parse Rate:",
		"1,373,322 req/sec",
		"Amount of IPs Read:",
		"500,000",
		"Parsing Time:",
		"762ms",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("buildSummaryText() missing %q\nfull output:\n%s", want, out)
		}
	}

	// Each stat must appear on its OWN line, so none can be horizontally
	// clipped. Locate each label's line and ensure no two labels share a line.
	lines := strings.Split(out, "\n")
	labels := []string{"Parse Rate:", "Amount of IPs Read:", "Parsing Time:"}
	lineOf := make(map[string]int)
	for _, label := range labels {
		found := -1
		for i, line := range lines {
			if strings.Contains(line, label) {
				if found != -1 {
					t.Fatalf("label %q appears on multiple lines (%d and %d)", label, found, i)
				}
				found = i
			}
		}
		if found == -1 {
			t.Fatalf("label %q not found on any line", label)
		}
		lineOf[label] = found
	}

	// The three labels must be on three distinct lines.
	seen := map[int]string{}
	for label, idx := range lineOf {
		if other, dup := seen[idx]; dup {
			t.Fatalf("labels %q and %q share line %d (output not split one-per-line)", label, other, idx)
		}
		seen[idx] = label
	}
}
