package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/ChristianF88/flokbn/config"
	"github.com/ChristianF88/flokbn/output"
)

// heatmapText reads the visualization view's raw text on the UI goroutine.
func (a *App) heatmapText() string {
	var text string
	a.app.QueueUpdate(func() {
		if a.visualizationView != nil {
			text = a.visualizationView.view.GetText(false)
		}
	})
	return text
}

// showsHeatmap reports whether a visualization text is a drawn heatmap (it has
// the grid's top axis) rather than the loading placeholder or nothing.
func showsHeatmap(text string) bool {
	return strings.Contains(text, "256 A") && !strings.Contains(text, "Loading traffic data")
}

// TestVisualizationOpenedBeforeRequestDataFillsIn is the regression test for
// the stuck visualization: the results are shown before the parsed requests
// are handed over, and pressing 'v' in between left the visualization without
// a heatmap - blank, or on "Loading traffic data" after a cluster-set change -
// until the next trie switch, because nothing re-rendered it once the data was
// there (and the placeholder text had been cached as the set's rendering).
func TestVisualizationOpenedBeforeRequestDataFillsIn(t *testing.T) {
	multi := output.NewJSONOutput("static", time.Now())
	multi.Tries = []output.TrieResult{
		{Name: "trie-a", Data: []output.ClusterResult{
			*newClusterSet("10.0.0.0/8"),
			*newClusterSet("192.168.0.0/16"),
		}},
		{Name: "trie-b", Data: []output.ClusterResult{*newClusterSet("192.168.0.0/16")}},
	}

	a := NewAppFromConfig(&config.Config{Static: &config.StaticConfig{}}, "")
	stop := startSimApp(t, a)
	defer stop()

	a.SetAnalysisResults(multi)

	// 'v' right after the results appeared, then a look at the other cluster
	// set and back - all before the requests arrive.
	a.app.QueueUpdateDraw(func() {
		a.showVisualization()
		a.visualizationView.NextClusterSet()
		a.visualizationView.PrevClusterSet()
	})
	if text := a.heatmapText(); showsHeatmap(text) {
		t.Fatalf("heatmap drawn before any request data was handed over:\n%s", firstLines(text, 8))
	}

	a.SetRequestData(raceTestRequests())

	// The heatmap has to appear on its own: no trie switch, no key press.
	waitFor(t, func() bool { return showsHeatmap(a.heatmapText()) }, 3*time.Second)

	// The other cluster set must not be stuck on a cached placeholder either.
	a.app.QueueUpdateDraw(func() { a.visualizationView.NextClusterSet() })
	if text := a.heatmapText(); !showsHeatmap(text) || !strings.Contains(text, "Cluster Set 2/2") {
		t.Errorf("cluster set 2 does not show its heatmap after the data arrived:\n%s", firstLines(text, 8))
	}
}
