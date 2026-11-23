package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/ChristianF88/flokbn/config"
	"github.com/ChristianF88/flokbn/output"
)

// clusterParamsApp builds an App whose only trie has one cluster set with a
// threshold that distinguishes the formats: 0.25 is "0.2" with %.1f (what the
// visualization used to print) and "0.25" with %.2f (the plain renderer).
func clusterParamsApp() *App {
	set := newClusterSet("10.0.0.0/8")
	set.Parameters = output.ClusterParameters{
		MinClusterSize:       1000,
		MinDepth:             24,
		MaxDepth:             32,
		MeanSubnetDifference: 0.25,
	}
	multi := output.NewJSONOutput("static", time.Now())
	multi.Tries = []output.TrieResult{{Name: "trie-a", Data: []output.ClusterResult{*set}}}

	a := &App{cfg: &config.Config{}, multiTrieResult: multi, trieCache: NewTrieCache()}
	a.jsonResult = a.singleTrieOutput(0)
	return a
}

// wantClusterParams is the one rendering every view must show for the set in
// clusterParamsApp - identical to the plain-text renderer's
// "Set 1: min_size=1000, depth=24-32, threshold=0.25".
const wantClusterParams = "min_size=1000, depth=24-32, threshold=0.25"

// TestClusteringPanelShowsThreshold: the clustering panel printed min_size and
// the depth range but omitted the threshold, so two sets differing only in
// their threshold were indistinguishable.
func TestClusteringPanelShowsThreshold(t *testing.T) {
	a := clusterParamsApp()

	got := visibleText(a.buildClusteringTextFor(a.jsonResult))

	if want := "Set 1 (" + wantClusterParams + ")"; !strings.Contains(got, want) {
		t.Errorf("clustering panel is missing %q\nvisible text:\n%s", want, got)
	}
}

// TestVisualizationParametersMatchPlainOutput: the visualization header printed
// the threshold as "mean_diff=%.1f" (0.25 became 0.2) while the plain renderer
// prints "threshold=%.2f". All views must agree.
func TestVisualizationParametersMatchPlainOutput(t *testing.T) {
	a := clusterParamsApp()
	v := a.NewVisualizationView()

	got := visibleText(v.generateRenderText())

	if want := "Parameters: " + wantClusterParams; !strings.Contains(got, want) {
		t.Errorf("visualization header is missing %q\nvisible text:\n%s", want, firstLines(got, 3))
	}
}

// firstLines returns the first n lines of s.
func firstLines(s string, n int) string {
	lines := strings.SplitN(s, "\n", n+1)
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}
