package tui

import (
	"testing"
	"time"

	"github.com/ChristianF88/flokbn/config"
	"github.com/ChristianF88/flokbn/output"
	"github.com/rivo/tview"
)

// newCacheTestApp builds a headless multi-trie App wired the way
// NewAppFromConfig wires it: cfg set, trieCache present, panels created,
// jsonResult pointing at the current trie's converted output.
func newCacheTestApp(t *testing.T) *App {
	t.Helper()

	multi := output.NewJSONOutput("static", time.Now())
	multi.General.TotalRequests = 42
	multi.Tries = []output.TrieResult{
		{Name: "trie-a", Data: []output.ClusterResult{*newClusterSet("10.0.0.0/8")}},
		{Name: "trie-b", Data: []output.ClusterResult{*newClusterSet("192.168.0.0/16")}},
	}

	a := &App{
		cfg:             &config.Config{},
		multiTrieResult: multi,
		trieCache:       NewTrieCache(),
		currentTrie:     0,
		summary:         tview.NewTextView(),
		clustering:      tview.NewTextView(),
		cidrAnalysis:    tview.NewTextView(),
		diagnostics:     tview.NewTextView(),
	}
	a.jsonResult = a.singleTrieOutput(0)
	if a.jsonResult == nil {
		t.Fatal("singleTrieOutput(0) returned nil")
	}
	return a
}

// TestDisplayCachedResultsSeedsCache verifies the miss path builds all four
// panel texts, stores them in the shared TrieCache, and displays them.
func TestDisplayCachedResultsSeedsCache(t *testing.T) {
	a := newCacheTestApp(t)

	if _, _, _, _, ok := a.trieCache.GetPreRenderedTexts(0); ok {
		t.Fatal("cache unexpectedly populated before first display")
	}

	a.displayCachedResults()

	summary, clustering, cidr, diagnostics, ok := a.trieCache.GetPreRenderedTexts(0)
	if !ok {
		t.Fatal("displayCachedResults did not seed the cache")
	}
	want := map[string][2]string{
		"summary":     {summary, a.buildSummaryText()},
		"clustering":  {clustering, a.buildClusteringText()},
		"cidr":        {cidr, a.buildCidrAnalysisText()},
		"diagnostics": {diagnostics, a.buildDiagnosticsText()},
	}
	for name, pair := range want {
		if pair[0] != pair[1] {
			t.Errorf("%s: cached text differs from freshly built text", name)
		}
		if pair[0] == "" {
			t.Errorf("%s: cached text is empty", name)
		}
	}
}

// TestDisplayCachedResultsHitWinsOverRebuild verifies the hit path returns
// the cached texts without rebuilding, so the former two caches can no
// longer diverge.
func TestDisplayCachedResultsHitWinsOverRebuild(t *testing.T) {
	a := newCacheTestApp(t)

	a.trieCache.SetPreRenderedTexts(0, "S-sentinel", "C-sentinel", "R-sentinel", "D-sentinel")
	a.displayCachedResults()

	got := []struct {
		name, text, want string
	}{
		{"summary", a.summary.GetText(false), "S-sentinel"},
		{"clustering", a.clustering.GetText(false), "C-sentinel"},
		{"cidr", a.cidrAnalysis.GetText(false), "R-sentinel"},
		{"diagnostics", a.diagnostics.GetText(false), "D-sentinel"},
	}
	for _, g := range got {
		if g.text != g.want+"\n" && g.text != g.want {
			t.Errorf("%s: got %q, want cached sentinel %q", g.name, g.text, g.want)
		}
	}
}

// TestFastAndCachedPathsAgree verifies displayResultsFromTrieCache and
// displayCachedResults render identical texts for every trie — the
// regression test for the former divergent dual-cache design.
func TestFastAndCachedPathsAgree(t *testing.T) {
	a := newCacheTestApp(t)
	a.trieCache.PreCacheAllTries(a, a.multiTrieResult, nil)

	for i := range a.multiTrieResult.Tries {
		a.currentTrie = i
		a.jsonResult = a.singleTrieOutput(i)

		a.displayResultsFromTrieCache(i)
		fast := [4]string{
			a.summary.GetText(true),
			a.clustering.GetText(true),
			a.cidrAnalysis.GetText(true),
			a.diagnostics.GetText(true),
		}

		a.displayCachedResults()
		cached := [4]string{
			a.summary.GetText(true),
			a.clustering.GetText(true),
			a.cidrAnalysis.GetText(true),
			a.diagnostics.GetText(true),
		}

		if fast != cached {
			t.Errorf("trie %d: fast path and cached path rendered different texts", i)
		}
	}
}
