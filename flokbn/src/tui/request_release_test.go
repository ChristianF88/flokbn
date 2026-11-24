package tui

import (
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ChristianF88/flokbn/accesslog"
	"github.com/ChristianF88/flokbn/config"
	"github.com/ChristianF88/flokbn/output"
)

// TestRequestsReleasedAfterPrecache: the parsed requests are the whole log in
// memory, and the TUI needs them only to build the visualization grids. Once
// every trie is precached it must not keep them alive for the rest of the
// session - and everything must still be served from the cache afterwards.
func TestRequestsReleasedAfterPrecache(t *testing.T) {
	multi := output.NewJSONOutput("static", time.Now())
	multi.Tries = []output.TrieResult{
		{Name: "trie-a", Data: []output.ClusterResult{*newClusterSet("10.0.0.0/8")}},
		{Name: "trie-b", Data: []output.ClusterResult{*newClusterSet("192.168.0.0/16")}},
	}

	a := NewAppFromConfig(&config.Config{Static: &config.StaticConfig{}})
	stop := startSimApp(t, a)
	defer stop()

	// The finalizer on the slice's backing array fires only when nothing
	// references the requests any more.
	collected := make(chan struct{})
	reqs := raceTestRequests()
	runtime.SetFinalizer(&reqs[0], func(*accesslog.Request) { close(collected) })

	a.SetAnalysisResults(multi)
	a.SetRequestData(reqs)
	reqs = nil

	// The heatmap is refreshed at the end of the precache.
	waitFor(t, func() bool { return showsHeatmap(a.heatmapText()) }, 3*time.Second)

	if a.requestData() != nil {
		t.Error("App still references the requests after the precache")
	}
	released := false
	for i := 0; i < 100 && !released; i++ {
		runtime.GC()
		select {
		case <-collected:
			released = true
		case <-time.After(20 * time.Millisecond):
		}
	}
	if !released {
		t.Error("the parsed requests are still reachable after the precache")
	}

	// A trie switch is served from the cache alone.
	a.app.QueueUpdateDraw(func() { a.nextTrie() })
	waitFor(t, func() bool {
		var current int
		a.app.QueueUpdate(func() { current = a.currentTrie })
		return current == 1 && !a.switchingTrie.Load()
	}, 3*time.Second)
	if text := a.heatmapText(); !showsHeatmap(text) || !strings.Contains(text, "192.168.0.0/16") {
		t.Errorf("trie-b's heatmap is not shown after the requests were released:\n%s", firstLines(text, 8))
	}
}
