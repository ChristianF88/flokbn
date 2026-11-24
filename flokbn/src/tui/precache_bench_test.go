package tui

import (
	"runtime"
	"testing"

	"github.com/ChristianF88/flokbn/accesslog"
)

// precacheRequestData does what SetRequestData starts in the background once
// the parsed requests are handed over, up to the point where the first heatmap
// can be shown: fill the trie cache and prepare the visualization.
func precacheRequestData(a *App, reqs []accesslog.Request) *VisualizationView {
	a.trieCache.PreCacheAllTries(a, a.multiTrieResult, reqs)

	v := a.newVisualizationViewWith(len(a.multiTrieResult.Tries[0].Data))
	v.PreCacheAllTriesFor(reqs, 0)
	return v
}

// BenchmarkPrecacheRequestData measures the request hand-over for a 4-trie,
// 4-cluster-sets-per-trie result over 1,000,000 requests. Besides time and
// allocations it reports "retained-KB": the heap that stays live for the rest
// of the session once the precache is done (grids and rendered texts; the
// request slice itself is not counted).
func BenchmarkPrecacheRequestData(b *testing.B) {
	a, _ := lockTestApp()
	a.jsonResult = a.singleTrieOutput(0)
	reqs := makeClusteredRequests(1_000_000, 0.3, mustCIDRs(b,
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "203.0.113.0/24", "198.51.100.0/24", "192.0.2.0/24"))

	var before, after runtime.MemStats
	a.trieCache = nil
	runtime.GC()
	runtime.ReadMemStats(&before)
	a.trieCache = NewTrieCache()
	v := precacheRequestData(a, reqs)
	runtime.GC()
	runtime.ReadMemStats(&after)
	retainedKB := (float64(after.HeapAlloc) - float64(before.HeapAlloc)) / 1024
	runtime.KeepAlive(v)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a.trieCache = NewTrieCache()
		v = precacheRequestData(a, reqs)
	}
	b.StopTimer()
	runtime.KeepAlive(v)
	b.ReportMetric(retainedKB, "retained-KB")
}
