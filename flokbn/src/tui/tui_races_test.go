package tui

import (
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ChristianF88/flokbn/config"
	"github.com/ChristianF88/flokbn/ingestor"
	"github.com/ChristianF88/flokbn/output"
	"github.com/rivo/tview"
)

// raceTestRequests synthesizes a small request corpus that lands inside both
// tries' cluster ranges so every precache pass has real work to do.
func raceTestRequests() []ingestor.Request {
	dots := []string{
		"10.0.0.1", "10.1.2.3", "10.255.255.254", // inside trie-a 10.0.0.0/8
		"192.168.1.1", "192.168.254.9", // inside trie-b 192.168.0.0/16
		"8.8.8.8", "1.1.1.1", "203.0.113.5", // outside both
	}
	reqs := make([]ingestor.Request, 0, len(dots))
	for _, d := range dots {
		reqs = append(reqs, reqFor(d))
	}
	return reqs
}

// TestConcurrentTrieSwitchingNoRace is the -race regression test required by the
// Resolved decision. It reproduces the production concurrency around trie
// switching: SetRequestData launches a BACKGROUND trieCache.PreCacheAllTries
// goroutine (which used to mutate App.jsonResult/currentTrie under app.mu) while
// the UI goroutine runs the visualization PreCacheAllTries and reads/writes the
// same fields. Under UI-thread-only ownership neither precache may mutate those
// fields off the UI goroutine; run with `go test -race ./tui` to catch any
// residual lock-free access.
func TestConcurrentTrieSwitchingNoRace(t *testing.T) {
	multi := output.NewJSONOutput("static", time.Now())
	multi.General.TotalRequests = 100
	multi.Tries = []output.TrieResult{
		{Name: "trie-a", Data: []output.ClusterResult{*newClusterSet("10.0.0.0/8")}},
		{Name: "trie-b", Data: []output.ClusterResult{*newClusterSet("192.168.0.0/16")}},
	}

	reqs := raceTestRequests()

	a := &App{
		cfg:             &config.Config{},
		multiTrieResult: multi,
		trieCache:       NewTrieCache(),
		currentTrie:     0,
		requests:        reqs,
		summary:         tview.NewTextView(),
		clustering:      tview.NewTextView(),
		cidrAnalysis:    tview.NewTextView(),
		diagnostics:     tview.NewTextView(),
	}
	a.jsonResult = a.singleTrieOutput(0)
	if a.jsonResult == nil {
		t.Fatal("singleTrieOutput(0) returned nil")
	}
	a.visualizationView = a.NewVisualizationView()

	var wg sync.WaitGroup

	// Background precache goroutine, exactly as SetRequestData launches it. After
	// the fix this must not touch App.jsonResult/currentTrie at all.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			a.trieCache.PreCacheAllTries(a, a.multiTrieResult, reqs)
		}
	}()

	// Background single-trie precache goroutine, as switchTrieAsync launches it
	// on a cache miss. Also must not touch the UI-owned fields.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			a.trieCache.PreCacheSingleTrie(a, i%len(multi.Tries), a.multiTrieResult, reqs)
		}
	}()

	// "UI goroutine": the sole owner of jsonResult/currentTrie. Drive the viz
	// PreCacheAllTries (called on the UI thread in production) plus the field
	// reads/writes that the switch closures perform.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			a.visualizationView.PreCacheAllTries(reqs)
			idx := i % len(multi.Tries)
			a.currentTrie = idx
			a.jsonResult = a.singleTrieOutput(idx)
			_ = a.buildSummaryText()
			_ = a.buildClusteringText()
		}
	}()

	wg.Wait()
}

// TestUpdateVisualizationFromCacheResetsClusterSet pins finding #3: the cache-hit
// fast path must reset the displayed cluster set to 0 and refresh
// totalClusterSets on a trie switch, matching the slow fallback path.
//
// The trie counts and navigated index are chosen deliberately so the test is a
// genuine regression test: the navigated cluster-set index (1) is IN RANGE for
// the target trie (trie-b, 3 sets), so getCurrentClusterSet's out-of-range
// clamp (currentClusterSet >= actualClusterSets) does NOT fire. On the unfixed
// code (no explicit reset in updateVisualizationFromCache) currentClusterSet
// therefore stays at 1 and this test fails; only the explicit reset added by the
// fix yields currentClusterSet == 0.
func TestUpdateVisualizationFromCacheResetsClusterSet(t *testing.T) {
	a := newCacheTestApp(t)
	// trie-a has 2 cluster sets; trie-b has 3. The navigated index (1) is in
	// range for trie-b so the clamp in getCurrentClusterSet cannot mask a missing
	// reset, and totalClusterSets genuinely differs between the two tries.
	a.multiTrieResult.Tries[0].Data = []output.ClusterResult{
		*newClusterSet("10.0.0.0/8"),
		*newClusterSet("172.16.0.0/12"),
	}
	a.multiTrieResult.Tries[1].Data = []output.ClusterResult{
		*newClusterSet("192.168.0.0/16"),
		*newClusterSet("192.169.0.0/16"),
		*newClusterSet("192.170.0.0/16"),
	}
	a.jsonResult = a.singleTrieOutput(0)

	a.trieCache.PreCacheAllTries(a, a.multiTrieResult, nil)

	a.visualizationView = a.NewVisualizationView()
	a.visualizationView.totalClusterSets = len(a.jsonResult.Clustering.Data)

	// Simulate the user having navigated to cluster set 1 on trie-a. This index
	// is also valid for trie-b (3 sets), so the bounds-check clamp will NOT reset
	// it on the switch — only the explicit reset under test can.
	a.visualizationView.currentClusterSet = 1

	// Switch to trie-b via the cache-hit fast path.
	a.currentTrie = 1
	a.jsonResult = a.singleTrieOutput(1)
	a.updateVisualizationFromCache(1)

	if a.visualizationView.currentClusterSet != 0 {
		t.Errorf("currentClusterSet = %d after cache-hit trie switch, want 0 "+
			"(reset must happen even when the index is in range for the new trie)",
			a.visualizationView.currentClusterSet)
	}
	wantSets := len(a.jsonResult.Clustering.Data)
	if a.visualizationView.totalClusterSets != wantSets {
		t.Errorf("totalClusterSets = %d after switch, want %d",
			a.visualizationView.totalClusterSets, wantSets)
	}
}

// TestHeatmapTotalPercentageSumsPerRange pins finding #6: the heatmap
// "Total: ... (%)" line equals the SUM of the per-range percentages (the
// total-requests denominator), not totalRequests/uniqueIPs*100. The per-range
// lines must sum exactly to the Total, and the Total must differ from the old
// uniqueIPs-based value.
func TestHeatmapTotalPercentageSumsPerRange(t *testing.T) {
	// Per-range percentages chosen so their sum (0.50+0.30+0.20 = 1.00%) differs
	// from the old denominator: totalRequests=10000, uniqueIPs=500000 ->
	// 10000/500000*100 = 2.00%. Distinct values guarantee the test fails on the
	// old formula.
	clusterSet := output.ClusterResult{
		MergedRanges: []output.CIDRRange{
			{CIDR: "9.9.0.0/16", Requests: 5000, Percentage: 0.50},
			{CIDR: "9.10.0.0/16", Requests: 3000, Percentage: 0.30},
			{CIDR: "9.11.0.0/16", Requests: 2000, Percentage: 0.20},
		},
	}

	app := &App{}
	app.jsonResult = &output.JSONOutput{}
	app.jsonResult.General.UniqueIPs = 500000 // would yield 2.00% under the old formula
	app.jsonResult.Clustering.Data = []output.ClusterResult{clusterSet}

	v := &VisualizationView{
		app:                 app,
		totalClusterSets:    1,
		currentClusterSet:   0,
		cachedClusteredData: make(map[clusterKey][256][256]uint32),
	}
	// Populate some traffic so renderHeatmap runs (maxTraffic > 0).
	v.requests = repeatReq("9.9.0.1", 100)
	v.ProcessTrafficData(v.requests)

	text := v.generateRenderText()

	wantSum := 0.50 + 0.30 + 0.20 // 1.00%
	total := parseTotalPercentage(t, text)
	if absf(total-wantSum) > 1e-9 {
		t.Errorf("heatmap Total percentage = %.4f%%, want summed per-range %.4f%% (not uniqueIPs-based)", total, wantSum)
	}
	// The old uniqueIPs-based value (2.00%) must no longer be produced.
	if absf(total-2.00) < 1e-9 {
		t.Errorf("heatmap Total percentage still uses the uniqueIPs denominator (got %.4f%%)", total)
	}

	// Per-range lines must sum to the Total.
	perRangeSum := sumPerRangePercentages(t, text)
	if absf(perRangeSum-total) > 1e-9 {
		t.Errorf("per-range percentages sum to %.4f%% but Total is %.4f%%", perRangeSum, total)
	}
}

// parseTotalPercentage extracts the percentage from the heatmap footer
// "Total: ... requests (X.XX%)" line.
func parseTotalPercentage(t *testing.T, render string) float64 {
	t.Helper()
	for _, line := range strings.Split(render, "\n") {
		s := stripTviewTags(line)
		if strings.HasPrefix(strings.TrimSpace(s), "Total:") {
			return parsePercentInParens(t, s)
		}
	}
	t.Fatalf("no \"Total:\" line in render:\n%s", render)
	return 0
}

// sumPerRangePercentages sums the percentages on the per-range bullet lines
// ("  • CIDR: N requests (X.XX%)").
func sumPerRangePercentages(t *testing.T, render string) float64 {
	t.Helper()
	var sum float64
	for _, line := range strings.Split(render, "\n") {
		s := stripTviewTags(line)
		trimmed := strings.TrimSpace(s)
		if strings.HasPrefix(trimmed, "•") && strings.Contains(trimmed, "requests (") {
			sum += parsePercentInParens(t, s)
		}
	}
	return sum
}

// parsePercentInParens parses the "X.XX" inside the trailing "(X.XX%)".
func parsePercentInParens(t *testing.T, s string) float64 {
	t.Helper()
	open := strings.LastIndex(s, "(")
	pct := strings.Index(s, "%")
	if open < 0 || pct < 0 || pct < open {
		t.Fatalf("no (X.XX%%) in line: %q", s)
	}
	val, err := strconv.ParseFloat(strings.TrimSpace(s[open+1:pct]), 64)
	if err != nil {
		t.Fatalf("parse percent in %q: %v", s, err)
	}
	return val
}

func absf(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}
