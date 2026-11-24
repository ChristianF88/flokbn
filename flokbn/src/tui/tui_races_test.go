package tui

import (
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ChristianF88/flokbn/accesslog"
	"github.com/ChristianF88/flokbn/config"
	"github.com/ChristianF88/flokbn/output"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// raceTestRequests synthesizes a small request corpus that lands inside both
// tries' cluster ranges so every precache pass has real work to do.
func raceTestRequests() []accesslog.Request {
	dots := []string{
		"10.0.0.1", "10.1.2.3", "10.255.255.254", // inside trie-a 10.0.0.0/8
		"192.168.1.1", "192.168.254.9", // inside trie-b 192.168.0.0/16
		"8.8.8.8", "1.1.1.1", "203.0.113.5", // outside both
	}
	reqs := make([]accesslog.Request, 0, len(dots))
	for _, d := range dots {
		reqs = append(reqs, reqFor(d))
	}
	return reqs
}

// TestConcurrentTrieSwitchingNoRace is the -race regression test required by the
// Resolved decision. It reproduces the production concurrency around trie
// switching: SetRequestData launches a BACKGROUND trieCache.PreCacheAllTries
// goroutine (which used to mutate App.jsonResult/currentTrie under app.mu) while
// the UI goroutine switches tries, renders the visualization from the same
// cache and reads/writes those fields. Under UI-thread-only ownership the
// precache may not mutate them off the UI goroutine, and the grids it publishes
// must be safe to render from while it is still running; run with
// `go test -race ./tui` to catch any residual lock-free access.
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

	// "UI goroutine": the sole owner of jsonResult/currentTrie and of the
	// visualization view. Drive the field reads/writes that the switch closures
	// perform plus the heatmap render, which reads the grids the two precache
	// goroutines above are publishing.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			idx := i % len(multi.Tries)
			a.currentTrie = idx
			a.jsonResult = a.singleTrieOutput(idx)
			a.visualizationView.updateForCurrentTrie()
			_ = a.visualizationView.generateRenderText()
			_ = a.buildSummaryText()
			_ = a.buildClusteringText()
		}
	}()

	wg.Wait()
}

// TestSetRequestDataVizPathNoRace is the AUDIT-02 regression test for the
// visualization data races (findings #1 + #2 + #3). It drives the REAL ordering
// the CLI layer uses - SetAnalysisResults then SetRequestData - on a live tview
// event loop (SimulationScreen), so the background precache runs concurrently
// with the UI render closures, exactly as in production.
//
// This path once had two concurrent writers of the same VisualizationView (an
// off-thread initialisation and a UI closure both wrote its maps and
// scalar/array fields), producing a concurrent-map-write panic and data races.
// The view now never leaves the UI goroutine and holds no data: the background
// goroutine writes only the TrieCache, and the view renders from it. Run with
// `go test -race ./tui` to verify clean.
func TestSetRequestDataVizPathNoRace(t *testing.T) {
	multi := output.NewJSONOutput("static", time.Now())
	multi.General.TotalRequests = 100
	multi.Tries = []output.TrieResult{
		{Name: "trie-a", Data: []output.ClusterResult{
			*newClusterSet("10.0.0.0/8"),
			*newClusterSet("172.16.0.0/12"),
		}},
		{Name: "trie-b", Data: []output.ClusterResult{
			*newClusterSet("192.168.0.0/16"),
		}},
	}

	a := NewAppFromConfig(&config.Config{Static: &config.StaticConfig{}}, "")

	// Drive a real event loop on a headless simulation screen so QueueUpdateDraw
	// closures actually execute (the publish + render steps run on this loop).
	sim := tcell.NewSimulationScreen("UTF-8")
	if err := sim.Init(); err != nil {
		t.Fatalf("sim.Init: %v", err)
	}
	sim.SetSize(120, 40)
	a.app.SetScreen(sim)

	runErr := make(chan error, 1)
	go func() { runErr <- a.app.Run() }()

	reqs := raceTestRequests()

	// Production order: results first, then request data (which fills the cache
	// the viz renders from).
	a.SetAnalysisResults(multi)
	a.SetRequestData(reqs)

	// Wait until the background precache has refreshed the view with the
	// heatmap, then drive a few UI-thread reads/writes that used to race with
	// the off-thread producer.
	waitFor(t, func() bool { return showsHeatmap(a.heatmapText()) }, 5*time.Second)

	a.app.QueueUpdateDraw(func() {
		a.showVisualization()
		if a.visualizationView != nil {
			a.visualizationView.NextClusterSet()
			a.visualizationView.PrevClusterSet()
			a.visualizationView.ToggleIntensityScale()
		}
		a.updateStatusBar()
	})

	a.app.Stop()
	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("app.Run: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("app.Run did not return after Stop")
	}
	// tview's Run() finalizes the screen on Stop; do not Fini it again here.
}

// waitFor polls cond until it returns true or the timeout elapses.
func waitFor(t *testing.T, cond func() bool, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	if !cond() {
		t.Fatal("waitFor: condition not met before timeout")
	}
}

// TestVizRenderDuringPrecacheNoRace replaces the race test of the view's own
// (no-config) precache, which is gone: views no longer scan requests or keep
// grids, they render from the shared TrieCache. Several views - each owned by
// one goroutine, as the single view is owned by the UI goroutine in production
// - render every cluster set while the cache is being precached concurrently.
// A published grid is immutable, so the renders must never observe a write.
// Run with `go test -race ./tui`.
func TestVizRenderDuringPrecacheNoRace(t *testing.T) {
	multi := output.NewJSONOutput("static", time.Now())
	multi.Tries = []output.TrieResult{{Name: "trie", Data: []output.ClusterResult{
		*newClusterSet("10.0.0.0/8"),
		*newClusterSet("192.168.0.0/16"),
	}}}
	app := &App{cfg: &config.Config{}, multiTrieResult: multi, trieCache: NewTrieCache()}
	app.jsonResult = app.singleTrieOutput(0)

	reqs := raceTestRequests()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			app.trieCache.PreCacheAllTries(app, multi, reqs)
		}
	}()
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Each goroutine owns its OWN view; the cache is the only shared state.
			v := app.NewVisualizationView()
			for i := 0; i < 20; i++ {
				v.currentClusterSet = i % v.totalClusterSets
				v.RenderCached()
			}
		}()
	}
	wg.Wait()

	// Once the precache is done every view renders the real heatmap.
	v := app.NewVisualizationView()
	if text := v.generateRenderText(); v.loading || !strings.Contains(text, "256 A") {
		t.Errorf("view still shows the loading placeholder after the precache:\n%s", firstLines(text, 6))
	}
}

// TestTrieSwitchResetsVisualizationClusterSet pins finding #3: a trie switch
// (updateForCurrentTrie, formerly the cache-hit fast path
// updateVisualizationFromCache) must reset the displayed cluster set to 0 and
// refresh totalClusterSets.
//
// The trie counts and navigated index are chosen deliberately so the test is a
// genuine regression test: the navigated cluster-set index (1) is IN RANGE for
// the target trie (trie-b, 3 sets), so getCurrentClusterSet's out-of-range
// clamp (currentClusterSet >= actualClusterSets) does NOT fire. Without the
// explicit reset currentClusterSet therefore stays at 1 and this test fails;
// only the explicit reset yields currentClusterSet == 0.
func TestTrieSwitchResetsVisualizationClusterSet(t *testing.T) {
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
	// it on the switch - only the explicit reset under test can.
	a.visualizationView.currentClusterSet = 1

	// Switch to trie-b the way the switch closures do.
	a.currentTrie = 1
	a.jsonResult = a.singleTrieOutput(1)
	a.visualizationView.updateForCurrentTrie()

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

	// Populate some traffic so renderHeatmap runs (maxTraffic > 0).
	v := newOverlayViewFor(repeatReq("9.9.0.1", 100), clusterSet)
	v.app.jsonResult.General.UniqueIPs = 500000 // would yield 2.00% under the old formula

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
