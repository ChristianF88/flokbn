package tui

import (
	"runtime"
	"testing"
	"time"

	"github.com/ChristianF88/flokbn/accesslog"
	"github.com/ChristianF88/flokbn/config"
	"github.com/ChristianF88/flokbn/output"
	"github.com/gdamore/tcell/v2"
)

// lockTestApp builds an App with several tries and cluster sets plus a request
// corpus large enough that precaching it takes real time (full request scans
// per trie and per cluster set).
func lockTestApp() (*App, []accesslog.Request) {
	multi := output.NewJSONOutput("static", time.Now())
	for _, name := range []string{"trie-a", "trie-b", "trie-c", "trie-d"} {
		multi.Tries = append(multi.Tries, output.TrieResult{
			Name: name,
			Data: []output.ClusterResult{
				*newClusterSet("10.0.0.0/8"),
				*newClusterSet("172.16.0.0/12", "192.168.0.0/16"),
				*newClusterSet("203.0.113.0/24"),
				*newClusterSet("198.51.100.0/24", "192.0.2.0/24"),
			},
		})
	}

	reqs := make([]accesslog.Request, 300_000)
	for i := range reqs {
		// Spread over the address space; never 0 (0 = "no IP", skipped).
		reqs[i].IPUint32 = uint32(i)*2654435761 | 1
	}

	a := &App{cfg: &config.Config{}, multiTrieResult: multi, trieCache: NewTrieCache()}
	return a, reqs
}

// TestPreCacheAllTriesDoesNotHoldLockAcrossScans is the regression test for the
// UI stall: PreCacheAllTries used to take the cache's write lock once and keep
// it for the whole precache, i.e. across every full request scan of every trie.
// The UI goroutine reads the same cache under the read lock (trie switch,
// visualization), so it froze until the background precache finished.
//
// The scans must run without the lock; it may only be taken to publish a
// finished entry. A reader probing the lock while the precache runs must
// therefore find it free nearly always (before the fix: never).
func TestPreCacheAllTriesDoesNotHoldLockAcrossScans(t *testing.T) {
	a, reqs := lockTestApp()
	ftc := a.trieCache

	started := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		close(started)
		ftc.PreCacheAllTries(a, a.multiTrieResult, reqs)
	}()

	<-started
	var free, held int
probe:
	for {
		select {
		case <-done:
			break probe
		default:
		}
		if ftc.mu.TryRLock() {
			ftc.mu.RUnlock()
			free++
		} else {
			held++
		}
		runtime.Gosched()
	}

	if free+held == 0 {
		t.Skip("precache finished before the lock could be probed")
	}
	t.Logf("read lock free on %d of %d probes", free, free+held)
	if free <= held {
		t.Errorf("read lock was free on %d of %d probes during PreCacheAllTries; "+
			"the write lock is being held across the request scans", free, free+held)
	}

	// The precache must still have published every trie.
	if _, maxTraffic, ok := ftc.GetTrafficData(); !ok || maxTraffic == 0 {
		t.Errorf("traffic data ok=%v max=%d, want cached non-zero traffic", ok, maxTraffic)
	}
	for i := range a.multiTrieResult.Tries {
		if _, ok := ftc.GetTrieOutput(i); !ok {
			t.Errorf("trie %d: no cached output after PreCacheAllTries", i)
		}
		if _, _, _, _, ok := ftc.GetPreRenderedTexts(i); !ok {
			t.Errorf("trie %d: no cached texts after PreCacheAllTries", i)
		}
		for s := range a.multiTrieResult.Tries[i].Data {
			if _, ok := ftc.GetClusteredData(i, s); !ok {
				t.Errorf("trie %d set %d: no cached clustered grid", i, s)
			}
		}
	}
}

// TestPreCacheMatchesDirectComputation pins that moving the scans out of the
// lock did not change what is cached: the traffic matrix and the clustered
// grids equal an independent recomputation.
func TestPreCacheMatchesDirectComputation(t *testing.T) {
	a, reqs := lockTestApp()
	reqs = reqs[:20_000]
	a.trieCache.PreCacheAllTries(a, a.multiTrieResult, reqs)

	var wantTraffic [256][256]uint32
	var wantMax uint32
	for i := range reqs {
		ip := reqs[i].IPUint32
		c := &wantTraffic[byte(ip>>24)][byte(ip>>16)]
		*c++
		if *c > wantMax {
			wantMax = *c
		}
	}

	gotTraffic, gotMax, ok := a.trieCache.GetTrafficData()
	if !ok {
		t.Fatalf("traffic data not cached")
	}
	if *gotTraffic != wantTraffic || gotMax != wantMax {
		t.Errorf("cached traffic matrix (max %d) differs from recomputation (max %d)", gotMax, wantMax)
	}

	for ti := range a.multiTrieResult.Tries {
		for si := range a.multiTrieResult.Tries[ti].Data {
			intervals := buildClusterIntervals(&a.multiTrieResult.Tries[ti].Data[si])
			var want [256][256]uint32
			for i := range reqs {
				if ip := reqs[i].IPUint32; intervals.Contains(ip) {
					want[byte(ip>>24)][byte(ip>>16)]++
				}
			}
			got, ok := a.trieCache.GetClusteredData(ti, si)
			if !ok {
				t.Fatalf("trie %d set %d: clustered grid not cached", ti, si)
			}
			if *got != want {
				t.Errorf("trie %d set %d: cached clustered grid differs from recomputation", ti, si)
			}
		}
	}
}

// TestPreCacheWithoutRequestsDoesNotFreezeTraffic: a precache that runs before
// the request data has arrived (a trie switch right after the results are
// shown) must not mark the all-zero traffic matrix as final, nor publish
// all-zero clustered grids for its trie. Once the requests are there, the next
// precache has to pick them up.
func TestPreCacheWithoutRequestsDoesNotFreezeTraffic(t *testing.T) {
	a, reqs := lockTestApp()
	reqs = reqs[:1000]

	if !a.trieCache.PreCacheSingleTrie(a, 1, a.multiTrieResult, nil) {
		t.Fatal("PreCacheSingleTrie without requests returned false")
	}
	// The texts are there, the grids are not: the view must keep showing its
	// loading placeholder instead of an empty heatmap.
	if _, _, _, _, ok := a.trieCache.GetPreRenderedTexts(1); !ok {
		t.Error("texts not cached by the precache without requests")
	}
	if _, _, ok := a.trieCache.GetTrafficData(); ok {
		t.Error("traffic matrix published by a precache without requests")
	}
	if _, ok := a.trieCache.GetClusteredData(1, 0); ok {
		t.Error("clustered grid published by a precache without requests")
	}

	a.trieCache.PreCacheAllTries(a, a.multiTrieResult, reqs)

	if _, maxTraffic, ok := a.trieCache.GetTrafficData(); !ok || maxTraffic == 0 {
		t.Errorf("traffic ok=%v max=%d after the requests arrived, want non-zero traffic", ok, maxTraffic)
	}
	for ti := range a.multiTrieResult.Tries {
		if _, ok := a.trieCache.GetClusteredData(ti, 0); !ok {
			t.Errorf("trie %d: no clustered grid after the requests arrived", ti)
		}
	}

	// A later precache without requests must not take the grids away again.
	a.trieCache.PreCacheSingleTrie(a, 1, a.multiTrieResult, nil)
	if _, ok := a.trieCache.GetClusteredData(1, 0); !ok {
		t.Error("precache without requests dropped the trie's clustered grids")
	}
}

// TestShowVisualizationRequestsNoRace is the -race regression test for the
// unlocked read of App.requests: showVisualization (UI goroutine, 'v' key) read
// the slice without a.mu while SetRequestData (analysis goroutine) writes it
// under a.mu. Pressing 'v' right after the results appeared raced with the
// request hand-over. Run with `go test -race ./tui`.
func TestShowVisualizationRequestsNoRace(t *testing.T) {
	multi := output.NewJSONOutput("static", time.Now())
	multi.Tries = []output.TrieResult{
		{Name: "trie-a", Data: []output.ClusterResult{*newClusterSet("10.0.0.0/8")}},
		{Name: "trie-b", Data: []output.ClusterResult{*newClusterSet("192.168.0.0/16")}},
	}

	a := NewAppFromConfig(&config.Config{Static: &config.StaticConfig{}}, "")
	sim := tcell.NewSimulationScreen("UTF-8")
	if err := sim.Init(); err != nil {
		t.Fatalf("sim.Init: %v", err)
	}
	sim.SetSize(120, 40)
	a.app.SetScreen(sim)

	runErr := make(chan error, 1)
	go func() { runErr <- a.app.Run() }()

	a.SetAnalysisResults(multi)

	// The 'v' key and a trie switch on the UI goroutine, then the request
	// hand-over on this goroutine. The sleep is deliberately NOT a
	// synchronisation edge: it only makes the UI-side reads happen first, so the
	// race detector sees an unordered read/write pair on the unfixed code.
	queued := make(chan struct{})
	go func() {
		defer close(queued)
		a.app.QueueUpdateDraw(func() {
			a.showVisualization()
			a.nextTrie()
		})
	}()
	time.Sleep(50 * time.Millisecond)
	a.SetRequestData(raceTestRequests())
	<-queued

	// Let the background precache goroutines finish before stopping.
	waitFor(t, func() bool {
		_, ok0 := a.trieCache.GetTrieOutput(0)
		_, ok1 := a.trieCache.GetTrieOutput(1)
		return ok0 && ok1 && !a.switchingTrie.Load()
	}, 5*time.Second)
	a.app.QueueUpdateDraw(func() {})

	a.app.Stop()
	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("app.Run: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("app.Run did not return after Stop")
	}
}
