package tui

import (
	"sync"

	"github.com/ChristianF88/flokbn/accesslog"
	"github.com/ChristianF88/flokbn/cidr"
	"github.com/ChristianF88/flokbn/output"
)

// TrieCache holds all trie data in RAM so trie switching needs no recomputation
// This eliminates any conversion or processing delays during trie switching.
//
// It is the TUI's only cache of derived data: the results panels and the
// visualization both read from it, and only the precache functions below scan
// the parsed requests.
type TrieCache struct {
	mu sync.RWMutex

	// Pre-computed data
	trieOutput      map[int]*output.JSONOutput // Single-trie output per trie
	summaryTexts    map[int]string             // Pre-rendered summary text per trie
	clusterTexts    map[int]string             // Pre-rendered clustering text per trie
	cidrTexts       map[int]string             // Pre-rendered CIDR text per trie
	diagnosticTexts map[int]string             // Pre-rendered diagnostic text per trie

	// Visualization data. A grid counts requests per /16: grid[a][b] for the
	// first two octets a.b. A published grid is never written again, so readers
	// share the pointer instead of copying 256 KiB per lookup.

	// Clustered-traffic grids per trie per cluster set. clusteredMatrixes[trie][set][a][b]
	// counts requests in /16 a.b whose full IP is inside a detected cluster
	// range of that (trie, set). Used for the traffic-capture overlay. A trie
	// has an entry only once it was precached with request data.
	clusteredMatrixes map[int][]*[256][256]uint32

	// Ground-truth traffic over ALL parsed requests: one grid, shown for every
	// trie. Computed once, by the first precache that has request data; nil
	// until then.
	globalTraffic    *[256][256]uint32
	globalMaxTraffic uint32
}

// NewTrieCache creates a new fast trie cache
func NewTrieCache() *TrieCache {
	return &TrieCache{
		trieOutput:        make(map[int]*output.JSONOutput),
		summaryTexts:      make(map[int]string),
		clusterTexts:      make(map[int]string),
		cidrTexts:         make(map[int]string),
		diagnosticTexts:   make(map[int]string),
		clusteredMatrixes: make(map[int][]*[256][256]uint32),
	}
}

// PreCacheAllTries processes and caches all trie data upfront.
//
// Locking: every full request scan and every text render runs WITHOUT ftc.mu;
// the write lock is only taken to publish one finished trie at a time (map
// stores). The UI goroutine reads this cache under the read lock on every trie
// switch and heatmap render, so holding the write lock across the scans would
// freeze the TUI for the whole precache.
func (ftc *TrieCache) PreCacheAllTries(app *App, multiResult *output.JSONOutput, requests []accesslog.Request) {
	if multiResult == nil || len(multiResult.Tries) == 0 {
		return
	}

	// Process each trie and cache everything
	for trieIndex := 0; trieIndex < len(multiResult.Tries); trieIndex++ {
		ftc.precacheTrie(app, trieIndex, multiResult, requests)
	}
}

// PreCacheSingleTrie caches a specific trie with priority
func (ftc *TrieCache) PreCacheSingleTrie(app *App, trieIndex int, multiResult *output.JSONOutput, requests []accesslog.Request) bool {
	if multiResult == nil || trieIndex >= len(multiResult.Tries) {
		return false
	}
	return ftc.precacheTrie(app, trieIndex, multiResult, requests)
}

// precacheTrie computes everything the cache holds for one trie and publishes
// it. The computation (single-trie conversion, text rendering, request scans)
// runs unlocked on local values; ftc.mu is held only for the final stores.
// Renders from the locally-derived single-trie output and index - it does NOT
// touch app.jsonResult/currentTrie, which are owned exclusively by the tview UI
// goroutine. Returns false when the trie cannot be converted.
func (ftc *TrieCache) precacheTrie(app *App, trieIndex int, multiResult *output.JSONOutput, requests []accesslog.Request) bool {
	// 1. Convert to single-trie output
	trieOutput := app.singleTrieOutput(trieIndex)
	if trieOutput == nil {
		return false
	}

	// 2. Pre-render all text components
	summary := app.buildSummaryTextFor(trieIndex)
	clustering := app.buildClusteringTextFor(trieOutput)
	cidr := app.buildCidrAnalysisTextFor(trieOutput)
	diagnostics := app.buildDiagnosticsTextFor(trieOutput)

	// 3. Pre-process traffic data for visualization. A precache that runs
	// before the request data has arrived (a trie switch right after the results
	// are shown) publishes the texts only: all-zero grids must not pass for the
	// real ones, and a later call with the requests fills them in.
	var clustered []*[256][256]uint32
	if len(requests) > 0 {
		ftc.ensureGlobalTraffic(requests)
		clustered = clusteredGrids(requests, multiResult.Tries[trieIndex])
	}

	ftc.mu.Lock()
	defer ftc.mu.Unlock()

	ftc.trieOutput[trieIndex] = trieOutput
	ftc.summaryTexts[trieIndex] = summary
	ftc.clusterTexts[trieIndex] = clustering
	ftc.cidrTexts[trieIndex] = cidr
	ftc.diagnosticTexts[trieIndex] = diagnostics
	if clustered != nil {
		ftc.clusteredMatrixes[trieIndex] = clustered
	}
	return true
}

// ensureGlobalTraffic computes the traffic matrix over ALL parsed requests on
// first use. The matrix is ground truth - identical for every trie - so it is
// computed once and shared; only the clustered grids are trie-specific.
//
// The scan runs without ftc.mu. Two concurrent first callers may both scan;
// they compute the same matrix and the first to finish publishes it.
func (ftc *TrieCache) ensureGlobalTraffic(requests []accesslog.Request) {
	ftc.mu.RLock()
	ready := ftc.globalTraffic != nil
	ftc.mu.RUnlock()
	if ready {
		return
	}

	m, maxTraffic := trafficGrid(requests)

	ftc.mu.Lock()
	if ftc.globalTraffic == nil {
		ftc.globalTraffic = m
		ftc.globalMaxTraffic = maxTraffic
	}
	ftc.mu.Unlock()
}

// trafficGrid counts the requests per /16 (first.second octet) and returns the
// grid together with its busiest bin. It touches no cache state and takes no
// lock.
func trafficGrid(requests []accesslog.Request) (*[256][256]uint32, uint32) {
	m := new([256][256]uint32)
	var maxTraffic uint32
	for i := range requests {
		ip := requests[i].IPUint32
		if ip == 0 {
			continue
		}
		a := byte(ip >> 24)
		b := byte(ip >> 16)
		m[a][b]++
		if m[a][b] > maxTraffic {
			maxTraffic = m[a][b]
		}
	}
	return m, maxTraffic
}

// clusteredGrids builds one clustered-traffic grid per cluster set of a trie in
// a single pass over the requests. It touches no cache state and takes no lock.
//
// requests holds ALL parsed requests, not the trie's filtered subset (the TUI
// is never handed per-trie request sets). The overlay therefore counts every
// parsed request whose IP lies inside the set's detected ranges, including
// requests the trie's own filters (User-Agent, endpoint, time range, UA
// whitelist) excluded from detection. That matches the heatmap it is drawn on,
// which is all traffic too, so the dot stays a true share of the cell: "how
// much of what this cell received would a ban on these ranges hit". It is NOT
// the request count the range was detected with; that number is the per-range
// "requests" figure listed below the map.
func clusteredGrids(requests []accesslog.Request, trieResult output.TrieResult) []*[256][256]uint32 {
	// Pre-parse each cluster set's detected ranges once into sorted intervals so
	// membership is an allocation-free binary search in the hot loop. One
	// clustered grid is accumulated per cluster set in a single pass.
	intervalsPerSet := make([]cidr.IntervalSet, len(trieResult.Data))
	clusteredPerSet := make([]*[256][256]uint32, len(trieResult.Data))
	for s := range trieResult.Data {
		intervalsPerSet[s] = buildClusterIntervals(&trieResult.Data[s])
		clusteredPerSet[s] = &[256][256]uint32{}
	}

	if len(intervalsPerSet) > 0 {
		for i := range requests {
			ip := requests[i].IPUint32
			if ip == 0 {
				continue
			}
			a := byte(ip >> 24)
			b := byte(ip >> 16)
			for s := range intervalsPerSet {
				if intervalsPerSet[s].Contains(ip) {
					clusteredPerSet[s][a][b]++
				}
			}
		}
	}

	return clusteredPerSet
}

// GetClusteredData returns the cached clustered-traffic grid for a (trie,
// cluster set) pair, if present. The grid is shared and must not be modified.
func (ftc *TrieCache) GetClusteredData(trieIndex, clusterSetIndex int) (grid *[256][256]uint32, exists bool) {
	ftc.mu.RLock()
	defer ftc.mu.RUnlock()

	setGrids := ftc.clusteredMatrixes[trieIndex]
	if clusterSetIndex < 0 || clusterSetIndex >= len(setGrids) {
		return nil, false
	}
	return setGrids[clusterSetIndex], true
}

// GetTrieOutput returns the cached single-trie output
func (ftc *TrieCache) GetTrieOutput(trieIndex int) (*output.JSONOutput, bool) {
	ftc.mu.RLock()
	defer ftc.mu.RUnlock()

	data, exists := ftc.trieOutput[trieIndex]
	return data, exists
}

// GetPreRenderedTexts returns all pre-rendered texts for a trie
func (ftc *TrieCache) GetPreRenderedTexts(trieIndex int) (summary, clustering, cidr, diagnostics string, exists bool) {
	ftc.mu.RLock()
	defer ftc.mu.RUnlock()

	summary, summaryExists := ftc.summaryTexts[trieIndex]
	clustering, clusteringExists := ftc.clusterTexts[trieIndex]
	cidr, cidrExists := ftc.cidrTexts[trieIndex]
	diagnostics, diagnosticsExists := ftc.diagnosticTexts[trieIndex]

	exists = summaryExists && clusteringExists && cidrExists && diagnosticsExists
	return summary, clustering, cidr, diagnostics, exists
}

// SetPreRenderedTexts stores all four pre-rendered panel texts for a trie.
func (ftc *TrieCache) SetPreRenderedTexts(trieIndex int, summary, clustering, cidr, diagnostics string) {
	ftc.mu.Lock()
	defer ftc.mu.Unlock()

	ftc.summaryTexts[trieIndex] = summary
	ftc.clusterTexts[trieIndex] = clustering
	ftc.cidrTexts[trieIndex] = cidr
	ftc.diagnosticTexts[trieIndex] = diagnostics
}

// GetTrafficData returns the cached ground-truth traffic matrix (the same for
// every trie) and its busiest /16 bin, once a precache with request data has
// computed it. The matrix is shared and must not be modified.
func (ftc *TrieCache) GetTrafficData() (trafficMatrix *[256][256]uint32, maxTraffic uint32, exists bool) {
	ftc.mu.RLock()
	defer ftc.mu.RUnlock()

	return ftc.globalTraffic, ftc.globalMaxTraffic, ftc.globalTraffic != nil
}
