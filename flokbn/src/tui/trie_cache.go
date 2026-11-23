package tui

import (
	"sync"
	"time"

	"github.com/ChristianF88/flokbn/ingestor"
	"github.com/ChristianF88/flokbn/output"
)

// TrieCache holds all trie data in RAM so trie switching needs no recomputation
// This eliminates any conversion or processing delays during trie switching
type TrieCache struct {
	mu sync.RWMutex

	// Pre-computed data
	trieOutput      map[int]*output.JSONOutput // Single-trie output per trie
	summaryTexts    map[int]string             // Pre-rendered summary text per trie
	clusterTexts    map[int]string             // Pre-rendered clustering text per trie
	cidrTexts       map[int]string             // Pre-rendered CIDR text per trie
	diagnosticTexts map[int]string             // Pre-rendered diagnostic text per trie

	// Visualization data
	trafficMatrixes map[int][256][256]uint32 // Traffic data per trie
	maxTraffics     map[int]uint32           // Max traffic per trie
	// Clustered-traffic grids per trie per cluster set. clusteredMatrixes[trie][set][a][b]
	// counts requests in /16 a.b whose full IP is inside a detected cluster
	// range of that (trie, set). Used for the traffic-capture overlay.
	clusteredMatrixes map[int]map[int][256][256]uint32

	// Ground-truth traffic over ALL parsed requests, identical for every trie.
	// Computed once, by the first precache that has request data.
	globalTraffic      [256][256]uint32
	globalMaxTraffic   uint32
	globalTrafficReady bool

	// Metadata
	lastUpdated time.Time
}

// NewTrieCache creates a new fast trie cache
func NewTrieCache() *TrieCache {
	return &TrieCache{
		trieOutput:        make(map[int]*output.JSONOutput),
		summaryTexts:      make(map[int]string),
		clusterTexts:      make(map[int]string),
		cidrTexts:         make(map[int]string),
		diagnosticTexts:   make(map[int]string),
		trafficMatrixes:   make(map[int][256][256]uint32),
		maxTraffics:       make(map[int]uint32),
		clusteredMatrixes: make(map[int]map[int][256][256]uint32),
	}
}

// PreCacheAllTries processes and caches all trie data upfront.
//
// Locking: every full request scan and every text render runs WITHOUT ftc.mu;
// the write lock is only taken to publish one finished trie at a time (map
// stores plus a matrix copy). The UI goroutine reads this cache under the read
// lock on every trie switch, so holding the write lock across the scans would
// freeze the TUI for the whole precache.
func (ftc *TrieCache) PreCacheAllTries(app *App, multiResult *output.JSONOutput, requests []ingestor.Request) {
	if multiResult == nil || len(multiResult.Tries) == 0 {
		return
	}

	// Process each trie and cache everything
	for trieIndex := 0; trieIndex < len(multiResult.Tries); trieIndex++ {
		ftc.precacheTrie(app, trieIndex, multiResult, requests)
	}

	ftc.mu.Lock()
	ftc.lastUpdated = time.Now()
	ftc.mu.Unlock()
}

// PreCacheSingleTrie caches a specific trie with priority
func (ftc *TrieCache) PreCacheSingleTrie(app *App, trieIndex int, multiResult *output.JSONOutput, requests []ingestor.Request) bool {
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
func (ftc *TrieCache) precacheTrie(app *App, trieIndex int, multiResult *output.JSONOutput, requests []ingestor.Request) bool {
	// 1. Convert to single-trie output
	trieOutput := app.singleTrieOutput(trieIndex)
	if trieOutput == nil {
		return false
	}

	// 2. Pre-render all text components
	summary := app.buildSummaryTextFor(trieOutput, trieIndex)
	clustering := app.buildClusteringTextFor(trieOutput)
	cidr := app.buildCidrAnalysisTextFor(trieOutput)
	diagnostics := app.buildDiagnosticsTextFor(trieOutput)

	// 3. Pre-process traffic data for visualization
	traffic, maxTraffic := ftc.globalTrafficData(requests)
	clustered := clusteredGrids(requests, multiResult.Tries[trieIndex])

	ftc.mu.Lock()
	defer ftc.mu.Unlock()

	ftc.trieOutput[trieIndex] = trieOutput
	ftc.summaryTexts[trieIndex] = summary
	ftc.clusterTexts[trieIndex] = clustering
	ftc.cidrTexts[trieIndex] = cidr
	ftc.diagnosticTexts[trieIndex] = diagnostics
	ftc.trafficMatrixes[trieIndex] = *traffic
	ftc.maxTraffics[trieIndex] = maxTraffic
	ftc.clusteredMatrixes[trieIndex] = clustered
	return true
}

// globalTrafficData returns the traffic matrix over ALL parsed requests and its
// busiest /16 bin. The matrix is ground truth - identical for every trie - so
// it is computed once and reused; only the clustered grids are trie-specific.
//
// The scan runs without ftc.mu. Two concurrent first callers may both scan;
// they compute the same matrix and the first to finish publishes it. An empty
// request slice (a precache that runs before the request data has arrived) is
// never published as the final matrix, so a later call with the real requests
// still computes it.
func (ftc *TrieCache) globalTrafficData(requests []ingestor.Request) (*[256][256]uint32, uint32) {
	ftc.mu.RLock()
	if ftc.globalTrafficReady {
		m, maxTraffic := ftc.globalTraffic, ftc.globalMaxTraffic
		ftc.mu.RUnlock()
		return &m, maxTraffic
	}
	ftc.mu.RUnlock()

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

	if len(requests) > 0 {
		ftc.mu.Lock()
		if !ftc.globalTrafficReady {
			ftc.globalTraffic = *m
			ftc.globalMaxTraffic = maxTraffic
			ftc.globalTrafficReady = true
		}
		ftc.mu.Unlock()
	}
	return m, maxTraffic
}

// clusteredGrids builds one clustered-traffic grid per cluster set of a trie in
// a single pass over the requests. It touches no cache state and takes no lock.
func clusteredGrids(requests []ingestor.Request, trieResult output.TrieResult) map[int][256][256]uint32 {
	// Pre-parse each cluster set's detected ranges once into sorted intervals so
	// membership is an allocation-free binary search in the hot loop. One
	// clustered grid is accumulated per cluster set in a single pass.
	intervalsPerSet := make([]*clusterIntervals, len(trieResult.Data))
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

	setGrids := make(map[int][256][256]uint32, len(clusteredPerSet))
	for s := range clusteredPerSet {
		setGrids[s] = *clusteredPerSet[s]
	}
	return setGrids
}

// GetClusteredData returns the cached clustered-traffic grid for a (trie,
// cluster set) pair, if present.
func (ftc *TrieCache) GetClusteredData(trieIndex, clusterSetIndex int) (grid [256][256]uint32, exists bool) {
	ftc.mu.RLock()
	defer ftc.mu.RUnlock()

	if setGrids, ok := ftc.clusteredMatrixes[trieIndex]; ok {
		grid, exists = setGrids[clusterSetIndex]
	}
	return grid, exists
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

// GetTrafficData returns cached traffic data for visualization
func (ftc *TrieCache) GetTrafficData(trieIndex int) (trafficMatrix [256][256]uint32, maxTraffic uint32, exists bool) {
	ftc.mu.RLock()
	defer ftc.mu.RUnlock()

	trafficMatrix, matrixExists := ftc.trafficMatrixes[trieIndex]
	maxTraffic, maxExists := ftc.maxTraffics[trieIndex]

	exists = matrixExists && maxExists
	return trafficMatrix, maxTraffic, exists
}
