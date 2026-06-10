package tui

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/ChristianF88/cidrx/ingestor"
	"github.com/ChristianF88/cidrx/output"
)

// FastTrieCache holds ALL trie data in RAM for instant switching
// This eliminates any conversion or processing delays during trie switching
type FastTrieCache struct {
	mu sync.RWMutex

	// Pre-computed data for instant access
	legacyData      map[int]*output.JSONOutput // Converted legacy format per trie
	summaryTexts    map[int]string             // Pre-rendered summary text per trie
	clusterTexts    map[int]string             // Pre-rendered clustering text per trie
	cidrTexts       map[int]string             // Pre-rendered CIDR text per trie
	diagnosticTexts map[int]string             // Pre-rendered diagnostic text per trie

	// Visualization data for instant switching
	trafficMatrixes map[int][256][256]uint32 // Traffic data per trie
	maxTraffics     map[int]uint32           // Max traffic per trie
	// Clustered-traffic grids per trie per cluster set. clusteredMatrixes[trie][set][a][b]
	// counts requests in /16 a.b whose full IP is inside a detected cluster
	// range of that (trie, set). Used for the traffic-capture overlay.
	clusteredMatrixes map[int]map[int][256][256]uint32
	vizRenderCache    map[int]map[int]string // Visualization render cache per trie per cluster set

	// Ground-truth traffic over ALL parsed requests, identical for every trie.
	// Computed once on the first preProcessTrafficData call.
	globalTraffic      [256][256]uint32
	globalMaxTraffic   uint32
	globalTrafficReady bool

	// Metadata
	totalTries    int
	cacheComplete bool
	lastUpdated   time.Time

	// Performance metrics (atomic for concurrent access under RLock)
	cacheHits   atomic.Int64
	cacheMisses atomic.Int64
}

// NewFastTrieCache creates a new fast trie cache
func NewFastTrieCache() *FastTrieCache {
	return &FastTrieCache{
		legacyData:        make(map[int]*output.JSONOutput),
		summaryTexts:      make(map[int]string),
		clusterTexts:      make(map[int]string),
		cidrTexts:         make(map[int]string),
		diagnosticTexts:   make(map[int]string),
		trafficMatrixes:   make(map[int][256][256]uint32),
		maxTraffics:       make(map[int]uint32),
		clusteredMatrixes: make(map[int]map[int][256][256]uint32),
		vizRenderCache:    make(map[int]map[int]string),
	}
}

// PreCacheAllTries processes and caches ALL trie data upfront for instant switching
func (ftc *FastTrieCache) PreCacheAllTries(app *App, multiResult *output.JSONOutput, requests []ingestor.Request) {
	if multiResult == nil || len(multiResult.Tries) == 0 {
		return
	}

	ftc.mu.Lock()
	defer ftc.mu.Unlock()

	ftc.totalTries = len(multiResult.Tries)
	ftc.cacheComplete = false

	// Process each trie and cache everything
	for trieIndex := 0; trieIndex < len(multiResult.Tries); trieIndex++ {
		// 1. Convert to legacy format and cache
		legacyData := app.convertTrieToLegacy(trieIndex)
		if legacyData != nil {
			ftc.legacyData[trieIndex] = legacyData

			// 2. Pre-render all text components
			ftc.preRenderTrieTexts(trieIndex, legacyData, app)

			// 3. Pre-process traffic data for visualization
			ftc.preProcessTrafficData(trieIndex, requests, multiResult.Tries[trieIndex])

			// 4. Pre-render visualization for all cluster sets (disabled for now to avoid nil pointer issues)
			// ftc.preRenderVisualization(trieIndex, legacyData, app)
		}
	}

	ftc.cacheComplete = true
	ftc.lastUpdated = time.Now()
}

// PreCacheSingleTrie caches a specific trie with priority
func (ftc *FastTrieCache) PreCacheSingleTrie(app *App, trieIndex int, multiResult *output.JSONOutput, requests []ingestor.Request) bool {
	if multiResult == nil || trieIndex >= len(multiResult.Tries) {
		return false
	}

	ftc.mu.Lock()
	defer ftc.mu.Unlock()

	// Convert to legacy format and cache
	legacyData := app.convertTrieToLegacy(trieIndex)
	if legacyData != nil {
		ftc.legacyData[trieIndex] = legacyData

		// Pre-render all text components
		ftc.preRenderTrieTexts(trieIndex, legacyData, app)

		// Pre-process traffic data for visualization
		ftc.preProcessTrafficData(trieIndex, requests, multiResult.Tries[trieIndex])

		return true
	}
	return false
}

// preRenderTrieTexts pre-renders all text components for a trie.
// Must hold ftc.mu (write lock) on entry. Acquires app.mu to safely
// swap jsonResult/currentTrie during rendering.
func (ftc *FastTrieCache) preRenderTrieTexts(trieIndex int, legacyData *output.JSONOutput, app *App) {
	app.mu.Lock()
	originalResult := app.jsonResult
	originalTrieIndex := app.currentTrie
	app.jsonResult = legacyData
	app.currentTrie = trieIndex

	// Pre-render all text components while holding the lock
	ftc.summaryTexts[trieIndex] = app.buildSummaryText()
	ftc.clusterTexts[trieIndex] = app.buildClusteringText()
	ftc.cidrTexts[trieIndex] = app.buildCidrAnalysisText()
	ftc.diagnosticTexts[trieIndex] = app.buildDiagnosticsText()

	// Restore original state
	app.jsonResult = originalResult
	app.currentTrie = originalTrieIndex
	app.mu.Unlock()
}

// preProcessTrafficData pre-processes traffic data for visualization.
// The traffic matrix is ground truth over ALL parsed requests — identical for
// every trie — so it is computed once and reused. Only the clustered grids are
// trie-specific (they depend on the trie's detected cluster ranges).
func (ftc *FastTrieCache) preProcessTrafficData(trieIndex int, requests []ingestor.Request, trieResult output.TrieResult) {
	if !ftc.globalTrafficReady {
		var m [256][256]uint32
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
		ftc.globalTraffic = m
		ftc.globalMaxTraffic = maxTraffic
		ftc.globalTrafficReady = true
	}
	ftc.trafficMatrixes[trieIndex] = ftc.globalTraffic
	ftc.maxTraffics[trieIndex] = ftc.globalMaxTraffic

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
	ftc.clusteredMatrixes[trieIndex] = setGrids
}

// GetClusteredData returns the cached clustered-traffic grid for a (trie,
// cluster set) pair, if present.
func (ftc *FastTrieCache) GetClusteredData(trieIndex, clusterSetIndex int) (grid [256][256]uint32, exists bool) {
	ftc.mu.RLock()
	defer ftc.mu.RUnlock()

	if setGrids, ok := ftc.clusteredMatrixes[trieIndex]; ok {
		grid, exists = setGrids[clusterSetIndex]
	}
	return grid, exists
}

// GetLegacyData returns cached legacy data for instant access
func (ftc *FastTrieCache) GetLegacyData(trieIndex int) (*output.JSONOutput, bool) {
	ftc.mu.RLock()
	defer ftc.mu.RUnlock()

	data, exists := ftc.legacyData[trieIndex]
	if exists {
		ftc.cacheHits.Add(1)
	} else {
		ftc.cacheMisses.Add(1)
	}
	return data, exists
}

// GetPreRenderedTexts returns all pre-rendered texts for instant display
func (ftc *FastTrieCache) GetPreRenderedTexts(trieIndex int) (summary, clustering, cidr, diagnostics string, exists bool) {
	ftc.mu.RLock()
	defer ftc.mu.RUnlock()

	summary, summaryExists := ftc.summaryTexts[trieIndex]
	clustering, clusteringExists := ftc.clusterTexts[trieIndex]
	cidr, cidrExists := ftc.cidrTexts[trieIndex]
	diagnostics, diagnosticsExists := ftc.diagnosticTexts[trieIndex]

	exists = summaryExists && clusteringExists && cidrExists && diagnosticsExists
	if exists {
		ftc.cacheHits.Add(1)
	} else {
		ftc.cacheMisses.Add(1)
	}

	return summary, clustering, cidr, diagnostics, exists
}

// GetTrafficData returns cached traffic data for instant visualization
func (ftc *FastTrieCache) GetTrafficData(trieIndex int) (trafficMatrix [256][256]uint32, maxTraffic uint32, exists bool) {
	ftc.mu.RLock()
	defer ftc.mu.RUnlock()

	trafficMatrix, matrixExists := ftc.trafficMatrixes[trieIndex]
	maxTraffic, maxExists := ftc.maxTraffics[trieIndex]

	exists = matrixExists && maxExists
	if exists {
		ftc.cacheHits.Add(1)
	} else {
		ftc.cacheMisses.Add(1)
	}

	return trafficMatrix, maxTraffic, exists
}

// GetVisualizationRender returns pre-rendered visualization text
func (ftc *FastTrieCache) GetVisualizationRender(trieIndex, clusterSetIndex int) (string, bool) {
	ftc.mu.RLock()
	defer ftc.mu.RUnlock()

	if trieCache, trieExists := ftc.vizRenderCache[trieIndex]; trieExists {
		if renderText, renderExists := trieCache[clusterSetIndex]; renderExists {
			ftc.cacheHits.Add(1)
			return renderText, true
		}
	}

	ftc.cacheMisses.Add(1)
	return "", false
}

// IsCacheComplete returns true if all tries have been cached
func (ftc *FastTrieCache) IsCacheComplete() bool {
	ftc.mu.RLock()
	defer ftc.mu.RUnlock()
	return ftc.cacheComplete
}

// GetCacheStats returns cache performance statistics
func (ftc *FastTrieCache) GetCacheStats() (totalTries int, cacheComplete bool, hits, misses int64, hitRatio float64) {
	ftc.mu.RLock()
	defer ftc.mu.RUnlock()

	totalTries = ftc.totalTries
	cacheComplete = ftc.cacheComplete
	hits = ftc.cacheHits.Load()
	misses = ftc.cacheMisses.Load()

	if hits+misses > 0 {
		hitRatio = float64(hits) / float64(hits+misses) * 100
	}

	return
}

// Clear clears all cached data
func (ftc *FastTrieCache) Clear() {
	ftc.mu.Lock()
	defer ftc.mu.Unlock()

	ftc.legacyData = make(map[int]*output.JSONOutput)
	ftc.summaryTexts = make(map[int]string)
	ftc.clusterTexts = make(map[int]string)
	ftc.cidrTexts = make(map[int]string)
	ftc.diagnosticTexts = make(map[int]string)
	ftc.trafficMatrixes = make(map[int][256][256]uint32)
	ftc.maxTraffics = make(map[int]uint32)
	ftc.clusteredMatrixes = make(map[int]map[int][256][256]uint32)
	ftc.vizRenderCache = make(map[int]map[int]string)
	ftc.globalTraffic = [256][256]uint32{}
	ftc.globalMaxTraffic = 0
	ftc.globalTrafficReady = false

	ftc.totalTries = 0
	ftc.cacheComplete = false
	ftc.cacheHits.Store(0)
	ftc.cacheMisses.Store(0)
}
