package tui

import (
	"fmt"
	"math"
	"strings"

	"github.com/ChristianF88/cidrx/ingestor"
	"github.com/ChristianF88/cidrx/output"
	"github.com/rivo/tview"
)

// VisualizationView represents the 2D heatmap visualization
type VisualizationView struct {
	app               *App
	view              *tview.TextView
	trafficData       [256][256]uint32
	clusteredData     [256][256]uint32 // Per-/16 count of requests inside detected cluster ranges (current set)
	maxTraffic        uint32
	requests          []ingestor.Request
	currentClusterSet int
	totalClusterSets  int
	blockScale        int // /16 bins per display-cell side (0 → default 8)
	scaleMode         int // brightness mapping: scaleLinear, scaleSqrt or scaleLog

	// Legacy caching for performance (kept for compatibility)
	cachedTrafficData map[int][256][256]uint32 // Cache traffic data per trie
	cachedMaxTraffic  map[int]uint32           // Cache max traffic per trie
	cachedRenderText  map[int]string           // Cache rendered visualization text per trie

	// Cache of clustered-traffic grids keyed by trieIndex*1000+clusterSet.
	// trafficData is per-trie (same across cluster sets); clusteredData differs
	// per cluster set because it depends on that set's detected ranges.
	cachedClusteredData map[int][256][256]uint32
}

// NewVisualizationView creates a new visualization view
func (a *App) NewVisualizationView() *VisualizationView {
	var totalClusterSets int
	if a.cfg != nil && a.jsonResult != nil {
		// Config mode - use legacy format (jsonResult has the current trie data)
		totalClusterSets = len(a.jsonResult.Clustering.Data)
	} else {
		// Legacy mode
		totalClusterSets = len(a.jsonResult.Clustering.Data)
	}

	v := &VisualizationView{
		app:               a,
		currentClusterSet: 0,
		totalClusterSets:  totalClusterSets,
		// Initialize legacy cache maps
		cachedTrafficData:   make(map[int][256][256]uint32),
		cachedMaxTraffic:    make(map[int]uint32),
		cachedRenderText:    make(map[int]string),
		cachedClusteredData: make(map[int][256][256]uint32),
	}

	v.view = tview.NewTextView().
		SetDynamicColors(true).
		SetScrollable(true).
		SetWrap(false)
	v.view.SetBorder(true).SetTitle(" 2D Traffic Visualization (/16 bins, 32×32 grid) ").SetTitleAlign(tview.AlignCenter)

	return v
}

// PreCacheAllTries processes and caches traffic data for all tries to eliminate switching delays (legacy)
func (v *VisualizationView) PreCacheAllTries(requests []ingestor.Request) {
	if v.app.cfg == nil || v.app.multiTrieResult == nil {
		// Legacy mode - cache single trie
		v.ProcessTrafficData(requests)
		v.cachedTrafficData[0] = v.trafficData
		v.cachedMaxTraffic[0] = v.maxTraffic

		// Pre-cache render text for all cluster sets
		for i := 0; i < v.totalClusterSets; i++ {
			v.currentClusterSet = i
			renderText := v.generateRenderText()
			v.cachedRenderText[v.renderCacheKey(0, i)] = renderText
		}
		v.currentClusterSet = 0 // Reset to first
		return
	}

	// Multi-trie mode - cache traffic data for each trie
	originalTrie := v.app.currentTrie
	originalRequests := v.requests
	v.requests = requests

	for trieIndex := 0; trieIndex < len(v.app.multiTrieResult.Tries); trieIndex++ {
		// Temporarily switch to this trie for processing
		v.app.currentTrie = trieIndex

		// Update to this trie's data
		v.app.jsonResult = v.app.convertTrieToLegacy(trieIndex)
		v.totalClusterSets = len(v.app.jsonResult.Clustering.Data)

		// Process traffic data for this trie
		v.ProcessTrafficData(requests)

		// Cache the traffic data
		v.cachedTrafficData[trieIndex] = v.trafficData
		v.cachedMaxTraffic[trieIndex] = v.maxTraffic

		// Pre-cache render text for all cluster sets in this trie
		for clusterSet := 0; clusterSet < v.totalClusterSets; clusterSet++ {
			v.currentClusterSet = clusterSet
			cacheKey := v.renderCacheKey(trieIndex, clusterSet)
			renderText := v.generateRenderText()
			v.cachedRenderText[cacheKey] = renderText
		}
	}

	// Restore original state
	v.app.currentTrie = originalTrie
	v.app.jsonResult = v.app.convertTrieToLegacy(originalTrie)
	v.totalClusterSets = len(v.app.jsonResult.Clustering.Data)
	v.currentClusterSet = 0
	v.requests = originalRequests

	// Load the original trie's cached data
	if cachedData, exists := v.cachedTrafficData[originalTrie]; exists {
		v.trafficData = cachedData
		v.maxTraffic = v.cachedMaxTraffic[originalTrie]
	}
}

// getCurrentClusterSet returns the current cluster set based on mode
func (v *VisualizationView) getCurrentClusterSet() *output.ClusterResult {
	// Ensure app and jsonResult exist
	if v.app == nil || v.app.jsonResult == nil {
		return nil
	}

	// Update totalClusterSets from current data
	actualClusterSets := len(v.app.jsonResult.Clustering.Data)
	if actualClusterSets == 0 {
		return nil
	}

	// Fix totalClusterSets if it's wrong
	if v.totalClusterSets != actualClusterSets {
		v.totalClusterSets = actualClusterSets
	}

	// Bounds check and fix currentClusterSet if it's out of range
	if v.currentClusterSet >= actualClusterSets {
		v.currentClusterSet = 0 // Reset to first cluster set
	}

	// Always use jsonResult.Clustering.Data since we convert multi-trie to legacy format
	return &v.app.jsonResult.Clustering.Data[v.currentClusterSet]
}

// updateForCurrentTrie updates the visualization for the current trie
func (v *VisualizationView) updateForCurrentTrie() {
	// Update cluster set count from current jsonResult (legacy format)
	if v.app.jsonResult != nil {
		v.totalClusterSets = len(v.app.jsonResult.Clustering.Data)
		v.currentClusterSet = 0 // Reset to first cluster set

		// Use cached traffic data if available
		if v.app.cfg != nil && len(v.requests) > 0 {
			v.updateTrafficDataCached()
		} else if len(v.requests) > 0 {
			// Legacy mode - no caching
			v.ProcessTrafficData(v.requests)
		}

		v.RenderCached()
	}
}

// updateMetadataOnly updates only the cluster set metadata without re-processing traffic
func (v *VisualizationView) updateMetadataOnly() {
	// Only update cluster set count, don't re-process traffic data
	if v.app.jsonResult != nil {
		v.totalClusterSets = len(v.app.jsonResult.Clustering.Data)
		v.currentClusterSet = 0 // Reset to first cluster set
		// Don't call ProcessTrafficData or Render - too expensive
	}
}

// updateTrafficDataCached loads traffic data from cache or processes it
func (v *VisualizationView) updateTrafficDataCached() {
	currentTrie := v.app.currentTrie

	// Check if we have cached traffic data for this trie
	if cachedData, exists := v.cachedTrafficData[currentTrie]; exists {
		// Load from cache
		v.trafficData = cachedData
		v.maxTraffic = v.cachedMaxTraffic[currentTrie]
	} else {
		// Process and cache traffic data
		v.ProcessTrafficData(v.requests)

		// Cache the results
		v.cachedTrafficData[currentTrie] = v.trafficData
		v.cachedMaxTraffic[currentTrie] = v.maxTraffic
	}
}

// ProcessTrafficData processes the requests and builds the traffic heatmap and
// the clustered-traffic overlay grid for the current cluster set in a single
// pass. trafficData[a][b] counts all requests in /16 a.b; clusteredData[a][b]
// counts only those whose full IP falls inside a detected cluster range of the
// current set. The overlay dot then encodes clustered/total per cell.
func (v *VisualizationView) ProcessTrafficData(requests []ingestor.Request) {
	v.requests = requests
	v.maxTraffic = 0

	// Reset both grids.
	for i := range v.trafficData {
		v.trafficData[i] = [256]uint32{}
		v.clusteredData[i] = [256]uint32{}
	}

	// Pre-parse the current cluster set's ranges once into sorted intervals so
	// membership is an allocation-free binary search in the hot loop.
	intervals := buildClusterIntervals(v.getCurrentClusterSet())

	// Count traffic by /16 ranges (first.second octets) over ALL parsed
	// requests — the matrix is ground truth and identical across tries; only
	// the clustered overlay differs per (trie, cluster set). Clustered traffic
	// uses the full 32-bit IP membership test.
	for i := range requests {
		req := &requests[i]
		ip := req.IPUint32
		if ip == 0 {
			continue
		}
		a := byte(ip >> 24)
		b := byte(ip >> 16)
		v.trafficData[a][b]++
		if v.trafficData[a][b] > v.maxTraffic {
			v.maxTraffic = v.trafficData[a][b]
		}
		if intervals.Contains(ip) {
			v.clusteredData[a][b]++
		}
	}
}

// renderCacheKey returns the render-text cache key for a (trie, cluster set)
// pair under the current brightness mode. Renders differ per mode, so each
// scale mode is offset into its own key space.
func (v *VisualizationView) renderCacheKey(trie, set int) int {
	return trie*1000 + set + v.scaleMode*1_000_000
}

// clusteredCacheKey returns the composite cache key for the clustered grid of
// the current (trie, cluster set) pair. Matches the trie*1000+set scheme used
// for render-text caching.
func (v *VisualizationView) clusteredCacheKey() int {
	trie := 0
	if v.app != nil {
		trie = v.app.currentTrie
	}
	return trie*1000 + v.currentClusterSet
}

// ensureClusteredData makes v.clusteredData reflect the current (trie, cluster
// set). It reuses the cached per-(trie,set) clustered grid when available;
// otherwise it does a single clustered-only pass over the (already filtered)
// requests and caches the result. trafficData is NOT recomputed here — it is
// the same for a trie across all cluster sets.
func (v *VisualizationView) ensureClusteredData() {
	key := v.clusteredCacheKey()
	if v.cachedClusteredData != nil {
		if cached, ok := v.cachedClusteredData[key]; ok {
			v.clusteredData = cached
			return
		}
	}

	// Reset and rebuild clustered grid for the current cluster set.
	for i := range v.clusteredData {
		v.clusteredData[i] = [256]uint32{}
	}

	intervals := buildClusterIntervals(v.getCurrentClusterSet())
	if !intervals.empty() {
		for i := range v.requests {
			ip := v.requests[i].IPUint32
			if ip == 0 {
				continue
			}
			if intervals.Contains(ip) {
				v.clusteredData[byte(ip>>24)][byte(ip>>16)]++
			}
		}
	}

	if v.cachedClusteredData != nil {
		v.cachedClusteredData[key] = v.clusteredData
	}
}

// RenderCached generates the 2D visualization using optimized cache when possible
func (v *VisualizationView) RenderCached() {
	// Use legacy caching
	if v.app.cfg != nil {
		currentTrie := v.app.currentTrie
		cacheKey := v.renderCacheKey(currentTrie, v.currentClusterSet)

		if cachedText, exists := v.cachedRenderText[cacheKey]; exists {
			// Use cached render text
			v.view.SetText(cachedText)
			return
		}

		// Generate and cache the render text
		renderText := v.generateRenderText()
		v.cachedRenderText[cacheKey] = renderText
		v.view.SetText(renderText)
	} else {
		// Legacy mode - no caching
		v.Render()
	}
}

// Render generates the 2D visualization
func (v *VisualizationView) Render() {
	renderText := v.generateRenderText()
	v.view.SetText(renderText)
}

// generateRenderText creates the render text (for caching)
func (v *VisualizationView) generateRenderText() string {
	var content strings.Builder

	// The matrix always shows ALL parsed traffic (ground truth, identical
	// across tries); only the cluster overlay is trie/set-specific.
	trafficScope := "All Traffic"

	if v.totalClusterSets > 0 && v.currentClusterSet < v.totalClusterSets {
		cluster := v.getCurrentClusterSet()
		if cluster != nil {
			content.WriteString(fmt.Sprintf("[white::b]Traffic Heatmap (/16 ranges) - Cluster Set %d/%d - %s[white::-]\n",
				v.currentClusterSet+1, v.totalClusterSets, trafficScope))
			content.WriteString(fmt.Sprintf("[dim]Parameters: min_size=%d, depth=%d-%d, mean_diff=%.1f[white]\n",
				cluster.Parameters.MinClusterSize,
				cluster.Parameters.MinDepth,
				cluster.Parameters.MaxDepth,
				cluster.Parameters.MeanSubnetDifference))
		}
	} else if v.totalClusterSets > 0 {
		content.WriteString(fmt.Sprintf("[white::b]Traffic Heatmap (/16 ranges) - %d cluster sets available - %s[white::-]\n",
			v.totalClusterSets, trafficScope))
	} else {
		content.WriteString(fmt.Sprintf("[white::b]Traffic Heatmap (/16 ranges) - No cluster sets - %s[white::-]\n", trafficScope))
	}

	scale := v.effectiveScale()
	grid := 256 / scale
	content.WriteString(fmt.Sprintf("[dim]Grid: %d×%d cells - 1 cell = %d×%d /16 bins[white]\n", grid, grid, scale, scale))
	content.WriteString(fmt.Sprintf("[dim]Legend: cell brightness = requests in cell (%s, 100%% = busiest cell) | [red]Red dot[white] = share of cell's requests inside detected cluster ranges[white]\n", v.scaleName()))
	content.WriteString("[dim]Navigate: ←→ change cluster set, 'l' linear/sqrt/log scale, ↑↓ scroll, 'r' results, 'q' quit[white]\n\n")

	if v.maxTraffic == 0 {
		content.WriteString("[yellow]Loading traffic data...[white]\n")
		content.WriteString("[dim]Traffic data will appear once analysis is complete.[white]\n")
	} else {
		// Ensure the clustered-traffic overlay grid matches the current
		// (trie, cluster set) before rendering the heatmap.
		v.ensureClusteredData()
		v.renderHeatmap(&content)
	}

	return content.String()
}

// renderHeatmap creates the ASCII-based heatmap. Cell brightness encodes the
// cell's TOTAL requests (sum of its scale×scale /16 bins), normalized against
// the busiest cell on the map (= 100% = white); the red dot encodes the share
// of the cell's requests inside detected cluster ranges.
func (v *VisualizationView) renderHeatmap(content *strings.Builder) {
	// Each display cell aggregates a scale×scale block of /16 bins. scale=8
	// keeps the 32×32 grid compact enough to avoid scrolling.
	scale := v.effectiveScale()

	// First pass: the busiest cell total is the 100% brightness reference.
	var maxCellTraffic uint32
	for a := 0; a < 256; a += scale {
		for b := 0; b < 256; b += scale {
			if cellTraffic, _ := blockStats(&v.trafficData, &v.clusteredData, a, b, scale); cellTraffic > maxCellTraffic {
				maxCellTraffic = cellTraffic
			}
		}
	}

	// Simple scale line for A axis (first octet) - now on x-axis, 1.5x wider
	content.WriteString("    1") // Start at 1
	totalCols := 256 / scale
	scaleLineLength := totalCols*3 - 4 // Account for triple-width cells (3 chars each) minus space for numbers
	for i := 0; i < scaleLineLength; i++ {
		content.WriteString("─")
	}
	content.WriteString("256 A\n")

	// Render rows (B axis) with simple row numbering - now on y-axis, reversed for bottom-left origin
	totalRows := 256 / scale
	for rowIndex := 0; rowIndex < totalRows; rowIndex++ {
		// Calculate actual B value (reverse order: start from top = 256, go down to 1)
		b := 256 - scale - (rowIndex * scale)

		// Row labels for y-axis
		if rowIndex == 0 {
			content.WriteString("256│")
		} else if rowIndex == totalRows-1 {
			content.WriteString("1 │ ")
		} else {
			content.WriteString("  │ ")
		}

		for a := 0; a < 256; a += scale {
			// Sum the cell's traffic and clustered requests.
			cellTraffic, cellClustered := blockStats(&v.trafficData, &v.clusteredData, a, b, scale)

			// Overlay dot encodes the share of THIS cell's requests that fall
			// inside detected cluster ranges (traffic-capture ratio), not
			// address-space geometry. Bright cell + strong dot = traffic is
			// flagged; bright cell + no dot = traffic NOT captured.
			dotChar := getRatioMarker(ratioOf(cellClustered, cellTraffic))

			if cellTraffic == 0 {
				// Black for no traffic - use triple width (3 characters)
				content.WriteString("[black]███[white]")
			} else {
				// Intensity of the cell total relative to the busiest cell,
				// mapped linearly or logarithmically per the current mode.
				intensity := v.intensityOf(cellTraffic, maxCellTraffic)
				color, char := v.getTrafficColorAndChar(intensity)

				if dotChar != "" {
					// Red dot overlaid on traffic color, preserving background
					content.WriteString(fmt.Sprintf("[%s]%s[red]%s[%s]%s[white]", color, char, dotChar, color, char))
				} else {
					// Normal traffic color
					content.WriteString(fmt.Sprintf("[%s]%s%s%s[white]", color, char, char, char))
				}
			}
		}

		// Right side labels
		if rowIndex == 0 {
			content.WriteString("│256\n")
		} else if rowIndex == totalRows-1 {
			content.WriteString(" │1\n")
		} else {
			content.WriteString(" │\n")
		}
	}

	// Add axis label
	content.WriteString("B\n")

	// Footer with color legend. In linear mode the 10% steps speak for
	// themselves; in the nonlinear modes percentages would mislead, so each
	// grey step is labelled with the request count it starts at (inverse map).
	rampColors := [...]string{"black", "#202020", "#303030", "#404040", "#505050", "#606060", "#808080", "#A0A0A0", "#C0C0C0", "#E0E0E0", "white"}
	if v.scaleMode != scaleLinear {
		content.WriteString(fmt.Sprintf("\n[dim]Traffic Intensity (%s, step label = requests per cell at lower bound):[white]\n", v.scaleName()))
		for i, color := range rampColors {
			if i == 0 {
				content.WriteString("[black]███[white]=0 ")
			} else {
				content.WriteString(fmt.Sprintf("[%s]███[white]≥%s ", color, output.FormatNumber(int(v.intensityThresholdCount(float64(i-1)/10, maxCellTraffic)))))
			}
			if i == 4 {
				content.WriteString("\n")
			}
		}
		content.WriteString(fmt.Sprintf("(max %s)\n", output.FormatNumber(int(maxCellTraffic))))
	} else {
		content.WriteString("\n[dim]Traffic Intensity (linear, 100% = busiest cell):[white]\n")
		for i, color := range rampColors {
			if i == 0 {
				content.WriteString("[black]███[white]=0% ")
			} else {
				content.WriteString(fmt.Sprintf("[%s]███[white]=%d-%d%% ", color, (i-1)*10, i*10))
			}
			if i == 4 {
				content.WriteString("\n")
			}
		}
		content.WriteString("\n")
	}
	content.WriteString("\n[dim]Axes: A=First octet (horizontal), B=Second octet (vertical)[white]\n")
	content.WriteString("[dim]Overlay dot = share of cell's requests captured by clusters: [red]●[white]≥80%, [red]•[white]≥20%, [red]·[white]>0%, none=0%[white]\n")

	// Show current cluster set ranges
	if v.totalClusterSets > 0 && v.currentClusterSet < v.totalClusterSets {
		clusterSet := v.getCurrentClusterSet()
		if clusterSet != nil && len(clusterSet.MergedRanges) > 0 {
			content.WriteString(fmt.Sprintf("\n[yellow]Cluster Set %d Detected Ranges:[white]\n", v.currentClusterSet+1))

			// Calculate total for this cluster set
			var totalRequests uint32
			for _, cidr := range clusterSet.MergedRanges {
				totalRequests += cidr.Requests
			}

			// Get unique IPs count depending on mode
			var uniqueIPs int
			if v.app.cfg != nil && len(v.app.jsonResult.Tries) > 0 && v.app.currentTrie < len(v.app.jsonResult.Tries) {
				// Multi-trie mode - use current trie's unique IPs
				uniqueIPs = v.app.jsonResult.Tries[v.app.currentTrie].Stats.UniqueIPs
			} else {
				// Legacy mode
				uniqueIPs = v.app.jsonResult.General.UniqueIPs
			}

			var totalPercentage float64
			if uniqueIPs > 0 {
				totalPercentage = float64(totalRequests) / float64(uniqueIPs) * 100
			}

			for _, cidr := range clusterSet.MergedRanges {
				content.WriteString(fmt.Sprintf("  • [red]%s[white]: %s requests (%.2f%%)\n",
					cidr.CIDR, output.FormatNumber(int(cidr.Requests)), cidr.Percentage))
			}
			content.WriteString(fmt.Sprintf("[yellow]Total: %s requests (%.2f%%)[white]\n",
				output.FormatNumber(int(totalRequests)), totalPercentage))
		} else {
			content.WriteString(fmt.Sprintf("\n[dim]Cluster Set %d: No ranges detected[white]\n", v.currentClusterSet+1))
		}
	}
}

// blockStats sums traffic and clustered requests over the scale x scale block
// of /16 bins starting at (aStart, bStart) — the totals of one display cell.
// Pointer params avoid copying the 256x256 arrays.
func blockStats(traffic, clustered *[256][256]uint32, aStart, bStart, scale int) (cellTraffic, cellClustered uint32) {
	for aa := aStart; aa < aStart+scale && aa < 256; aa++ {
		for bb := bStart; bb < bStart+scale && bb < 256; bb++ {
			cellTraffic += traffic[aa][bb]
			cellClustered += clustered[aa][bb]
		}
	}
	return cellTraffic, cellClustered
}

// effectiveScale returns the /16-bins-per-cell-side used for rendering.
func (v *VisualizationView) effectiveScale() int {
	if v.blockScale > 0 {
		return v.blockScale
	}
	return 8
}

// Brightness mappings, cycled by the 'l' key. Sqrt sits between linear (small
// cells crushed to black) and log (small cells inflated): perceptual middle
// ground, endpoints exact in all three modes (0 → black, busiest cell → white).
const (
	scaleLinear = iota
	scaleSqrt
	scaleLog
	scaleModeCount
)

// scaleName names the current brightness mapping for legend text.
func (v *VisualizationView) scaleName() string {
	switch v.scaleMode {
	case scaleSqrt:
		return "sqrt scale"
	case scaleLog:
		return "log scale"
	default:
		return "linear"
	}
}

// intensityOf maps a display cell's request total to [0,1] relative to the
// busiest cell on the map. Linear: x/max. Sqrt: sqrt(x/max) — power scale,
// middle ground between linear and log. Log: log1p(x)/log1p(max). All modes
// keep the endpoints (0 → 0, max → 1) and only redistribute the middle.
func (v *VisualizationView) intensityOf(traffic, maxCellTraffic uint32) float64 {
	if maxCellTraffic == 0 {
		return 0
	}
	switch v.scaleMode {
	case scaleSqrt:
		return math.Sqrt(float64(traffic) / float64(maxCellTraffic))
	case scaleLog:
		return math.Log1p(float64(traffic)) / math.Log1p(float64(maxCellTraffic))
	default:
		return float64(traffic) / float64(maxCellTraffic)
	}
}

// intensityThresholdCount inverts the current intensity map: the request count
// at which a cell reaches intensity t. Used for legend labels in the nonlinear
// modes (where percentage labels would mislead).
func (v *VisualizationView) intensityThresholdCount(t float64, maxCellTraffic uint32) uint32 {
	switch v.scaleMode {
	case scaleSqrt:
		return uint32(math.Ceil(t * t * float64(maxCellTraffic)))
	case scaleLog:
		return uint32(math.Ceil(math.Expm1(t * math.Log1p(float64(maxCellTraffic)))))
	default:
		return uint32(math.Ceil(t * float64(maxCellTraffic)))
	}
}

// ToggleIntensityScale cycles the brightness mapping linear → sqrt → log and
// re-renders. Each mode keeps its own render-text cache entries, so cycling
// is served from cache after the first render of each mode.
func (v *VisualizationView) ToggleIntensityScale() {
	v.scaleMode = (v.scaleMode + 1) % scaleModeCount
	v.RenderCached()
	v.app.updateStatusBar()
}

// ratioOf returns clustered/total in [0,1], guarding divide-by-zero.
func ratioOf(clustered, total uint32) float64 {
	if total == 0 {
		return 0
	}
	return float64(clustered) / float64(total)
}

// getRatioMarker maps a traffic-capture ratio (share of a cell's requests that
// fall inside detected cluster ranges) to an overlay dot character. Returns the
// bare dot rune (no surrounding spaces) or "" for ratio == 0.
func getRatioMarker(ratio float64) string {
	switch {
	case ratio >= 0.8:
		return "●" // most of the cell's traffic is flagged
	case ratio >= 0.2:
		return "•" // a meaningful share is flagged
	case ratio > 0.0:
		return "·" // a small share is flagged
	default:
		return "" // none of the cell's traffic is flagged
	}
}

// getTrafficColorAndChar returns color and character for traffic intensity
// 10-level progression with 10% resolution: 0%, 10%, 20%, ..., 90%, 100%
func (v *VisualizationView) getTrafficColorAndChar(intensity float64) (string, string) {
	switch {
	case intensity >= 0.9:
		return "white", "█" // 90-100%: white
	case intensity >= 0.8:
		return "#E0E0E0", "█" // 80-90%: very light grey
	case intensity >= 0.7:
		return "#C0C0C0", "█" // 70-80%: light grey
	case intensity >= 0.6:
		return "#A0A0A0", "█" // 60-70%: medium-light grey
	case intensity >= 0.5:
		return "#808080", "█" // 50-60%: medium grey
	case intensity >= 0.4:
		return "#606060", "█" // 40-50%: medium-dark grey
	case intensity >= 0.3:
		return "#505050", "█" // 30-40%: dark grey
	case intensity >= 0.2:
		return "#404040", "█" // 20-30%: darker grey
	case intensity >= 0.1:
		return "#303030", "█" // 10-20%: very dark grey
	case intensity > 0:
		return "#202020", "█" // 0-10%: almost black
	default:
		return "black", "█" // 0%: black
	}
}

// NextClusterSet moves to the next cluster set
func (v *VisualizationView) NextClusterSet() {
	if v.totalClusterSets > 0 {
		v.currentClusterSet = (v.currentClusterSet + 1) % v.totalClusterSets
		v.RenderCached()
		// Update status bar to reflect new cluster set
		v.app.updateStatusBar()
	}
}

// PrevClusterSet moves to the previous cluster set
func (v *VisualizationView) PrevClusterSet() {
	if v.totalClusterSets > 0 {
		v.currentClusterSet = (v.currentClusterSet - 1 + v.totalClusterSets) % v.totalClusterSets
		v.RenderCached()
		// Update status bar to reflect new cluster set
		v.app.updateStatusBar()
	}
}

// GetView returns the tview component
func (v *VisualizationView) GetView() *tview.TextView {
	return v.view
}
