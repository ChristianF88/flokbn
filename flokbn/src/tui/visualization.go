package tui

import (
	"fmt"
	"math"
	"strings"

	"github.com/ChristianF88/flokbn/output"
	"github.com/rivo/tview"
)

// renderKey identifies a cached render text: (trie, cluster set, scale mode).
type renderKey struct{ trie, set, mode int }

// VisualizationView represents the 2D heatmap visualization.
//
// The view holds no traffic data of its own: every render reads the grids from
// the App's TrieCache, which the request precache fills in the background. It
// is created with the App and only ever touched on the tview UI goroutine.
type VisualizationView struct {
	app               *App
	view              *tview.TextView
	currentClusterSet int
	totalClusterSets  int
	blockScale        int // /16 bins per display-cell side (0 → default 8)
	scaleMode         int // brightness mapping: scaleLinear, scaleSqrt or scaleLog

	// Rendered heatmap text per (trie, cluster set, scale mode). Only finished
	// heatmaps are stored, never the loading placeholder.
	cachedRenderText map[renderKey]string

	// loading is true while the last generated text is the "Loading traffic
	// data" placeholder, i.e. the cache did not yet hold the grids of the
	// current (trie, cluster set).
	loading bool
}

// NewVisualizationView creates the visualization view. The cluster-set count is
// seeded from a.jsonResult when results are already displayed; otherwise
// updateForCurrentTrie sets it once they are.
func (a *App) NewVisualizationView() *VisualizationView {
	v := &VisualizationView{
		app:              a,
		cachedRenderText: make(map[renderKey]string),
	}
	if a.jsonResult != nil {
		v.totalClusterSets = len(a.jsonResult.Clustering.Data)
	}

	v.view = tview.NewTextView().
		SetDynamicColors(true).
		SetScrollable(true).
		SetWrap(false)
	v.view.SetBorder(true).SetTitle(" 2D Traffic Visualization (/16 bins, 32×32 grid) ").SetTitleAlign(tview.AlignCenter)

	return v
}

// getCurrentClusterSet returns the current cluster set of the App's current
// trie (the UI-owned jsonResult), or nil when there is none.
func (v *VisualizationView) getCurrentClusterSet() *output.ClusterResult {
	// Ensure app and the active result exist.
	if v.app == nil || v.app.jsonResult == nil {
		return nil
	}
	result := v.app.jsonResult

	// Update totalClusterSets from current data
	actualClusterSets := len(result.Clustering.Data)
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

	// Always use Clustering.Data since we convert multi-trie to single-trie output
	return &result.Clustering.Data[v.currentClusterSet]
}

// updateForCurrentTrie points the visualization at the App's current trie:
// refreshed cluster-set count, first cluster set, re-rendered from the cache.
func (v *VisualizationView) updateForCurrentTrie() {
	if v.app.jsonResult != nil {
		v.totalClusterSets = len(v.app.jsonResult.Clustering.Data)
		v.currentClusterSet = 0 // Reset to first cluster set

		v.RenderCached()
	}
}

// noClusteredTraffic is the overlay grid of a trie without cluster sets: no
// request is inside a detected range. Read-only.
var noClusteredTraffic [256][256]uint32

// heatmapGrids returns the grids the heatmap of the current (trie, cluster set)
// is drawn from, straight out of the shared TrieCache: traffic[a][b] counts all
// parsed requests in /16 a.b (ground truth, identical across tries), and
// clustered[a][b] those inside the set's detected ranges. ready is false until
// the request precache has published both (and while there is no traffic at
// all).
func (v *VisualizationView) heatmapGrids() (traffic, clustered *[256][256]uint32, ready bool) {
	traffic, maxTraffic, ok := v.app.trieCache.GetTrafficData()
	if !ok || maxTraffic == 0 {
		return nil, nil, false
	}
	if v.getCurrentClusterSet() == nil {
		return traffic, &noClusteredTraffic, true
	}
	clustered, ok = v.app.trieCache.GetClusteredData(v.app.currentTrie, v.currentClusterSet)
	return traffic, clustered, ok
}

// renderCacheKey returns the render-text cache key for a (trie, cluster set)
// pair under the current brightness mode. Renders differ per mode, so the
// scale mode is part of the key.
func (v *VisualizationView) renderCacheKey(trie, set int) renderKey {
	return renderKey{trie: trie, set: set, mode: v.scaleMode}
}

// RenderCached shows the heatmap of the current (trie, cluster set, scale
// mode), from the render-text cache when it was rendered before.
func (v *VisualizationView) RenderCached() {
	cacheKey := v.renderCacheKey(v.app.currentTrie, v.currentClusterSet)

	if cachedText, exists := v.cachedRenderText[cacheKey]; exists {
		// Use cached render text
		v.loading = false
		v.view.SetText(cachedText)
		return
	}

	// Generate the render text and cache it - unless it is the loading
	// placeholder, which has to give way to the heatmap once the data is in.
	renderText := v.generateRenderText()
	if !v.loading {
		v.cachedRenderText[cacheKey] = renderText
	}
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
			content.WriteString(fmt.Sprintf("[dim]Parameters: %s[white]\n",
				output.FormatClusterParameters(cluster.Parameters)))
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

	traffic, clustered, ready := v.heatmapGrids()
	v.loading = !ready
	if !ready {
		content.WriteString("[yellow]Loading traffic data...[white]\n")
		content.WriteString("[dim]Traffic data will appear once analysis is complete.[white]\n")
	} else {
		v.renderHeatmap(&content, traffic, clustered)
	}

	return content.String()
}

// Heatmap layout constants. gridGutter is the visible width of the left
// y-axis label column every body row reserves (e.g. "256│", "  │ "); cellWidth
// is the visible width every display cell renders (three glyphs: "███", or a
// char/dot/char overlay). The top A-axis and both body gutters are sized off
// these so the dash run, cells, and "│" borders all line up in the same
// columns on every row.
const (
	gridGutter = 4
	cellWidth  = 3
)

// axisDashCount returns the number of "─" runes for the top A-axis so the dash
// run plus its "1"/"256" end labels exactly span the grid's cell area
// (totalCols cells × cellWidth glyphs). Clamped at 0 for tiny grids
// (scale=256 → totalCols=1, where the labels alone already exceed the cells).
func axisDashCount(totalCols int) int {
	n := totalCols*cellWidth - len("1") - len("256")
	if n < 0 {
		n = 0
	}
	return n
}

// writePadded writes s into a fixed-width field of width columns, padding with
// spaces. rightAlign puts the padding before s (numbers flush right against the
// "│"); otherwise the padding follows s. Labels here are ASCII so len == column
// count. Allocation-free: it writes the spaces and the string directly to b.
func writePadded(b *strings.Builder, s string, width int, rightAlign bool) {
	pad := width - len(s)
	if pad < 0 {
		pad = 0
	}
	if rightAlign {
		for i := 0; i < pad; i++ {
			b.WriteByte(' ')
		}
		b.WriteString(s)
	} else {
		b.WriteString(s)
		for i := 0; i < pad; i++ {
			b.WriteByte(' ')
		}
	}
}

// renderHeatmap creates the ASCII-based heatmap. Cell brightness encodes the
// cell's TOTAL requests (sum of its scale×scale /16 bins), normalized against
// the busiest cell on the map (= 100% = white); the red dot encodes the share
// of the cell's requests inside detected cluster ranges.
func (v *VisualizationView) renderHeatmap(content *strings.Builder, traffic, clustered *[256][256]uint32) {
	// Each display cell aggregates a scale×scale block of /16 bins. scale=8
	// keeps the 32×32 grid compact enough to avoid scrolling.
	scale := v.effectiveScale()

	// First pass: the busiest cell total is the 100% brightness reference.
	var maxCellTraffic uint32
	for a := 0; a < 256; a += scale {
		for b := 0; b < 256; b += scale {
			if cellTraffic, _ := blockStats(traffic, clustered, a, b, scale); cellTraffic > maxCellTraffic {
				maxCellTraffic = cellTraffic
			}
		}
	}

	// Top A-axis (first octet, x-axis). The dash run plus its "1"/"256" end
	// labels exactly span the grid's cell area, and a gridGutter-wide blank
	// lead-in aligns the "1" with the first cell column (matching the body
	// rows' left label width). Visible width therefore equals
	// gridGutter + totalCols*cellWidth + len(" A"), so the axis never overruns
	// the cell area or the right border.
	totalCols := 256 / scale
	content.WriteString(strings.Repeat(" ", gridGutter)) // align with cell-area start
	content.WriteString("1")
	content.WriteString(strings.Repeat("─", axisDashCount(totalCols)))
	content.WriteString("256 A\n")

	// Render rows (B axis) with simple row numbering - now on y-axis, reversed for bottom-left origin
	totalRows := 256 / scale
	for rowIndex := 0; rowIndex < totalRows; rowIndex++ {
		// Calculate actual B value (reverse order: start from top = 256, go down to 1)
		b := 256 - scale - (rowIndex * scale)

		// Left y-axis label: a fixed gridGutter-wide field so the "│" border
		// lands in the SAME column on every row (the numeric label is
		// right-aligned in gridGutter-1 columns, then the bar). Preserves the
		// label text ("256", "1", blank). Built with plain WriteString to keep
		// the per-row cost allocation-free (no fmt).
		var leftLabel string
		if rowIndex == 0 {
			leftLabel = "256"
		} else if rowIndex == totalRows-1 {
			leftLabel = "1"
		}
		writePadded(content, leftLabel, gridGutter-1, true) // right-align
		content.WriteString("│")

		for a := 0; a < 256; a += scale {
			// Sum the cell's traffic and clustered requests.
			cellTraffic, cellClustered := blockStats(traffic, clustered, a, b, scale)

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

		// Right y-axis label: the "│" border immediately follows the last
		// cell on EVERY row (same column), then a fixed gridGutter-1-wide,
		// left-aligned label field so all body rows have identical visible
		// width. Preserves the label text ("256", "1", blank). Allocation-free
		// (no fmt).
		var rightLabel string
		if rowIndex == 0 {
			rightLabel = "256"
		} else if rowIndex == totalRows-1 {
			rightLabel = "1"
		}
		content.WriteString("│")
		writePadded(content, rightLabel, gridGutter-1, false) // left-align
		content.WriteString("\n")
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

			// Calculate the total for this cluster set; sum the per-range
			// percentages so the Total shares their denominator (requests after
			// filtering, not unique IPs). This mirrors buildClusteringText and
			// keeps the per-range lines summing exactly to the Total.
			var totalRequests uint32
			var totalPercentage float64
			for _, cidr := range clusterSet.MergedRanges {
				totalRequests += cidr.Requests
				totalPercentage += cidr.Percentage
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
// of /16 bins starting at (aStart, bStart) - the totals of one display cell.
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
// busiest cell on the map. Linear: x/max. Sqrt: sqrt(x/max) - power scale,
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
