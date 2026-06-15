package tui

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ChristianF88/cidrx/config"
	"github.com/ChristianF88/cidrx/ingestor"
	"github.com/ChristianF88/cidrx/output"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// App represents the TUI application
type App struct {
	app               *tview.Application
	pages             *tview.Pages
	progressView      *tview.TextView
	resultsView       *tview.Flex
	visualizationView *VisualizationView
	statusBar         *tview.TextView

	// Results panels
	summary        *tview.TextView
	clustering     *tview.TextView
	cidrAnalysis   *tview.TextView
	diagnostics    *tview.TextView
	focusableItems []tview.Primitive
	currentFocus   int

	logFile        string
	clusterArgSets []string
	rangesCidr     []string
	plotPath       string

	// Shared mutable state protected by mu (accessed from background goroutines)
	mu              sync.Mutex
	jsonResult      *output.JSONOutput
	requests        []ingestor.Request
	currentTrie     int
	multiTrieResult *output.JSONOutput // Store the full multi-trie result

	// Atomic flags for cross-goroutine signaling (no mutex needed)
	analysisComplete atomic.Bool
	switchingTrie    atomic.Bool
	requestsReady    chan struct{} // closed when requests are available

	// Multi-trie support (immutable after construction)
	cfg        *config.Config
	configPath string

	// Performance optimization components
	trieCache *TrieCache // pre-rendered per-trie texts and visualization data
}

// NewAppFromConfig creates a new TUI application from config file
func NewAppFromConfig(cfg *config.Config, configPath string) *App {
	app := &App{
		app:           tview.NewApplication(),
		pages:         tview.NewPages(),
		cfg:           cfg,
		configPath:    configPath,
		logFile:       cfg.Static.LogFile,
		plotPath:      cfg.Static.PlotPath,
		currentTrie:   0,
		requestsReady: make(chan struct{}),
	}

	// Initialize performance optimization components
	app.trieCache = NewTrieCache()

	app.setupUI()
	return app
}

// SetAnalysisResults sets the complete analysis results from StaticFromConfig
func (a *App) SetAnalysisResults(multiResult *output.JSONOutput) {
	if multiResult == nil {
		return
	}

	// Store the complete analysis results under lock
	a.mu.Lock()
	a.multiTrieResult = multiResult

	// Convert first trie to single-trie output for initial display
	if len(multiResult.Tries) > 0 {
		a.jsonResult = a.singleTrieOutput(0)
		if a.jsonResult == nil {
			a.mu.Unlock()
			a.ShowError(fmt.Sprintf("Failed to convert trie 0 to single-trie output. Tries available: %d", len(multiResult.Tries)))
			return
		}
	} else {
		a.mu.Unlock()
		a.ShowError("Analysis completed but no tries found in results")
		return
	}
	a.mu.Unlock()

	// Mark analysis as complete (atomic, no lock needed)
	a.analysisComplete.Store(true)

	// Update UI to show results immediately
	a.app.QueueUpdateDraw(func() {
		a.displayResults()
		a.updateStatusBar()
		a.pages.SwitchToPage("results")
	})

	// Pre-initialize visualization in background for instant switching
	go a.preInitializeVisualization()
}

// ShowError displays an error message in the TUI and stops the progress animation
func (a *App) ShowError(message string) {
	a.app.QueueUpdateDraw(func() {
		// Update progress view to show error
		a.progressView.SetText(fmt.Sprintf("[red]Error:[white] %s\n\n[yellow]Press 'q' to quit[white]", message))

		// Update status bar
		a.statusBar.SetText("[red]Analysis failed![white] | Press 'q' to quit")

		// Make sure we're on the progress page to show the error
		a.pages.SwitchToPage("progress")
	})
}

// preInitializeVisualization creates and prepares the visualization view in background
func (a *App) preInitializeVisualization() {
	// Wait for requests to be available (SetRequestData to be called)
	<-a.requestsReady

	// Create visualization view if it doesn't exist
	if a.visualizationView == nil {
		a.visualizationView = a.NewVisualizationView()

		// Create visualization page layout on UI thread
		a.app.QueueUpdateDraw(func() {
			visualizationLayout := tview.NewFlex().SetDirection(tview.FlexRow).
				AddItem(a.visualizationView.GetView(), 0, 1, true).
				AddItem(a.statusBar, 1, 0, false)

			a.pages.AddPage("visualization", visualizationLayout, true, false)
		})
	}

	// Pre-process traffic data in background (expensive operation)
	if len(a.requests) > 0 {
		a.visualizationView.ProcessTrafficData(a.requests)
		// Pre-render initial visualization
		a.visualizationView.Render()
	}
}

// SetRequestData sets the real request data for visualization and pre-caches all tries
func (a *App) SetRequestData(requests []ingestor.Request) {
	a.mu.Lock()
	a.requests = requests
	a.mu.Unlock()

	// Signal that requests are available
	close(a.requestsReady)

	if a.trieCache != nil && a.multiTrieResult != nil {
		go func() {
			a.trieCache.PreCacheAllTries(a, a.multiTrieResult, requests)
		}()
	}

	// Update visualization if it exists and pre-cache all tries for instant switching
	a.app.QueueUpdateDraw(func() {
		if a.visualizationView != nil {
			// Pre-cache traffic data with complete results
			a.visualizationView.PreCacheAllTries(a.requests)
			a.visualizationView.RenderCached()
		}
	})
}

// setupUI initializes the user interface
func (a *App) setupUI() {
	// Create progress view
	a.progressView = tview.NewTextView().
		SetDynamicColors(true).
		SetScrollable(false).
		SetWrap(false)
	a.progressView.SetBorder(true).SetTitle(" cidrx Analysis Progress ").SetTitleAlign(tview.AlignCenter)

	// Create results view (initially hidden)
	a.resultsView = tview.NewFlex().SetDirection(tview.FlexRow)
	a.setupResultsView()

	// Create status bar
	a.statusBar = tview.NewTextView().
		SetDynamicColors(true).
		SetText("[yellow]Starting analysis...[white] | Press 'q' to quit")
	a.statusBar.SetBorder(false)

	// Create main layout
	main := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(a.progressView, 0, 1, true).
		AddItem(a.statusBar, 1, 0, false)

	results := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(a.resultsView, 0, 1, true).
		AddItem(a.statusBar, 1, 0, false)

	// Add pages
	a.pages.AddPage("progress", main, true, true)
	a.pages.AddPage("results", results, true, false)

	// Set up key bindings
	a.app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Rune() {
		case 'q', 'Q':
			a.app.Stop()
			return nil
		case 'r', 'R':
			if a.analysisComplete.Load() {
				a.pages.SwitchToPage("results")
				a.updateStatusBar()
			}
			return nil
		case 'p', 'P':
			a.pages.SwitchToPage("progress")
			a.statusBar.SetText("[yellow]Analysis in progress...[white] | 'r' for results, 'q' to quit")
			return nil
		case 'v', 'V':
			if a.analysisComplete.Load() {
				a.showVisualization()
			}
			return nil
		case 't', 'T':
			if a.analysisComplete.Load() && a.cfg != nil && a.multiTrieResult != nil {
				// Check if we have multiple tries stored
				if len(a.multiTrieResult.Tries) > 1 {
					a.nextTrie()
				}
			}
			return nil
		}

		// Handle navigation in results view
		frontPageName, _ := a.pages.GetFrontPage()
		if a.analysisComplete.Load() && frontPageName == "results" {
			switch event.Key() {
			case tcell.KeyTab:
				a.nextFocus()
				return nil
			case tcell.KeyBacktab:
				a.prevFocus()
				return nil
			case tcell.KeyDown:
				if focused := a.getFocusedItem(); focused != nil {
					if tv, ok := focused.(*tview.TextView); ok {
						row, col := tv.GetScrollOffset()
						tv.ScrollTo(row+1, col)
					}
				}
				return nil
			case tcell.KeyUp:
				if focused := a.getFocusedItem(); focused != nil {
					if tv, ok := focused.(*tview.TextView); ok {
						row, col := tv.GetScrollOffset()
						if row > 0 {
							tv.ScrollTo(row-1, col)
						}
					}
				}
				return nil
			case tcell.KeyPgDn:
				if focused := a.getFocusedItem(); focused != nil {
					if tv, ok := focused.(*tview.TextView); ok {
						row, col := tv.GetScrollOffset()
						tv.ScrollTo(row+10, col)
					}
				}
				return nil
			case tcell.KeyPgUp:
				if focused := a.getFocusedItem(); focused != nil {
					if tv, ok := focused.(*tview.TextView); ok {
						row, col := tv.GetScrollOffset()
						if row > 10 {
							tv.ScrollTo(row-10, col)
						} else {
							tv.ScrollTo(0, col)
						}
					}
				}
				return nil
			}
		}

		// Handle navigation in visualization view
		if a.analysisComplete.Load() && frontPageName == "visualization" {
			switch event.Rune() {
			case 'l', 'L':
				if a.visualizationView != nil {
					a.visualizationView.ToggleIntensityScale()
				}
				return nil
			}
			switch event.Key() {
			case tcell.KeyLeft:
				if a.visualizationView != nil {
					a.visualizationView.PrevClusterSet()
				}
				return nil
			case tcell.KeyRight:
				if a.visualizationView != nil {
					a.visualizationView.NextClusterSet()
				}
				return nil
			case tcell.KeyUp:
				if a.visualizationView != nil {
					view := a.visualizationView.GetView()
					row, col := view.GetScrollOffset()
					if row > 0 {
						view.ScrollTo(row-1, col)
					}
				}
				return nil
			case tcell.KeyDown:
				if a.visualizationView != nil {
					view := a.visualizationView.GetView()
					row, col := view.GetScrollOffset()
					view.ScrollTo(row+1, col)
				}
				return nil
			}
		}

		return event
	})

	a.app.SetRoot(a.pages, true)
}

// setupResultsView creates the results display layout
func (a *App) setupResultsView() {
	// Summary panel
	a.summary = tview.NewTextView().
		SetDynamicColors(true).
		SetScrollable(false)
	a.summary.SetBorder(true).SetTitle(" Summary ").SetTitleAlign(tview.AlignLeft)

	// Clustering results
	a.clustering = tview.NewTextView().
		SetDynamicColors(true).
		SetScrollable(true)
	a.clustering.SetBorder(true).SetTitle(" Clustering Results ").SetTitleAlign(tview.AlignLeft)

	// CIDR analysis
	a.cidrAnalysis = tview.NewTextView().
		SetDynamicColors(true).
		SetScrollable(true)
	a.cidrAnalysis.SetBorder(true).SetTitle(" CIDR Analysis ").SetTitleAlign(tview.AlignLeft)

	// Warnings/Errors
	a.diagnostics = tview.NewTextView().
		SetDynamicColors(true).
		SetScrollable(true)
	a.diagnostics.SetBorder(true).SetTitle(" Diagnostics ").SetTitleAlign(tview.AlignLeft)

	// Set up focusable items
	a.focusableItems = []tview.Primitive{a.clustering, a.cidrAnalysis, a.diagnostics}
	a.currentFocus = 0
	a.updateFocusBorders()

	// Layout: Summary on top, then 3 columns for the rest
	topRow := tview.NewFlex().SetDirection(tview.FlexColumn).
		AddItem(a.summary, 0, 1, false)

	bottomRow := tview.NewFlex().SetDirection(tview.FlexColumn).
		AddItem(a.clustering, 0, 2, false).
		AddItem(a.cidrAnalysis, 0, 1, false).
		AddItem(a.diagnostics, 0, 1, false)

	a.resultsView.
		AddItem(topRow, 9, 0, false).
		AddItem(bottomRow, 0, 1, false)
}

// Run starts the TUI application
func (a *App) Run() error {
	// Analysis is now done in CLI layer before TUI starts
	// Just start the progress animation until results arrive
	go a.animateProgress()

	// Run the TUI
	return a.app.Run()
}

// animateProgress shows a fake progress animation
func (a *App) animateProgress() {
	stages := []string{
		"[yellow]▶[white] Initializing parser...",
		"[blue]▶[white] Loading log file...",
		"[cyan]▶[white] Parsing log entries...",
		"[green]▶[white] Building IP trie...",
		"[magenta]▶[white] Running clustering analysis...",
		"[yellow]▶[white] Processing CIDR ranges...",
		"[blue]▶[white] Merging overlapping ranges...",
		"[cyan]▶[white] Finalizing results...",
	}

	stageIndex := 0
	dots := 0

	for !a.analysisComplete.Load() {
		stage := stages[stageIndex%len(stages)]
		dotStr := strings.Repeat(".", dots%4)

		var clusterSets, cidrRanges int
		if a.cfg != nil {
			// Count cluster sets and CIDR ranges from config
			for _, trieConfig := range a.cfg.StaticTries {
				clusterSets += len(trieConfig.ClusterArgSets)
				cidrRanges += len(trieConfig.CIDRRanges)
			}
		} else {
			// No-config mode
			clusterSets = len(a.clusterArgSets) / 4
			cidrRanges = len(a.rangesCidr)
		}

		content := fmt.Sprintf(`
[white::b]cidrx Log Analysis[white::-]

%s%s

[dim]Log file:[white] %s
[dim]Cluster sets:[white] %d
[dim]CIDR ranges:[white] %d

[dim]Press 'q' to quit[white]
`, stage, dotStr, a.logFile, clusterSets, cidrRanges)

		a.app.QueueUpdateDraw(func() {
			a.progressView.SetText(content)
		})

		time.Sleep(200 * time.Millisecond)
		dots++

		if dots%20 == 0 {
			stageIndex++
		}
	}
}

// nextTrie cycles to the next trie in config mode (async optimized)
func (a *App) nextTrie() {
	a.mu.Lock()
	canSwitch := a.cfg != nil && a.multiTrieResult != nil && len(a.multiTrieResult.Tries) > 1
	var newTrieIndex int
	if canSwitch {
		newTrieIndex = (a.currentTrie + 1) % len(a.multiTrieResult.Tries)
	}
	a.mu.Unlock()

	if canSwitch {
		// Prevent concurrent switching (atomic CAS)
		if !a.switchingTrie.CompareAndSwap(false, true) {
			return
		}
		go a.switchTrieAsync(newTrieIndex)
	}
}

// switchTrieAsync performs instant trie switching using fast RAM cache
func (a *App) switchTrieAsync(newTrieIndex int) {
	defer a.switchingTrie.Store(false)

	// Try fast cache first for instant switching
	if a.trieCache != nil {
		trieOutput, cacheHit := a.trieCache.GetTrieOutput(newTrieIndex)
		if cacheHit && trieOutput != nil {
			// INSTANT switching using cached data
			a.app.QueueUpdateDraw(func() {
				a.currentTrie = newTrieIndex
				a.jsonResult = trieOutput

				// Use pre-rendered texts for instant display
				a.displayResultsFromTrieCache(newTrieIndex)
				a.updateStatusBar()

				// Update visualization with cached data
				if a.visualizationView != nil {
					a.updateVisualizationFromCache(newTrieIndex)
				}
			})
			return
		} else {
			// Try to quickly cache this specific trie if not already cached
			if a.multiTrieResult != nil && newTrieIndex < len(a.multiTrieResult.Tries) {
				go func() {
					if a.trieCache.PreCacheSingleTrie(a, newTrieIndex, a.multiTrieResult, a.requests) {
						// Cache was successful, trigger a quick re-render if still on this trie
						if a.currentTrie == newTrieIndex {
							a.app.QueueUpdateDraw(func() {
								// Re-try with newly cached data
								if cachedData, hit := a.trieCache.GetTrieOutput(newTrieIndex); hit && cachedData != nil {
									a.jsonResult = cachedData
									a.displayResultsFromTrieCache(newTrieIndex)
									if a.visualizationView != nil {
										a.updateVisualizationFromCache(newTrieIndex)
									}
								}
							})
						}
					}
				}()
			}
		}
	}

	// Last resort: Expensive synchronous processing (should rarely happen)
	a.app.QueueUpdateDraw(func() {
		a.currentTrie = newTrieIndex
		newTrieData := a.singleTrieOutput(newTrieIndex)
		if newTrieData != nil {
			a.jsonResult = newTrieData
			a.displayResults()
			a.updateStatusBar()

			if a.visualizationView != nil {
				frontPageName, _ := a.pages.GetFrontPage()
				if frontPageName == "visualization" {
					a.visualizationView.updateForCurrentTrie()
				} else {
					a.visualizationView.updateMetadataOnly()
				}
			}
		}
	})
}

// displayResults populates the results view with analysis data
func (a *App) displayResults() {
	if a.jsonResult == nil {
		return
	}

	if a.cfg != nil && a.multiTrieResult != nil {
		a.displayCachedResults()
	} else {
		a.displayResultsUncached()
	}
}

// displayCachedResults shows pre-rendered results for multi-trie analysis,
// building and caching all four panels on first display.
func (a *App) displayCachedResults() {
	summary, clustering, cidr, diagnostics, ok := a.trieCache.GetPreRenderedTexts(a.currentTrie)
	if !ok {
		summary = a.buildSummaryText()
		clustering = a.buildClusteringText()
		cidr = a.buildCidrAnalysisText()
		diagnostics = a.buildDiagnosticsText()
		a.trieCache.SetPreRenderedTexts(a.currentTrie, summary, clustering, cidr, diagnostics)
	}
	a.summary.SetText(summary)
	a.clustering.SetText(clustering)
	a.cidrAnalysis.SetText(cidr)
	a.diagnostics.SetText(diagnostics)
}

// displayResultsUncached shows results without caching (no-config mode)
func (a *App) displayResultsUncached() {
	// Populate summary with fixed stats and trie-specific stats
	summaryText := a.buildSummaryText()
	a.summary.SetText(summaryText)

	// Populate clustering results
	var clusteringText strings.Builder
	clusteringText.WriteString("[white::b]Detected Threats[white::-]\n\n")

	for i, cluster := range a.jsonResult.Clustering.Data {
		clusteringText.WriteString(fmt.Sprintf("[yellow]Set %d[white] (min_size=%d, depth=%d-%d)\n",
			i+1, cluster.Parameters.MinClusterSize, cluster.Parameters.MinDepth, cluster.Parameters.MaxDepth))

		if len(cluster.MergedRanges) > 0 {
			clusteringText.WriteString("[red]Merged Ranges:[white]\n")

			// Calculate total for this cluster set; sum the per-range
			// percentages so the total shares their denominator
			// (requests after filtering, not unique IPs)
			var totalRequests uint32
			var totalPercentage float64
			for _, cidr := range cluster.MergedRanges {
				totalRequests += cidr.Requests
				totalPercentage += cidr.Percentage
			}

			for _, cidr := range cluster.MergedRanges {
				clusteringText.WriteString(fmt.Sprintf("  • %s: [red]%s[white] requests (%.2f%%)\n",
					cidr.CIDR, output.FormatNumber(int(cidr.Requests)), cidr.Percentage))
			}
			clusteringText.WriteString(fmt.Sprintf("[yellow]Total for Set %d: %s requests (%.2f%%)[white]\n",
				i+1, output.FormatNumber(int(totalRequests)), totalPercentage))
		} else {
			clusteringText.WriteString("[dim]No significant ranges detected[white]\n")
		}
		clusteringText.WriteString("\n")
	}

	a.clustering.SetText(clusteringText.String())

	// Populate CIDR analysis
	var cidrText strings.Builder
	cidrText.WriteString("[white::b]Range Analysis[white::-]\n\n")

	if len(a.jsonResult.CIDRAnalysis.Data) > 0 {
		for _, cidr := range a.jsonResult.CIDRAnalysis.Data {
			cidrText.WriteString(fmt.Sprintf("[cyan]%s[white]\n", cidr.CIDR))
			cidrText.WriteString(fmt.Sprintf("  Requests: [yellow]%s[white] (%.2f%%)\n\n",
				output.FormatNumber(int(cidr.Requests)), cidr.Percentage))
		}
	} else {
		cidrText.WriteString("[dim]No specific ranges analyzed[white]")
	}

	a.cidrAnalysis.SetText(cidrText.String())

	// Populate diagnostics - filter out info messages in multi-trie mode
	var diagText strings.Builder
	diagText.WriteString("[white::b]Diagnostics[white::-]\n\n")

	// Filter out info messages
	var realWarnings []output.Warning
	for _, warning := range a.jsonResult.Warnings {
		if warning.Type != "info" {
			realWarnings = append(realWarnings, warning)
		}
	}

	if len(realWarnings) > 0 {
		diagText.WriteString("[yellow]Warnings:[white]\n")
		for _, warning := range realWarnings {
			diagText.WriteString(fmt.Sprintf("  • %s\n", warning.Message))
		}
		diagText.WriteString("\n")
	}

	if len(a.jsonResult.Errors) > 0 {
		diagText.WriteString("[red]Errors:[white]\n")
		for _, err := range a.jsonResult.Errors {
			diagText.WriteString(fmt.Sprintf("  • %s\n", err.Message))
		}
	} else if len(realWarnings) == 0 {
		diagText.WriteString("[green]✓ No issues detected[white]")
	}

	a.diagnostics.SetText(diagText.String())
}

// buildClusteringText creates the clustering results text
func (a *App) buildClusteringText() string {
	var clusteringText strings.Builder
	clusteringText.WriteString("[white::b]Detected Threats[white::-]\n\n")

	for i, cluster := range a.jsonResult.Clustering.Data {
		clusteringText.WriteString(fmt.Sprintf("[yellow]Set %d[white] (min_size=%d, depth=%d-%d)\n",
			i+1, cluster.Parameters.MinClusterSize, cluster.Parameters.MinDepth, cluster.Parameters.MaxDepth))

		if len(cluster.MergedRanges) > 0 {
			clusteringText.WriteString("[red]Merged Ranges:[white]\n")

			// Calculate total for this cluster set; sum the per-range
			// percentages so the total shares their denominator
			// (requests after filtering, not unique IPs)
			var totalRequests uint32
			var totalPercentage float64
			for _, cidr := range cluster.MergedRanges {
				totalRequests += cidr.Requests
				totalPercentage += cidr.Percentage
			}

			for _, cidr := range cluster.MergedRanges {
				clusteringText.WriteString(fmt.Sprintf("  • %s: [red]%s[white] requests (%.2f%%)\n",
					cidr.CIDR, output.FormatNumber(int(cidr.Requests)), cidr.Percentage))
			}
			clusteringText.WriteString(fmt.Sprintf("[yellow]Total for Set %d: %s requests (%.2f%%)[white]\n",
				i+1, output.FormatNumber(int(totalRequests)), totalPercentage))
		} else {
			clusteringText.WriteString("[dim]No significant ranges detected[white]\n")
		}
		clusteringText.WriteString("\n")
	}

	return clusteringText.String()
}

// buildCidrAnalysisText creates the CIDR analysis text
func (a *App) buildCidrAnalysisText() string {
	var cidrText strings.Builder
	cidrText.WriteString("[white::b]Range Analysis[white::-]\n\n")

	if len(a.jsonResult.CIDRAnalysis.Data) > 0 {
		for _, cidr := range a.jsonResult.CIDRAnalysis.Data {
			cidrText.WriteString(fmt.Sprintf("[cyan]%s[white]\n", cidr.CIDR))
			cidrText.WriteString(fmt.Sprintf("  Requests: [yellow]%s[white] (%.2f%%)\n\n",
				output.FormatNumber(int(cidr.Requests)), cidr.Percentage))
		}
	} else {
		cidrText.WriteString("[dim]No specific ranges analyzed[white]")
	}

	return cidrText.String()
}

// buildDiagnosticsText creates the diagnostics text
func (a *App) buildDiagnosticsText() string {
	var diagText strings.Builder
	diagText.WriteString("[white::b]Diagnostics[white::-]\n\n")

	// Filter out info messages
	var realWarnings []output.Warning
	for _, warning := range a.jsonResult.Warnings {
		if warning.Type != "info" {
			realWarnings = append(realWarnings, warning)
		}
	}

	if len(realWarnings) > 0 {
		diagText.WriteString("[yellow]Warnings:[white]\n")
		for _, warning := range realWarnings {
			diagText.WriteString(fmt.Sprintf("  • %s\n", warning.Message))
		}
		diagText.WriteString("\n")
	}

	if len(a.jsonResult.Errors) > 0 {
		diagText.WriteString("[red]Errors:[white]\n")
		for _, err := range a.jsonResult.Errors {
			diagText.WriteString(fmt.Sprintf("  • %s\n", err.Message))
		}
	} else if len(realWarnings) == 0 {
		diagText.WriteString("[green]✓ No issues detected[white]")
	}

	return diagText.String()
}

// buildSummaryText creates the summary text with fixed and trie-specific stats
func (a *App) buildSummaryText() string {
	var summaryText strings.Builder
	summaryText.WriteString("[white::b]Analysis Summary[white::-]\n\n")

	// Fixed stats (global, not trie-specific) - always show these first
	// Use original multiTrieResult data for truly fixed stats
	var parseRate int64
	var totalIPsRead int
	var parsingTime int64

	if a.cfg != nil && a.multiTrieResult != nil {
		// Multi-trie mode - use original data
		parseRate = a.multiTrieResult.General.Parsing.RatePerSecond
		totalIPsRead = a.multiTrieResult.General.TotalRequests
		parsingTime = a.multiTrieResult.General.Parsing.DurationMS
	} else {
		// No-config mode - use jsonResult data
		parseRate = a.jsonResult.General.Parsing.RatePerSecond
		totalIPsRead = a.jsonResult.General.TotalRequests
		parsingTime = a.jsonResult.General.Parsing.DurationMS
	}

	summaryText.WriteString(fmt.Sprintf("[dim]Parse Rate:[white] %s req/sec  ",
		output.FormatNumber(int(parseRate))))
	summaryText.WriteString(fmt.Sprintf("[dim]Amount of IPs Read:[white] %s  ",
		output.FormatNumber(totalIPsRead)))
	summaryText.WriteString(fmt.Sprintf("[dim]Parsing Time:[white] %dms\n\n",
		parsingTime))

	// Trie-specific stats (show below the fixed stats)
	// Always use multiTrieResult directly for accurate Parameters and Stats
	if a.cfg != nil && a.multiTrieResult != nil && a.currentTrie < len(a.multiTrieResult.Tries) {
		// Always use multiTrieResult directly - it has the accurate Parameters and Stats
		// The single-trie output conversion loses this information, so we bypass it here
		trieData := a.multiTrieResult.Tries[a.currentTrie]

		summaryText.WriteString(fmt.Sprintf("[white::b]Trie: %s[white::-]\n", trieData.Name))

		// Active filters
		summaryText.WriteString("[dim]Active Filters:[white] ")
		filters := a.getActiveFilters(trieData.Parameters)
		if len(filters) > 0 {
			summaryText.WriteString(strings.Join(filters, ", "))
		} else {
			summaryText.WriteString("None")
		}
		summaryText.WriteString("\n")

		// Trie build time (filtering + inserts)
		summaryText.WriteString(fmt.Sprintf("[dim]Trie Build Time:[white] %dms\n", trieData.Stats.InsertTimeMS))

		// Requests after filtering
		summaryText.WriteString(fmt.Sprintf("[dim]Requests After Filtering:[white] %s\n",
			output.FormatNumber(trieData.Stats.TotalRequestsAfterFiltering)))

		// Requests dropped by the global UA whitelist (shown so the count drop
		// is explained even when no per-trie filters are active).
		if trieData.Stats.UAWhitelistExcluded > 0 {
			summaryText.WriteString(fmt.Sprintf("[dim]Excluded (UA whitelist):[white] %s\n",
				output.FormatNumber(trieData.Stats.UAWhitelistExcluded)))
		}

		// Analysis time (sum of all clustering runs)
		totalAnalysisTime := a.calculateTotalAnalysisTime(trieData.Data)
		clusterCount := len(trieData.Data)
		if totalAnalysisTime == 0 && clusterCount > 0 {
			// If 0μs but we have cluster results, show "<1μs" for very fast operations
			summaryText.WriteString(fmt.Sprintf("[dim]Analysis Time:[white] <1μs (%d clusters)", clusterCount))
		} else if totalAnalysisTime > 0 {
			if totalAnalysisTime >= 1000 {
				// Show in milliseconds if >= 1000μs
				summaryText.WriteString(fmt.Sprintf("[dim]Analysis Time:[white] %.1fms (%d clusters)", float64(totalAnalysisTime)/1000.0, clusterCount))
			} else {
				summaryText.WriteString(fmt.Sprintf("[dim]Analysis Time:[white] %dμs (%d clusters)", totalAnalysisTime, clusterCount))
			}
		} else {
			// No clustering results
			summaryText.WriteString("[dim]Analysis Time:[white] N/A (no clustering)")
		}

	} else {
		// No-config CLI mode
		summaryText.WriteString("[white::b]Legacy Analysis[white::-]\n")
		summaryText.WriteString(fmt.Sprintf("[dim]Log File:[white] %s\n", a.jsonResult.General.LogFile))
		summaryText.WriteString(fmt.Sprintf("[dim]Unique IPs:[white] %s\n",
			output.FormatNumber(a.jsonResult.General.UniqueIPs)))
		summaryText.WriteString(fmt.Sprintf("[dim]Analysis Time:[white] %dms", a.jsonResult.Metadata.DurationMS))
	}

	return summaryText.String()
}

// getActiveFilters returns a list of active filter descriptions
func (a *App) getActiveFilters(params output.TrieParameters) []string {
	var filters []string

	if params.UserAgentRegex != nil && *params.UserAgentRegex != "" {
		filters = append(filters, fmt.Sprintf("User-Agent: %s", *params.UserAgentRegex))
	}

	if params.EndpointRegex != nil && *params.EndpointRegex != "" {
		filters = append(filters, fmt.Sprintf("Endpoint: %s", *params.EndpointRegex))
	}

	if params.TimeRange != nil {
		if !params.TimeRange.Start.IsZero() || !params.TimeRange.End.IsZero() {
			timeFilter := "Time: "
			if !params.TimeRange.Start.IsZero() {
				timeFilter += params.TimeRange.Start.Format("2006-01-02 15:04")
			} else {
				timeFilter += "∞"
			}
			timeFilter += " → "
			if !params.TimeRange.End.IsZero() {
				timeFilter += params.TimeRange.End.Format("2006-01-02 15:04")
			} else {
				timeFilter += "∞"
			}
			filters = append(filters, timeFilter)
		}
	}

	// Note: CIDRRanges are not filters - they are analysis targets, so we don't include them

	return filters
}

// calculateTotalAnalysisTime sums up all clustering execution times
func (a *App) calculateTotalAnalysisTime(clusterResults []output.ClusterResult) int64 {
	var total int64
	for _, result := range clusterResults {
		total += result.ExecutionTimeUS
	}
	return total
}

// Navigation helper functions
func (a *App) nextFocus() {
	a.currentFocus = (a.currentFocus + 1) % len(a.focusableItems)
	a.updateFocusBorders()
	a.updateStatusBar()
}

func (a *App) prevFocus() {
	a.currentFocus = (a.currentFocus - 1 + len(a.focusableItems)) % len(a.focusableItems)
	a.updateFocusBorders()
	a.updateStatusBar()
}

func (a *App) getFocusedItem() tview.Primitive {
	if a.currentFocus >= 0 && a.currentFocus < len(a.focusableItems) {
		return a.focusableItems[a.currentFocus]
	}
	return nil
}

func (a *App) updateFocusBorders() {
	titles := []string{" Clustering Results ", " CIDR Analysis ", " Diagnostics "}
	focusedTitles := []string{" [::b]Clustering Results[FOCUSED] ", " [::b]CIDR Analysis[FOCUSED] ", " [::b]Diagnostics[FOCUSED] "}

	for i, item := range a.focusableItems {
		if tv, ok := item.(*tview.TextView); ok {
			if i == a.currentFocus {
				tv.SetBorderColor(tcell.ColorYellow).SetTitle(focusedTitles[i])
			} else {
				tv.SetBorderColor(tcell.ColorDefault).SetTitle(titles[i])
			}
		}
	}
}

func (a *App) updateStatusBar() {
	if !a.analysisComplete.Load() {
		a.statusBar.SetText("[yellow]Analysis in progress...[white] | 'r' for results, 'q' to quit")
		return
	}

	frontPageName, _ := a.pages.GetFrontPage()

	switch frontPageName {
	case "visualization":
		if a.visualizationView != nil && a.visualizationView.totalClusterSets > 0 {
			a.statusBar.SetText(fmt.Sprintf("[green]Visualization mode[white] | Set %d/%d | ←→: change cluster set, ↑↓: scroll, 'r': results, 'v': visualization, 'q': quit",
				a.visualizationView.currentClusterSet+1, a.visualizationView.totalClusterSets))
		} else {
			a.statusBar.SetText("[green]Visualization mode[white] | ↑↓: scroll, 'r': results, 'q': quit")
		}
	default:
		panelNames := []string{"Clustering Results", "CIDR Analysis", "Diagnostics"}
		currentPanel := panelNames[a.currentFocus]

		if a.cfg != nil && a.multiTrieResult != nil {
			// Config mode - check if we have multiple tries stored
			if len(a.multiTrieResult.Tries) > 1 {
				// Multi-trie mode
				if a.currentTrie >= len(a.multiTrieResult.Tries) {
					a.currentTrie = 0
				}
				trieName := a.multiTrieResult.Tries[a.currentTrie].Name
				a.statusBar.SetText(fmt.Sprintf("[green]Analysis complete![white] | [yellow]%s[white] focused | [cyan]%s (%d/%d)[white] | Tab/Shift+Tab: panels, 't': next trie, ↑↓: scroll, 'v': visualization, 'p': progress, 'q': quit",
					currentPanel, trieName, a.currentTrie+1, len(a.multiTrieResult.Tries)))
			} else {
				// Single trie config mode
				a.statusBar.SetText(fmt.Sprintf("[green]Analysis complete![white] | [yellow]%s[white] focused | Tab/Shift+Tab: panels, ↑↓: scroll, 'v': visualization, 'p': progress, 'q': quit", currentPanel))
			}
		} else {
			// No-config CLI mode
			a.statusBar.SetText(fmt.Sprintf("[green]Analysis complete![white] | [yellow]%s[white] focused | Tab/Shift+Tab: switch panels, ↑↓: scroll, 'v': visualization, 'p': progress, 'q': quit", currentPanel))
		}
	}
}

// showVisualization switches to the visualization view
func (a *App) showVisualization() {
	// Check if visualization is ready (pre-initialized in background)
	if a.visualizationView == nil {
		// Fallback: create on-demand if background initialization hasn't finished
		a.visualizationView = a.NewVisualizationView()

		// Create visualization page layout
		visualizationLayout := tview.NewFlex().SetDirection(tview.FlexRow).
			AddItem(a.visualizationView.GetView(), 0, 1, true).
			AddItem(a.statusBar, 1, 0, false)

		a.pages.AddPage("visualization", visualizationLayout, true, false)

		// Process data if we have requests (fallback for immediate use)
		if len(a.requests) > 0 {
			a.visualizationView.ProcessTrafficData(a.requests)
			a.visualizationView.Render()
		}
	}

	// Switch to visualization page (should be instant if pre-initialized)
	a.pages.SwitchToPage("visualization")
	a.updateStatusBar()
}

// singleTrieOutput converts a specific trie to a single-trie JSONOutput
func (a *App) singleTrieOutput(trieIndex int) *output.JSONOutput {
	if a.multiTrieResult == nil {
		return nil
	}
	if trieIndex >= len(a.multiTrieResult.Tries) {
		return nil
	}

	trieResult := a.multiTrieResult.Tries[trieIndex]

	// Create a single-trie result
	trieOutput := output.NewJSONOutput("static", time.Now())

	// Copy general info but customize for this trie
	trieOutput.General = a.multiTrieResult.General
	trieOutput.General.UniqueIPs = trieResult.Stats.UniqueIPs
	// Keep TotalRequests as the original parsed amount (don't overwrite with filtered amount)

	// Add trie-specific info to log file name
	trieOutput.General.LogFile = fmt.Sprintf("%s [Trie: %s]", a.multiTrieResult.General.LogFile, trieResult.Name)

	// Convert clustering data
	trieOutput.Clustering.Data = trieResult.Data
	trieOutput.Clustering.Metadata.TotalClusters = len(trieResult.Data)

	// Convert CIDR analysis
	trieOutput.CIDRAnalysis.Data = trieResult.Stats.CIDRAnalysis

	// Copy warnings and errors
	trieOutput.Warnings = a.multiTrieResult.Warnings
	trieOutput.Errors = a.multiTrieResult.Errors

	return trieOutput
}

// displayResultsFromTrieCache uses pre-rendered texts from TrieCache for instant display
func (a *App) displayResultsFromTrieCache(trieIndex int) {
	if a.trieCache == nil {
		// Fallback to normal display
		a.displayResults()
		return
	}

	// Get pre-rendered texts from cache
	summaryText, clusteringText, cidrText, diagnosticsText, exists := a.trieCache.GetPreRenderedTexts(trieIndex)
	if !exists {
		// Fallback to normal display if cache miss
		a.displayResults()
		return
	}

	// Set pre-rendered content directly - no processing required
	a.summary.SetText(summaryText)
	a.clustering.SetText(clusteringText)
	a.cidrAnalysis.SetText(cidrText)
	a.diagnostics.SetText(diagnosticsText)
}

// updateVisualizationFromCache uses cached traffic data for instant visualization updates
func (a *App) updateVisualizationFromCache(trieIndex int) {
	if a.trieCache == nil || a.visualizationView == nil {
		// Fallback to uncached visualization update
		a.visualizationView.updateForCurrentTrie()
		return
	}

	// Get cached traffic data
	trafficMatrix, maxTraffic, exists := a.trieCache.GetTrafficData(trieIndex)
	if !exists {
		// Cache not ready yet, fall back to the uncached path
		a.visualizationView.updateForCurrentTrie()
		return
	}

	// Update visualization with cached data instantly
	a.visualizationView.trafficData = trafficMatrix
	a.visualizationView.maxTraffic = maxTraffic

	// Seed the clustered-overlay grid from the fast cache so the heatmap render
	// does not have to re-scan requests. Keyed by (trie, current cluster set).
	if grid, ok := a.trieCache.GetClusteredData(trieIndex, a.visualizationView.currentClusterSet); ok {
		a.visualizationView.clusteredData = grid
		if a.visualizationView.cachedClusteredData != nil {
			a.visualizationView.cachedClusteredData[clusterKey{trie: trieIndex, set: a.visualizationView.currentClusterSet}] = grid
		}
	}

	// Get current cluster set and render with cached visualization if available
	if cachedRender, cacheHit := a.trieCache.GetVisualizationRender(trieIndex, a.visualizationView.currentClusterSet); cacheHit {
		// Use pre-rendered visualization
		a.visualizationView.view.SetText(cachedRender)
	} else {
		// Generate on-demand if not cached (much faster since traffic data is cached)
		a.visualizationView.Render()
	}
}
