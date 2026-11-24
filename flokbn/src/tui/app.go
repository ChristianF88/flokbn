package tui

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ChristianF88/flokbn/accesslog"
	"github.com/ChristianF88/flokbn/config"
	"github.com/ChristianF88/flokbn/output"
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

	// Parent Flex rows that hold a.statusBar (one per page). The status bar is a
	// single shared primitive placed into each page's layout; these references
	// let setStatusBarText resize its row to fit the wrapped legend so the
	// navigational help is never clipped on narrow terminals.
	progressLayout      *tview.Flex
	resultsLayout       *tview.Flex
	visualizationLayout *tview.Flex

	// Results panels
	summary        *tview.TextView
	summaryTopRow  *tview.Flex // holds a.summary; resized to fit summary content
	clustering     *tview.TextView
	cidrAnalysis   *tview.TextView
	diagnostics    *tview.TextView
	focusableItems []tview.Primitive
	currentFocus   int

	logFile string

	// jsonResult and currentTrie are owned exclusively by the tview UI goroutine
	// (read/written only inside QueueUpdateDraw closures). Background precache
	// goroutines must NOT touch them; they derive single-trie outputs locally.
	jsonResult  *output.JSONOutput
	currentTrie int

	// Shared mutable state protected by mu (accessed from background goroutines).
	mu              sync.Mutex
	requests        []accesslog.Request
	multiTrieResult *output.JSONOutput // Store the full multi-trie result

	// Atomic flags for cross-goroutine signaling (no mutex needed)
	analysisComplete atomic.Bool
	// analysisFailed is set by ShowError. It stops the progress animation, which
	// would otherwise keep looping (analysisComplete is only set on success) and
	// overwrite the error text with its next frame.
	analysisFailed atomic.Bool
	switchingTrie  atomic.Bool
	// shuttingDown is set true when Run() returns (the tview application has
	// stopped). The analysis setters check it first so a late-finishing
	// background analysis cannot QueueUpdateDraw on a stopped application.
	shuttingDown atomic.Bool

	// cfg is the static config the analysis runs with. NewAppFromConfig is the
	// only constructor, so it is never nil; immutable after construction.
	cfg *config.Config

	// trieCache is the single cache of everything derived from the analysis:
	// pre-rendered per-trie texts and the visualization grids. Never nil.
	trieCache *TrieCache
}

// NewAppFromConfig creates a new TUI application from config file
func NewAppFromConfig(cfg *config.Config) *App {
	app := &App{
		app:         tview.NewApplication(),
		pages:       tview.NewPages(),
		cfg:         cfg,
		logFile:     cfg.Static.LogFile,
		currentTrie: 0,
	}

	// Initialize performance optimization components
	app.trieCache = NewTrieCache()

	app.setupUI()
	return app
}

// SetAnalysisResults sets the complete analysis results from StaticFromConfig
func (a *App) SetAnalysisResults(multiResult *output.JSONOutput) {
	if a.shuttingDown.Load() {
		return
	}
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

	// Update UI to show results immediately. The visualization shows its
	// loading placeholder until SetRequestData has precached the traffic grids.
	a.app.QueueUpdateDraw(func() {
		a.displayResults()
		a.visualizationView.updateForCurrentTrie()
		a.updateStatusBar()
		a.pages.SwitchToPage("results")
	})
}

// statusAnalysisFailed is the status-bar text of a failed run.
const statusAnalysisFailed = "[red]Analysis failed![white] | Press 'q' to quit"

// ShowError displays an error message in the TUI and stops the progress animation
func (a *App) ShowError(message string) {
	if a.shuttingDown.Load() {
		return
	}
	// Stop the animation BEFORE queueing the error: the animation loop checks
	// this flag both before queueing a frame and inside the queued closure, so
	// no frame can be drawn over the error text once it is on screen.
	a.analysisFailed.Store(true)
	a.app.QueueUpdateDraw(func() {
		// Update progress view to show error. Error messages are long single
		// lines (wrapped paths, nested causes), so let them wrap instead of
		// being clipped at the right border.
		a.progressView.SetWrap(true).SetWordWrap(true)
		a.progressView.SetText(errorText(message))

		// Update status bar
		a.setStatusBarText(statusAnalysisFailed)

		// Make sure we're on the progress page to show the error
		a.pages.SwitchToPage("progress")
	})
}

// requestData returns the parsed requests handed over by SetRequestData (nil
// until then). a.requests is written by the analysis goroutine and read by the
// UI goroutine and the precache goroutines, so every read goes through a.mu.
func (a *App) requestData() []accesslog.Request {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.requests
}

// errorText renders the error screen shown by ShowError. The message is
// escaped: errors quote config sections ("[static] ...") and paths, and tview
// would otherwise consume anything bracketed as a style tag.
func errorText(message string) string {
	return fmt.Sprintf("[red]Error:[white] %s\n\n[yellow]Press 'q' to quit[white]", tview.Escape(message))
}

// SetRequestData sets the real request data for visualization and pre-caches all
// tries.
//
// Concurrency model: the request scans run on a background goroutine that
// writes nothing but the TrieCache, which guards itself with its own lock and
// publishes one finished trie at a time. The visualization view never leaves
// the UI goroutine; it reads the published grids from the cache when it
// renders, and is told to render again once the precache is done.
func (a *App) SetRequestData(requests []accesslog.Request) {
	if a.shuttingDown.Load() {
		return
	}
	a.mu.Lock()
	a.requests = requests
	multiResult := a.multiTrieResult
	a.mu.Unlock()

	if multiResult != nil {
		go a.precacheRequests(multiResult, requests)
	}
}

// precacheRequests fills the trie cache from the handed-over requests and then
// lets the visualization catch up. The visualization is rendered with the
// results, i.e. before the requests arrive, and the user may already be
// looking at its loading placeholder ('v' pressed right after the results
// appeared): without the refresh it would stay there until the next trie
// switch.
func (a *App) precacheRequests(multiResult *output.JSONOutput, requests []accesslog.Request) {
	a.trieCache.PreCacheAllTries(a, multiResult, requests)

	if a.shuttingDown.Load() {
		return
	}
	a.app.QueueUpdateDraw(a.refreshVisualization)
}

// refreshVisualization re-renders the visualization if it is showing the
// loading placeholder: the grids it was waiting for may have been published
// since. Must run on the UI goroutine.
func (a *App) refreshVisualization() {
	if a.visualizationView.loading {
		a.visualizationView.RenderCached()
	}
}

// setupUI initializes the user interface
func (a *App) setupUI() {
	// Create progress view
	a.progressView = tview.NewTextView().
		SetDynamicColors(true).
		SetScrollable(false).
		SetWrap(false)
	a.progressView.SetBorder(true).SetTitle(" flokbn Analysis Progress ").SetTitleAlign(tview.AlignCenter)

	// Create results view (initially hidden)
	a.resultsView = tview.NewFlex().SetDirection(tview.FlexRow)
	a.setupResultsView()

	// Create status bar. Word wrapping is on so the navigational legend can fold
	// onto a second/third row on narrow terminals instead of being clipped; the
	// row height is sized to the wrapped line count by setStatusBarText.
	a.statusBar = tview.NewTextView().
		SetDynamicColors(true).
		SetWrap(true).
		SetWordWrap(true).
		SetText("[yellow]Starting analysis...[white] | Press 'q' to quit")
	a.statusBar.SetBorder(false)

	// Create main layout
	main := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(a.progressView, 0, 1, true).
		AddItem(a.statusBar, minStatusBarHeight, 0, false)
	a.progressLayout = main

	results := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(a.resultsView, 0, 1, true).
		AddItem(a.statusBar, minStatusBarHeight, 0, false)
	a.resultsLayout = results

	// Create the visualization page. The view only renders what the trie cache
	// holds, so it exists from the start and stays on the UI goroutine.
	a.visualizationView = a.NewVisualizationView()
	a.visualizationLayout = tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(a.visualizationView.GetView(), 0, 1, true).
		AddItem(a.statusBar, minStatusBarHeight, 0, false)

	// Add pages
	a.pages.AddPage("progress", main, true, true)
	a.pages.AddPage("results", results, true, false)
	a.pages.AddPage("visualization", a.visualizationLayout, true, false)

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
			a.showProgressPage()
			return nil
		case 'v', 'V':
			if a.analysisComplete.Load() {
				a.showVisualization()
			}
			return nil
		case 't', 'T':
			if a.analysisComplete.Load() && a.multiTrieResult != nil {
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
				a.visualizationView.ToggleIntensityScale()
				return nil
			}
			switch event.Key() {
			case tcell.KeyLeft:
				a.visualizationView.PrevClusterSet()
				return nil
			case tcell.KeyRight:
				a.visualizationView.NextClusterSet()
				return nil
			case tcell.KeyUp:
				view := a.visualizationView.GetView()
				row, col := view.GetScrollOffset()
				if row > 0 {
					view.ScrollTo(row-1, col)
				}
				return nil
			case tcell.KeyDown:
				view := a.visualizationView.GetView()
				row, col := view.GetScrollOffset()
				view.ScrollTo(row+1, col)
				return nil
			}
		}

		return event
	})

	// Re-fit the status-bar row to the live terminal width before every draw, so
	// the wrapped navigational legend is fully visible and stays correct across
	// terminal resizes. GetInnerRect only reflects the previous frame's width, so
	// reading the screen size here is the authoritative source for word wrapping.
	a.app.SetBeforeDrawFunc(func(screen tcell.Screen) bool {
		a.fitStatusBar(screen)
		return false
	})

	a.app.SetRoot(a.pages, true)
}

// fitStatusBar resizes the status-bar row in every page layout to the height
// needed to word-wrap the current legend at the live screen width. Called from
// the application's before-draw hook (and tolerant of a nil screen so tests that
// drive layouts directly can fall back to the bar's current rect width).
func (a *App) fitStatusBar(screen tcell.Screen) {
	if a.statusBar == nil {
		return
	}
	width := 0
	if screen != nil {
		width, _ = screen.Size()
	}
	if width <= 0 {
		// No screen context (or pre-layout): use the bar's last-known width.
		_, _, width, _ = a.statusBar.GetInnerRect()
	}
	h := statusBarHeight(a.statusBar.GetText(true), width)
	for _, layout := range []*tview.Flex{a.progressLayout, a.resultsLayout, a.visualizationLayout} {
		if layout != nil {
			layout.ResizeItem(a.statusBar, h, 0)
		}
	}
}

// setupResultsView creates the results display layout
func (a *App) setupResultsView() {
	// Summary panel. Scrollable acts as a safety net: on very small terminals
	// the panel may still be shorter than its content, and scrollable means
	// nothing becomes permanently unreachable. The panel is left out of
	// focusableItems below so it never steals tab focus.
	a.summary = tview.NewTextView().
		SetDynamicColors(true).
		SetScrollable(true)
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
	a.summaryTopRow = topRow

	bottomRow := tview.NewFlex().SetDirection(tview.FlexColumn).
		AddItem(a.clustering, 0, 2, false).
		AddItem(a.cidrAnalysis, 0, 1, false).
		AddItem(a.diagnostics, 0, 1, false)

	// Initial height is the minimum; setSummaryText resizes the row to fit the
	// real content once results are available (the summary cannot be built yet
	// because no analysis data exists at setup time).
	a.resultsView.
		AddItem(topRow, minSummaryPanelHeight, 0, false).
		AddItem(bottomRow, 0, 1, false)
}

// summaryPanel min/max fixed heights. The summary currently runs ~11-12 inner
// lines and can grow a little (e.g. the optional UA-whitelist line, or wrapped
// active-filter lists), so we allow headroom up to maxSummaryPanelHeight while
// never collapsing below minSummaryPanelHeight (which still fits the three
// global parse-stat lines plus a couple of trie lines).
const (
	minSummaryPanelHeight = 9
	maxSummaryPanelHeight = 18
	summaryPanelBorders   = 2 // top + bottom border rows
)

// summaryPanelHeight returns the fixed Flex height needed to display the full
// summary text without clipping its top: the visible line count plus the two
// border rows, clamped to a sane min/max. Previously this was hardcoded to 9,
// which only exposed ~7 inner rows and clipped the top three global parse-stat
// lines (Parse Rate / Amount of IPs Read / Parsing Time).
func summaryPanelHeight(text string) int {
	lines := strings.Count(strings.TrimRight(text, "\n"), "\n") + 1
	h := lines + summaryPanelBorders
	if h < minSummaryPanelHeight {
		h = minSummaryPanelHeight
	}
	if h > maxSummaryPanelHeight {
		h = maxSummaryPanelHeight
	}
	return h
}

// setSummaryText sets the Summary panel text and resizes its row to fit, so the
// top global parse stats are always visible. Used everywhere the summary is
// (re)rendered, including per-trie switches, so the height tracks the content.
func (a *App) setSummaryText(text string) {
	a.summary.SetText(text)
	if a.summaryTopRow != nil && a.resultsView != nil {
		a.resultsView.ResizeItem(a.summaryTopRow, summaryPanelHeight(text), 0)
	}
}

// status-bar fixed-height bounds. The bar normally needs a single row, but the
// full navigational legend ("Tab/Shift+Tab: panels ... 'q': quit") is long and
// must word-wrap onto a second (or, on very narrow terminals, third) row rather
// than be clipped. We grow only as far as the wrapped legend needs and never
// past maxStatusBarHeight so the main results/visualization area is not eaten
// on normal-width terminals (where the legend fits on one row).
const (
	minStatusBarHeight = 1
	maxStatusBarHeight = 3
)

// statusBarHeight returns the row height needed to render text word-wrapped to
// the given inner width, clamped to [minStatusBarHeight, maxStatusBarHeight].
// tview.WordWrap is the same wrapper the TextView uses to draw, and it is
// color-tag aware, so the count matches what is actually rendered. A width <= 0
// (no layout yet) falls back to the minimum height.
func statusBarHeight(text string, width int) int {
	if width <= 0 {
		return minStatusBarHeight
	}
	h := len(tview.WordWrap(text, width))
	if h < minStatusBarHeight {
		h = minStatusBarHeight
	}
	if h > maxStatusBarHeight {
		h = maxStatusBarHeight
	}
	return h
}

// setStatusBarText sets the status-bar text and resizes its row to fit the
// wrapped legend, mirroring the setSummaryText content-fit pattern. The
// before-draw hook re-fits at the live width on every frame; this best-effort
// resize keeps the height correct for callers that draw without the event loop
// (e.g. tests) by using the bar's last-known width.
func (a *App) setStatusBarText(text string) {
	a.statusBar.SetText(text)
	a.fitStatusBar(nil)
}

// Run starts the TUI application
func (a *App) Run() error {
	// Analysis is now done in CLI layer before TUI starts
	// Just start the progress animation until results arrive
	go a.animateProgress()

	// Run the TUI. Once it returns the application is stopped, so flag shutdown
	// to make the analysis setters no-ops (defends against a background analysis
	// finishing after the user quits).
	err := a.app.Run()
	a.shuttingDown.Store(true)
	return err
}

// progressTick is the frame interval of the progress animation.
const progressTick = 200 * time.Millisecond

// showProgressPage switches to the progress page ('p' key). Must run on the UI
// goroutine. A failed run keeps its failure status: the page then shows the
// error text, not a running analysis.
func (a *App) showProgressPage() {
	a.pages.SwitchToPage("progress")
	if a.analysisFailed.Load() {
		a.setStatusBarText(statusAnalysisFailed)
		return
	}
	a.setStatusBarText("[yellow]Analysis in progress...[white] | 'r' for results, 'q' to quit")
}

// progressAnimationDone reports whether the progress animation must stop: the
// analysis finished (results or error), or the application is shutting down.
func (a *App) progressAnimationDone() bool {
	return a.analysisComplete.Load() || a.analysisFailed.Load() || a.shuttingDown.Load()
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

	for !a.progressAnimationDone() {
		stage := stages[stageIndex%len(stages)]
		dotStr := strings.Repeat(".", dots%4)

		content := a.progressFrameText(stage, dotStr)

		a.app.QueueUpdateDraw(func() {
			// Re-check on the UI goroutine: the analysis may have finished
			// between the loop condition and this frame being drawn, and a
			// frame queued behind ShowError must not replace the error text.
			if a.progressAnimationDone() {
				return
			}
			a.progressView.SetText(content)
		})

		time.Sleep(progressTick)
		dots++

		if dots%20 == 0 {
			stageIndex++
		}
	}
}

// progressFrameText renders one frame of the progress animation: the current
// stage line (which carries its own style tags) plus the run's static facts.
func (a *App) progressFrameText(stage, dotStr string) string {
	// Count cluster sets and CIDR ranges from config
	var clusterSets, cidrRanges int
	for _, trieConfig := range a.cfg.StaticTries {
		clusterSets += len(trieConfig.ClusterArgSets)
		cidrRanges += len(trieConfig.CIDRRanges)
	}

	return fmt.Sprintf(`
[white::b]flokbn Log Analysis[white::-]

%s%s

[dim]Log file:[white] %s
[dim]Cluster sets:[white] %d
[dim]CIDR ranges:[white] %d

[dim]Press 'q' to quit[white]
`, stage, dotStr, tview.Escape(a.logFile), clusterSets, cidrRanges)
}

// nextTrie cycles to the next trie (async optimized)
func (a *App) nextTrie() {
	a.mu.Lock()
	canSwitch := a.multiTrieResult != nil && len(a.multiTrieResult.Tries) > 1
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
			a.visualizationView.updateForCurrentTrie()
		})
		return
	}

	// Not cached yet: precache this specific trie ahead of the background
	// precache. PreCacheSingleTrie locks ftc.mu internally; all reads/writes of
	// the UI-owned currentTrie/jsonResult happen inside QueueUpdateDraw so the
	// tview UI goroutine remains their sole owner.
	go func() {
		if a.trieCache.PreCacheSingleTrie(a, newTrieIndex, a.multiTrieResult, a.requestData()) {
			a.app.QueueUpdateDraw(func() {
				// Re-render only if the user is still on this trie.
				if a.currentTrie != newTrieIndex {
					return
				}
				// Re-try with newly cached data
				if cachedData, hit := a.trieCache.GetTrieOutput(newTrieIndex); hit && cachedData != nil {
					a.jsonResult = cachedData
					a.displayResultsFromTrieCache(newTrieIndex)
					a.visualizationView.updateForCurrentTrie()
				}
			})
		}
	}()

	// Meanwhile show the trie right away: the panel texts are cheap to build on
	// the UI goroutine, and the visualization shows its loading placeholder
	// until the precache above has published the trie's grids.
	a.app.QueueUpdateDraw(func() {
		a.currentTrie = newTrieIndex
		newTrieData := a.singleTrieOutput(newTrieIndex)
		if newTrieData != nil {
			a.jsonResult = newTrieData
			a.displayResults()
			a.updateStatusBar()
			a.visualizationView.updateForCurrentTrie()
		}
	})
}

// displayResults populates the results view with analysis data. jsonResult is
// only ever derived from multiTrieResult (singleTrieOutput), so a non-nil
// jsonResult implies the multi-trie result the panel builders read.
func (a *App) displayResults() {
	if a.jsonResult == nil {
		return
	}
	a.displayCachedResults()
}

// displayCachedResults shows the current trie's pre-rendered panels, building
// and caching all four on first display.
func (a *App) displayCachedResults() {
	summary, clustering, cidr, diagnostics, ok := a.trieCache.GetPreRenderedTexts(a.currentTrie)
	if !ok {
		summary = a.buildSummaryText()
		clustering = a.buildClusteringText()
		cidr = a.buildCidrAnalysisText()
		diagnostics = a.buildDiagnosticsText()
		a.trieCache.SetPreRenderedTexts(a.currentTrie, summary, clustering, cidr, diagnostics)
	}
	a.setSummaryText(summary)
	a.clustering.SetText(clustering)
	a.cidrAnalysis.SetText(cidr)
	a.diagnostics.SetText(diagnostics)
}

// buildClusteringText creates the clustering results text for the current trie.
func (a *App) buildClusteringText() string {
	return a.buildClusteringTextFor(a.jsonResult)
}

// buildClusteringTextFor creates the clustering results text from an explicit
// single-trie output, so callers (e.g. the background precache) need not mutate
// shared App state to render a non-current trie.
func (a *App) buildClusteringTextFor(result *output.JSONOutput) string {
	var clusteringText strings.Builder
	clusteringText.WriteString("[white::b]Detected Threats[white::-]\n\n")

	for i, cluster := range result.Clustering.Data {
		clusteringText.WriteString(fmt.Sprintf("[yellow]Set %d[white] (%s)\n",
			i+1, output.FormatClusterParameters(cluster.Parameters)))

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

// buildCidrAnalysisText creates the CIDR analysis text for the current trie.
func (a *App) buildCidrAnalysisText() string {
	return a.buildCidrAnalysisTextFor(a.jsonResult)
}

// buildCidrAnalysisTextFor creates the CIDR analysis text from an explicit
// single-trie output (see buildClusteringTextFor).
func (a *App) buildCidrAnalysisTextFor(result *output.JSONOutput) string {
	var cidrText strings.Builder
	cidrText.WriteString("[white::b]Range Analysis[white::-]\n\n")

	if len(result.CIDRAnalysis.Data) > 0 {
		for _, cidr := range result.CIDRAnalysis.Data {
			cidrText.WriteString(fmt.Sprintf("[cyan]%s[white]\n", cidr.CIDR))
			cidrText.WriteString(fmt.Sprintf("  Requests: [yellow]%s[white] (%.2f%%)\n\n",
				output.FormatNumber(int(cidr.Requests)), cidr.Percentage))
		}
	} else {
		cidrText.WriteString("[dim]No specific ranges analyzed[white]")
	}

	return cidrText.String()
}

// buildDiagnosticsText creates the diagnostics text for the current trie.
func (a *App) buildDiagnosticsText() string {
	return a.buildDiagnosticsTextFor(a.jsonResult)
}

// buildDiagnosticsTextFor creates the diagnostics text from an explicit
// single-trie output (see buildClusteringTextFor).
func (a *App) buildDiagnosticsTextFor(result *output.JSONOutput) string {
	var diagText strings.Builder
	diagText.WriteString("[white::b]Diagnostics[white::-]\n\n")

	// Filter out info messages
	var realWarnings []output.Warning
	for _, warning := range result.Warnings {
		if warning.Type != "info" {
			realWarnings = append(realWarnings, warning)
		}
	}

	if len(realWarnings) > 0 {
		diagText.WriteString("[yellow]Warnings:[white]\n")
		for _, warning := range realWarnings {
			diagText.WriteString(fmt.Sprintf("  • %s\n", tview.Escape(warning.Message)))
		}
		diagText.WriteString("\n")
	}

	if len(result.Errors) > 0 {
		diagText.WriteString("[red]Errors:[white]\n")
		for _, err := range result.Errors {
			diagText.WriteString(fmt.Sprintf("  • %s\n", tview.Escape(err.Message)))
		}
	} else if len(realWarnings) == 0 {
		diagText.WriteString("[green]✓ No issues detected[white]")
	}

	return diagText.String()
}

// buildSummaryText creates the summary text with fixed and trie-specific stats
// for the current trie.
func (a *App) buildSummaryText() string {
	return a.buildSummaryTextFor(a.currentTrie)
}

// buildSummaryTextFor creates the summary text for an explicit trie index, so
// the background precache can render a non-current trie without mutating
// shared App state. trieIndex must be a valid index into multiTrieResult.Tries
// (every caller derives it together with that trie's single-trie output).
func (a *App) buildSummaryTextFor(trieIndex int) string {
	var summaryText strings.Builder
	summaryText.WriteString("[white::b]Analysis Summary[white::-]\n")

	// Fixed stats (global, not trie-specific) - always show these first
	general := a.multiTrieResult.General
	summaryText.WriteString(fmt.Sprintf("[dim]Parse Rate:[white] %s req/sec\n",
		output.FormatNumber(int(general.Parsing.RatePerSecond))))
	summaryText.WriteString(fmt.Sprintf("[dim]Amount of IPs Read:[white] %s\n",
		output.FormatNumber(general.TotalRequests)))
	summaryText.WriteString(fmt.Sprintf("[dim]Parsing Time:[white] %dms\n\n",
		general.Parsing.DurationMS))

	// Trie-specific stats (show below the fixed stats). Read multiTrieResult
	// directly: it has the Parameters and Stats that the single-trie output
	// conversion does not carry.
	trieData := a.multiTrieResult.Tries[trieIndex]

	// Trie names, regex filters, paths and messages are user data and are
	// escaped wherever they are rendered: tview consumes anything that
	// looks like "[word]" as a style tag (useragentRegex = "[Bb]ot" was
	// displayed as "ot").
	summaryText.WriteString(fmt.Sprintf("[white::b]Trie: %s[white::-]\n", tview.Escape(trieData.Name)))

	// Active filters
	summaryText.WriteString("[dim]Active Filters:[white] ")
	filters := output.ActiveFilters(trieData.Parameters, a.multiTrieResult.GlobalFilters)
	if len(filters) > 0 {
		summaryText.WriteString(tview.Escape(strings.Join(filters, ", ")))
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

	return summaryText.String()
}

// Active-filter rendering lives in output.ActiveFilters, shared with the CLI
// plain renderer so the two never drift (and so the global whitelists are
// always listed, not just the per-trie TrieParameters).

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
	if a.analysisFailed.Load() {
		a.setStatusBarText(statusAnalysisFailed)
		return
	}
	if !a.analysisComplete.Load() {
		a.setStatusBarText("[yellow]Analysis in progress...[white] | 'r' for results, 'q' to quit")
		return
	}

	frontPageName, _ := a.pages.GetFrontPage()

	switch frontPageName {
	case "visualization":
		if a.visualizationView.totalClusterSets > 0 {
			a.setStatusBarText(fmt.Sprintf("[green]Visualization mode[white] | Set %d/%d | ←→: change cluster set, ↑↓: scroll, 'r': results, 'v': visualization, 'q': quit",
				a.visualizationView.currentClusterSet+1, a.visualizationView.totalClusterSets))
		} else {
			a.setStatusBarText("[green]Visualization mode[white] | ↑↓: scroll, 'r': results, 'q': quit")
		}
	default:
		panelNames := []string{"Clustering Results", "CIDR Analysis", "Diagnostics"}
		currentPanel := panelNames[a.currentFocus]

		// analysisComplete (checked above) is only set once multiTrieResult
		// is stored, so it is non-nil here.
		if len(a.multiTrieResult.Tries) > 1 {
			// Multi-trie mode
			if a.currentTrie >= len(a.multiTrieResult.Tries) {
				a.currentTrie = 0
			}
			trieName := a.multiTrieResult.Tries[a.currentTrie].Name
			a.setStatusBarText(fmt.Sprintf("[green]Analysis complete![white] | [yellow]%s[white] focused | [cyan]%s (%d/%d)[white] | Tab/Shift+Tab: panels, 't': next trie, ↑↓: scroll, 'v': visualization, 'p': progress, 'q': quit",
				currentPanel, tview.Escape(trieName), a.currentTrie+1, len(a.multiTrieResult.Tries)))
		} else {
			// Single trie
			a.setStatusBarText(fmt.Sprintf("[green]Analysis complete![white] | [yellow]%s[white] focused | Tab/Shift+Tab: panels, ↑↓: scroll, 'v': visualization, 'p': progress, 'q': quit", currentPanel))
		}
	}
}

// showVisualization switches to the visualization view
func (a *App) showVisualization() {
	// The heatmap is rendered whenever a trie is displayed. If that was before
	// the request precache had published the trie's grids, render again: they
	// may be there by now (the precache refreshes only once every trie is done).
	a.refreshVisualization()

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
	// Get pre-rendered texts from cache
	summaryText, clusteringText, cidrText, diagnosticsText, exists := a.trieCache.GetPreRenderedTexts(trieIndex)
	if !exists {
		// Fallback to normal display if cache miss
		a.displayResults()
		return
	}

	// Set pre-rendered content directly - no processing required
	a.setSummaryText(summaryText)
	a.clustering.SetText(clusteringText)
	a.cidrAnalysis.SetText(cidrText)
	a.diagnostics.SetText(diagnosticsText)
}
