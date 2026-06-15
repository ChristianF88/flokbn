package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/ChristianF88/flokbn/config"
	"github.com/ChristianF88/flokbn/output"
	"github.com/gdamore/tcell/v2"
)

// newResultsViewTestApp builds an App through the real construction path
// (NewAppFromConfig -> setupUI -> setupResultsView) with a populated
// multiTrieResult, sets the live summary text, and returns the app ready to
// be rendered.
func newResultsViewTestApp(t *testing.T) *App {
	t.Helper()

	jo := output.NewJSONOutput("static", time.Time{})
	jo.General.Parsing.RatePerSecond = 1373322
	jo.General.TotalRequests = 1046826
	jo.General.Parsing.DurationMS = 762
	jo.Tries = []output.TrieResult{{
		Name: "cli_trie",
		Stats: output.TrieStats{
			TotalRequestsAfterFiltering: 1046826,
			InsertTimeMS:                316,
		},
	}}

	cfg := &config.Config{Static: &config.StaticConfig{}}
	a := NewAppFromConfig(cfg, "")
	a.multiTrieResult = jo
	a.currentTrie = 0

	// Mirror the live display path which sets the summary text and resizes the
	// panel to fit its content.
	a.setSummaryText(a.buildSummaryText())

	return a
}

// renderSummaryRegion lays out the results Flex on a tcell SimulationScreen of
// the given size, draws it, and returns the reconstructed text of the rows
// occupied by the Summary panel (the top fixed-height row of resultsView).
func renderSummaryRegion(t *testing.T, a *App, width, height int) string {
	t.Helper()

	sim := tcell.NewSimulationScreen("UTF-8")
	if err := sim.Init(); err != nil {
		t.Fatalf("sim.Init: %v", err)
	}
	defer sim.Fini()
	sim.SetSize(width, height)

	// Drive the layout deterministically without the event loop: place the
	// results Flex over the whole screen and draw it once.
	a.resultsView.SetRect(0, 0, width, height)
	a.resultsView.Draw(sim)
	sim.Show()

	cells, w, h := sim.GetContents()

	// Reconstruct the full screen as lines so we can locate the summary text
	// regardless of the exact fixed-height row boundary.
	var b strings.Builder
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			c := cells[y*w+x]
			if len(c.Runes) > 0 && c.Runes[0] != 0 {
				b.WriteRune(c.Runes[0])
			} else {
				b.WriteRune(' ')
			}
		}
		b.WriteRune('\n')
	}
	return b.String()
}

// TestSummaryPanelShowsGlobalParseStats is the regression guard for the
// Summary-panel top-clipping bug: with the panel sized correctly the three
// global parse stats (Parse Rate / Amount of IPs Read / Parsing Time) must be
// visible on screen after layout+draw at a realistic terminal size.
//
// With the old fixed height of 9 (plus a non-scrollable, bordered TextView that
// only exposes ~7 inner rows) the ~11-line summary overflowed and the top three
// stat lines were never drawn.
func TestSummaryPanelShowsGlobalParseStats(t *testing.T) {
	a := newResultsViewTestApp(t)

	screen := renderSummaryRegion(t, a, 160, 40)

	for _, want := range []string{
		"Parse Rate:",
		"Amount of IPs Read:",
		"Parsing Time:",
	} {
		if !strings.Contains(screen, want) {
			t.Errorf("rendered summary panel is missing %q (top content clipped)\n--- screen ---\n%s", want, screen)
		}
	}
}

// TestSummaryPanelHeightFitsContent is a pure-function guard on the sizing
// logic that replaced the hardcoded height of 9: the panel height must be at
// least the summary's visible line count plus the two border rows, so every
// content line (including the top three global stats) has a row to render in.
func TestSummaryPanelHeightFitsContent(t *testing.T) {
	a := newResultsViewTestApp(t)

	text := a.buildSummaryText()
	// Visible line count (a trailing newline does not add a visible line).
	lines := strings.Count(strings.TrimRight(text, "\n"), "\n") + 1

	got := summaryPanelHeight(text)
	wantInner := got - summaryPanelBorders
	if wantInner < lines {
		t.Errorf("summaryPanelHeight(%d-line text) = %d -> %d inner rows, need >= %d (top content would clip)\ntext:\n%s",
			lines, got, wantInner, lines, text)
	}

	// Sanity: the old hardcoded 9 (7 inner rows) must NOT have fit this content,
	// proving the test would have caught the original bug.
	if 9-summaryPanelBorders >= lines {
		t.Fatalf("guard is vacuous: old height 9 already fit %d lines; bug could not reproduce", lines)
	}
}

// TestSummaryPanelDrawsFullBorderBelowContent confirms via the SimulationScreen
// that the Summary panel's closing bottom border is drawn BELOW the last
// content line ("Analysis Time"), i.e. nothing was pushed off the top: with the
// old height-9 layout the top stats were clipped and the border closed early.
func TestSummaryPanelDrawsFullBorderBelowContent(t *testing.T) {
	a := newResultsViewTestApp(t)

	screen := renderSummaryRegion(t, a, 160, 40)
	rows := strings.Split(screen, "\n")

	rowOf := func(substr string) int {
		for i, r := range rows {
			if strings.Contains(r, substr) {
				return i
			}
		}
		return -1
	}

	// Panel landmarks, top to bottom: the top border row, the first global
	// stat line, and the last content line.
	top := rowOf(" Summary ")
	parseRate := rowOf("Parse Rate:")
	lastLine := rowOf("Analysis Time:")
	// The bottom border row is the first all-box-drawing row after lastLine.
	bottomBorder := -1
	for i := lastLine + 1; i < len(rows) && i < top+maxSummaryPanelHeight+1; i++ {
		if strings.Contains(rows[i], "└") {
			bottomBorder = i
			break
		}
	}

	if top < 0 || parseRate < 0 || lastLine < 0 || bottomBorder < 0 {
		t.Fatalf("could not locate panel landmarks: top=%d parseRate=%d lastLine=%d bottomBorder=%d\n%s",
			top, parseRate, lastLine, bottomBorder, screen)
	}
	if !(top < parseRate && parseRate < lastLine && lastLine < bottomBorder) {
		t.Errorf("panel rows out of order (content clipped): top=%d parseRate=%d lastLine=%d bottomBorder=%d\n%s",
			top, parseRate, lastLine, bottomBorder, screen)
	}
}
