package tui

import (
	"strings"
	"testing"

	"github.com/ChristianF88/flokbn/config"
	"github.com/gdamore/tcell/v2"
)

// longStatusLegend is the worst-case (longest) status-bar text: the multi-trie
// "Analysis complete!" line including the full navigational legend. On a narrow
// terminal it must word-wrap onto extra rows rather than be clipped, so the help
// tokens (Tab, the per-key hints, 'q': quit) stay visible.
const longStatusLegend = "[green]Analysis complete![white] | [yellow]Clustering Results[white] focused | [cyan]t1_baseline (1/4)[white] | Tab/Shift+Tab: panels, 't': next trie, ↑↓: scroll, 'v': visualization, 'p': progress, 'q': quit"

// renderStatusBarRegion lays out the results page Flex (which contains the
// shared status bar) on a SimulationScreen of the given size, draws it twice so
// the width-aware status-bar height settles (the first draw establishes the
// inner width that fitStatusBar reads), and returns the reconstructed full
// screen text.
//
// Two draws + an explicit fit mirror the real run loop: SetBeforeDrawFunc
// re-fits the bar to the live width before every frame. Here we drive the layout
// directly (no event loop), so we fit against the simulation width ourselves.
func renderStatusBarRegion(t *testing.T, a *App, width, height int) string {
	t.Helper()

	sim := tcell.NewSimulationScreen("UTF-8")
	if err := sim.Init(); err != nil {
		t.Fatalf("sim.Init: %v", err)
	}
	defer sim.Fini()
	sim.SetSize(width, height)

	// Use the same results-page Flex the app shows so the status bar is laid out
	// exactly as in production (resultsView on top, status bar fixed-height row
	// below).
	a.resultsLayout.SetRect(0, 0, width, height)

	// First draw establishes the status bar's inner width; the before-draw hook
	// in production reads the screen width directly, so emulate that here.
	a.resultsLayout.Draw(sim)
	a.fitStatusBar(sim)
	a.resultsLayout.Draw(sim)
	sim.Show()

	cells, w, h := sim.GetContents()
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

// TestStatusBarLegendWrapsOnNarrowTerminal is the regression guard for the
// status-bar clipping bug: with the old single-row, fixed-height-1 layout the
// long navigational legend was truncated to one line, so the trailing tokens
// ("'q': quit", "visualization", etc.) were never drawn on narrow terminals.
//
// With word wrapping enabled and the row sized to the wrapped line count, the
// full legend must appear at narrow widths.
func TestStatusBarLegendWrapsOnNarrowTerminal(t *testing.T) {
	cfg := &config.Config{Static: &config.StaticConfig{}}

	// Navigational tokens that live at the END of the legend and were clipped by
	// the old height-1 / no-wrap layout. The screen is whitespace-normalized
	// before searching (wrapping inserts row breaks and trailing padding), so we
	// choose tokens that do not themselves straddle a wrap boundary.
	wantTokens := []string{"next trie", "scroll", "visualization", "progress", "'q': quit"}

	// collapse turns the multi-row rendered screen into a single normalized line
	// (runs of whitespace, including the row breaks introduced by wrapping,
	// become a single space) so a legend split across rows still matches.
	collapse := func(s string) string { return strings.Join(strings.Fields(s), " ") }

	for _, sz := range []struct{ w, h int }{
		{60, 20},
		{80, 24},
	} {
		a := NewAppFromConfig(cfg, "")
		a.setStatusBarText(longStatusLegend)

		screen := renderStatusBarRegion(t, a, sz.w, sz.h)
		flat := collapse(screen)

		for _, tok := range wantTokens {
			if !strings.Contains(flat, tok) {
				t.Errorf("at %dx%d: status-bar legend missing %q (clipped, did not wrap)\n--- screen ---\n%s",
					sz.w, sz.h, tok, screen)
			}
		}
	}
}

// TestStatusBarHeightFitsLegend is a pure-function guard on the sizing logic: at
// narrow widths the bar must grow to the wrapped line count (capped at
// maxStatusBarHeight), and at wide widths it must collapse back to a single row
// so the main results/visualization area is not wasted.
func TestStatusBarHeightFitsLegend(t *testing.T) {
	// Narrow: the legend wraps and the bar must be taller than one row.
	if got := statusBarHeight(longStatusLegend, 60); got <= minStatusBarHeight {
		t.Errorf("statusBarHeight(legend, 60) = %d; want > %d (legend must wrap on a narrow terminal)", got, minStatusBarHeight)
	}
	if got := statusBarHeight(longStatusLegend, 60); got > maxStatusBarHeight {
		t.Errorf("statusBarHeight(legend, 60) = %d; want <= %d (height must be capped)", got, maxStatusBarHeight)
	}

	// Wide: the legend fits on one line, so the bar must not steal extra rows.
	if got := statusBarHeight(longStatusLegend, 240); got != minStatusBarHeight {
		t.Errorf("statusBarHeight(legend, 240) = %d; want %d (legend fits one line on a wide terminal)", got, minStatusBarHeight)
	}

	// No layout yet (width 0): fall back to the minimum height.
	if got := statusBarHeight(longStatusLegend, 0); got != minStatusBarHeight {
		t.Errorf("statusBarHeight(legend, 0) = %d; want %d (no-layout fallback)", got, minStatusBarHeight)
	}
}
