package cli

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/ChristianF88/flokbn/ingestor"
	"github.com/ChristianF88/flokbn/output"
)

// tuiHeatmap writes the plotPath heatmap of a --tui run.
//
// The TUI path used to drop plotPath silently: `flokbn static --config x.toml
// --tui` with `plotPath` set produced no heatmap and said nothing. The
// heatmap is now written like in the other output modes, with two
// TUI-specific constraints:
//
//   - Nothing may be printed while tview owns the terminal, so the file is
//     written quietly (output.WriteHeatmap) and the notice is held back until
//     report is called after the TUI has exited.
//   - The analysis goroutine outlives the TUI when the user quits early. mu
//     makes write and report mutually exclusive: report waits for a write that
//     is in flight (so the process never exits halfway through it), and a
//     write that starts after the TUI was cancelled is skipped.
type tuiHeatmap struct {
	mu     sync.Mutex
	notice string
}

// write generates the heatmap at plotPath from the parsed requests. It is a
// no-op without a plotPath or request data, or once ctx is cancelled (the user
// quit). The outcome is recorded on result exactly as in the non-TUI path: an
// "info" warning on success, a "heatmap" error on failure - the latter shows up
// in the TUI's Diagnostics panel.
func (h *tuiHeatmap) write(ctx context.Context, plotPath string, requests []ingestor.Request, result *output.JSONOutput) {
	if plotPath == "" || requests == nil {
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	if ctx.Err() != nil {
		return
	}

	plotStart := time.Now()
	if err := output.WriteHeatmap(requests, plotPath); err != nil {
		result.AddError("heatmap", fmt.Sprintf("failed to generate heatmap: %v", err), 1)
		h.notice = fmt.Sprintf("Heatmap not written: %v", err)
		return
	}
	result.AddWarning("info", fmt.Sprintf("Heatmap generated in %v at %s", time.Since(plotStart), plotPath), 0)
	h.notice = fmt.Sprintf("Heatmap saved to %s", plotPath)
}

// report prints the outcome of write to w (stderr). Call it only after the TUI
// has released the terminal. It blocks until a write in flight has finished.
func (h *tuiHeatmap) report(w io.Writer) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.notice != "" {
		fmt.Fprintln(w, h.notice)
	}
}
