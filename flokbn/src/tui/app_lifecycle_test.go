package tui

import (
	"testing"
	"time"

	"github.com/ChristianF88/flokbn/ingestor"
	"github.com/ChristianF88/flokbn/output"
)

// TestApp_SettersNoOpAfterShutdown is the TUI-lifecycle regression test
// (URGENT-14 finding #3): once the application has stopped (shuttingDown set,
// as Run() does when app.Run returns), the analysis setters must be no-ops.
//
// The App here has a nil tview.Application; without the shuttingDown guard each
// setter would call a.app.QueueUpdateDraw and panic on the nil pointer. The
// guard makes them return before touching a.app, so the test both proves the
// no-op and that a late-finishing background analysis can never drive a stopped
// application. analysisComplete must also stay false.
func TestApp_SettersNoOpAfterShutdown(t *testing.T) {
	a := &App{} // nil app; setters must not reach it after shutdown
	a.shuttingDown.Store(true)

	// Build a minimal valid analysis result so the no-op is attributable to the
	// shutdown guard, not to a nil-result early return.
	multi := output.NewJSONOutput("static", time.Now())
	multi.Tries = []output.TrieResult{{Name: "trie-a"}}

	// None of these may panic (which they would on the nil a.app) or mutate
	// state once shuttingDown is set.
	a.SetAnalysisResults(multi)
	a.ShowError("should be ignored")
	a.SetRequestData([]ingestor.Request{})

	if a.analysisComplete.Load() {
		t.Error("analysisComplete = true, want false (setters must no-op after shutdown)")
	}
	if a.multiTrieResult != nil {
		t.Error("multiTrieResult was set, want nil (SetAnalysisResults must no-op after shutdown)")
	}
	if a.requests != nil {
		t.Error("requests was set, want nil (SetRequestData must no-op after shutdown)")
	}
}
