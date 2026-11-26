package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/ChristianF88/flokbn/config"
	"github.com/gdamore/tcell/v2"
)

// startSimApp runs a's event loop (via Run, so the progress animation is
// started exactly as in production) on a headless simulation screen and
// returns a stop function that shuts it down and waits for Run to return.
func startSimApp(t *testing.T, a *App) (stop func()) {
	t.Helper()
	sim := tcell.NewSimulationScreen("UTF-8")
	if err := sim.Init(); err != nil {
		t.Fatalf("sim.Init: %v", err)
	}
	sim.SetSize(120, 40)
	a.app.SetScreen(sim)

	runErr := make(chan error, 1)
	go func() { runErr <- a.Run() }()

	return func() {
		a.app.Stop()
		select {
		case err := <-runErr:
			if err != nil {
				t.Fatalf("app.Run: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("app.Run did not return after Stop")
		}
	}
}

// progressText reads the progress view's raw text on the UI goroutine.
func (a *App) progressText() string {
	var text string
	a.app.QueueUpdate(func() { text = a.progressView.GetText(false) })
	return text
}

// statusText reads the status bar's raw text on the UI goroutine.
func (a *App) statusText() string {
	var text string
	a.app.QueueUpdate(func() { text = a.statusBar.GetText(false) })
	return text
}

// TestShowErrorSurvivesProgressAnimation is the regression test for the lost
// error screen: a failed analysis calls ShowError, but the progress animation
// used to keep looping (it only stopped on analysisComplete, which is set on
// success only) and overwrote the error text with the next animation frame
// within one tick. The error must stay on screen for as long as the TUI runs.
func TestShowErrorSurvivesProgressAnimation(t *testing.T) {
	a := NewAppFromConfig(&config.Config{Static: &config.StaticConfig{LogFile: "access.log"}})
	stop := startSimApp(t, a)
	defer stop()

	// The animation is running: wait for its first frame.
	waitFor(t, func() bool { return strings.Contains(a.progressText(), "flokbn Log Analysis") }, 5*time.Second)

	a.ShowError("Analysis failed: boom")

	if got := a.progressText(); !strings.Contains(got, "Analysis failed: boom") {
		t.Fatalf("progress view right after ShowError = %q, want the error message", got)
	}

	// Several animation ticks later the error must still be displayed.
	time.Sleep(3 * progressTick)

	if got := a.progressText(); !strings.Contains(got, "Analysis failed: boom") {
		t.Errorf("progress view %v after ShowError = %q, want the error message to persist "+
			"(the progress animation overwrote it)", 3*progressTick, got)
	}
	if got := a.statusText(); !strings.Contains(got, "Analysis failed") {
		t.Errorf("status bar = %q, want it to keep reporting the failure", got)
	}

	// Returning to the progress page must not relabel a failed run as running.
	a.app.QueueUpdateDraw(func() { a.showProgressPage() })
	if got := a.statusText(); !strings.Contains(got, "Analysis failed") {
		t.Errorf("status bar after 'p' = %q, want it to keep reporting the failure", got)
	}
}
