package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/ChristianF88/flokbn/config"
	"github.com/ChristianF88/flokbn/output"
	"github.com/rivo/tview"
)

// visibleText returns what a dynamic-colors TextView actually displays for s:
// style tags are consumed by tview's own parser, escaped brackets are restored.
// Using the real TextView (not a hand-rolled stripper) is the point - the bug
// was tview swallowing user data that merely looks like a tag.
func visibleText(s string) string {
	tv := tview.NewTextView().SetDynamicColors(true)
	tv.SetText(s)
	return tv.GetText(true)
}

// escapeTestApp builds an App whose single trie carries bracketed user data in
// every field the TUI renders: trie name, regex filters, log file, warning and
// error messages.
func escapeTestApp() *App {
	uaRegex := "[Bb]ot"
	endpointRegex := "^/wp-[a-z]+"

	multi := output.NewJSONOutput("static", time.Now())
	multi.General.LogFile = "/var/log/[prod]/access.log"
	multi.Tries = []output.TrieResult{
		{
			Name: "bots[red]",
			Parameters: output.TrieParameters{
				UserAgentRegex: &uaRegex,
				EndpointRegex:  &endpointRegex,
			},
		},
		{Name: "second"},
	}
	multi.AddWarning("config", "section [static] has no [red]cidrRanges[white]", 0)
	multi.AddError("heatmap", "cannot write [black]/tmp/plot[1].html", 1)

	return &App{cfg: &config.Config{}, multiTrieResult: multi, trieCache: NewTrieCache()}
}

// TestSummaryEscapesUserData is the regression test for swallowed style tags:
// `useragentRegex = "[Bb]ot"` was displayed as "ot" because tview parsed
// "[Bb]" as a style tag.
func TestSummaryEscapesUserData(t *testing.T) {
	a := escapeTestApp()

	got := visibleText(a.buildSummaryTextFor(0))

	for _, want := range []string{
		"Trie: bots[red]",
		"User-Agent: [Bb]ot",
		"Endpoint: ^/wp-[a-z]+",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("summary is missing %q (tview consumed it as a style tag)\nvisible text:\n%s", want, got)
		}
	}
}

// TestDiagnosticsEscapesUserData: warning and error messages quote config
// sections and paths, which routinely contain brackets.
func TestDiagnosticsEscapesUserData(t *testing.T) {
	a := escapeTestApp()

	got := visibleText(a.buildDiagnosticsTextFor(a.singleTrieOutput(0)))

	for _, want := range []string{
		"section [static] has no [red]cidrRanges[white]",
		"cannot write [black]/tmp/plot[1].html",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("diagnostics are missing %q (tview consumed it as a style tag)\nvisible text:\n%s", want, got)
		}
	}
}

// TestProgressFrameEscapesLogFile: the log file path is shown on every
// progress frame.
func TestProgressFrameEscapesLogFile(t *testing.T) {
	a := &App{cfg: &config.Config{}, logFile: "/var/log/[prod]/access.log"}

	got := visibleText(a.progressFrameText("[yellow]>[white] Parsing", ".."))

	if want := "Log file: /var/log/[prod]/access.log"; !strings.Contains(got, want) {
		t.Errorf("progress frame is missing %q\nvisible text:\n%s", want, got)
	}
}

// TestErrorTextEscapesMessage: error messages name config sections such as
// "[static]", which must not vanish from the error screen.
func TestErrorTextEscapesMessage(t *testing.T) {
	got := visibleText(errorText("[static] plotPath directory \"/x\" does not exist"))

	if want := "Error: [static] plotPath directory \"/x\" does not exist"; !strings.Contains(got, want) {
		t.Errorf("error text is missing %q\nvisible text:\n%s", want, got)
	}
}

// TestStatusBarEscapesTrieName: the multi-trie status bar shows the trie name.
func TestStatusBarEscapesTrieName(t *testing.T) {
	a := escapeTestApp()
	a.pages = tview.NewPages()
	a.statusBar = tview.NewTextView().SetDynamicColors(true)
	a.analysisComplete.Store(true)

	a.updateStatusBar()

	got := a.statusBar.GetText(true)
	if want := "bots[red] (1/2)"; !strings.Contains(got, want) {
		t.Errorf("status bar is missing %q\nvisible text:\n%s", want, got)
	}
}
