package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/ChristianF88/flokbn/config"
	"github.com/ChristianF88/flokbn/output"
)

// These tests characterize the one way an App comes to life in production:
// cli.executeTUI calls NewAppFromConfig(cfg) with the validated static config,
// then SetAnalysisResults and SetRequestData. There is no other constructor,
// so an App always has a config and - once results are displayed - a
// multi-trie result. The "no-config"/"legacy" rendering variants that used to
// sit behind `cfg == nil` checks can therefore never be shown; each test below
// fails if one of them were reachable through this path.

// TestNewAppFromConfigRequiresConfig pins the invariant itself: the
// constructor dereferences the config, so no App can be built without one.
func TestNewAppFromConfigRequiresConfig(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("NewAppFromConfig(nil) returned; an App without a config must be impossible")
		}
	}()
	NewAppFromConfig(nil, "")
}

// configModeResult builds a multi-trie analysis result with one trie per name.
func configModeResult(names ...string) *output.JSONOutput {
	multi := output.NewJSONOutput("static", time.Now())
	multi.General.LogFile = "access.log"
	multi.General.TotalRequests = 1234
	for i, name := range names {
		set := newClusterSet("10." + itoa(i) + ".0.0/16")
		set.MergedRanges[0].Requests = 100
		set.MergedRanges[0].Percentage = 12.5
		multi.Tries = append(multi.Tries, output.TrieResult{
			Name: name,
			Data: []output.ClusterResult{*set},
			Stats: output.TrieStats{
				TotalRequestsAfterFiltering: 800,
				CIDRAnalysis:                []output.CIDRRange{{CIDR: "10.0.0.0/8", Requests: 300, Percentage: 37.5}},
			},
		})
	}
	multi.AddWarning("config", "a real warning", 0)
	return multi
}

// configModeConfig builds a static config with two tries, three cluster sets
// and two CIDR ranges in total (the numbers the progress page reports).
func configModeConfig() *config.Config {
	return &config.Config{
		Static: &config.StaticConfig{LogFile: "access.log"},
		StaticTries: map[string]*config.TrieConfig{
			"trie-a": {ClusterArgSets: make([]config.ClusterArgSet, 2), CIDRRanges: []string{"10.0.0.0/8"}},
			"trie-b": {ClusterArgSets: make([]config.ClusterArgSet, 1), CIDRRanges: []string{"192.168.0.0/16"}},
		},
	}
}

// uiTexts reads the results panels and the status bar on the UI goroutine.
func (a *App) uiTexts() (summary, clustering, cidr, diagnostics, status string) {
	a.app.QueueUpdate(func() {
		summary = a.summary.GetText(false)
		clustering = a.clustering.GetText(false)
		cidr = a.cidrAnalysis.GetText(false)
		diagnostics = a.diagnostics.GetText(false)
		status = a.statusBar.GetText(false)
	})
	return
}

// TestProgressFrameCountsComeFromConfig: the progress page counts cluster sets
// and CIDR ranges across the config's tries (the removed alternative read two
// App fields no code ever assigned, i.e. always printed 0).
func TestProgressFrameCountsComeFromConfig(t *testing.T) {
	a := NewAppFromConfig(configModeConfig(), "")

	got := visibleText(a.progressFrameText("stage", ".."))

	for _, want := range []string{"Log file: access.log", "Cluster sets: 3", "CIDR ranges: 2"} {
		if !strings.Contains(got, want) {
			t.Errorf("progress frame is missing %q\nvisible text:\n%s", want, got)
		}
	}
}

// TestResultsPageIsConfigMode drives the production path on a live event loop
// and checks what is on screen: per-trie summary, the shared panel builders'
// output, and the multi-trie status legend - never the "Legacy Analysis"
// summary or the no-config status legend ("switch panels").
func TestResultsPageIsConfigMode(t *testing.T) {
	multi := configModeResult("trie-a", "trie-b")

	a := NewAppFromConfig(configModeConfig(), "")
	stop := startSimApp(t, a)
	defer stop()

	a.SetAnalysisResults(multi)
	a.SetRequestData(raceTestRequests())

	summary, clustering, cidr, diagnostics, status := a.uiTexts()

	// The panels show exactly what the shared builders render for trie 0.
	first := a.singleTrieOutput(0)
	for _, panel := range []struct{ name, got, want string }{
		{"summary", summary, a.buildSummaryTextFor(0)},
		{"clustering", clustering, a.buildClusteringTextFor(first)},
		{"cidr", cidr, a.buildCidrAnalysisTextFor(first)},
		{"diagnostics", diagnostics, a.buildDiagnosticsTextFor(first)},
	} {
		if panel.got != panel.want {
			t.Errorf("%s panel differs from the shared builder output\n got: %q\nwant: %q", panel.name, panel.got, panel.want)
		}
	}

	for _, want := range []string{"Trie: trie-a", "Requests After Filtering:", "Active Filters:"} {
		if !strings.Contains(summary, want) {
			t.Errorf("summary is missing %q:\n%s", want, summary)
		}
	}
	for _, legacy := range []string{"Legacy Analysis", "Unique IPs:", "Log File:"} {
		if strings.Contains(summary, legacy) {
			t.Errorf("summary shows the no-config variant (%q):\n%s", legacy, summary)
		}
	}
	if !strings.Contains(clustering, "10.0.0.0/16") || !strings.Contains(cidr, "10.0.0.0/8") {
		t.Errorf("clustering/cidr panels lack the trie's ranges:\n%s\n%s", clustering, cidr)
	}
	if !strings.Contains(diagnostics, "a real warning") {
		t.Errorf("diagnostics panel lacks the warning:\n%s", diagnostics)
	}

	if want := "trie-a (1/2)"; !strings.Contains(status, want) {
		t.Errorf("status bar is missing %q: %s", want, status)
	}
	if want := "Tab/Shift+Tab: panels, 't': next trie"; !strings.Contains(status, want) {
		t.Errorf("status bar is missing the multi-trie legend %q: %s", want, status)
	}
	if strings.Contains(status, "switch panels") {
		t.Errorf("status bar shows the no-config legend: %s", status)
	}
}

// TestSingleTrieStatusLegend: with one trie the legend drops the trie switch
// but is still the config-mode wording.
func TestSingleTrieStatusLegend(t *testing.T) {
	a := NewAppFromConfig(configModeConfig(), "")
	stop := startSimApp(t, a)
	defer stop()

	a.SetAnalysisResults(configModeResult("only"))

	_, _, _, _, status := a.uiTexts()
	if want := "Tab/Shift+Tab: panels, ↑↓: scroll"; !strings.Contains(status, want) {
		t.Errorf("status bar is missing the single-trie legend %q: %s", want, status)
	}
	for _, unwanted := range []string{"next trie", "switch panels"} {
		if strings.Contains(status, unwanted) {
			t.Errorf("single-trie status bar contains %q: %s", unwanted, status)
		}
	}
}
