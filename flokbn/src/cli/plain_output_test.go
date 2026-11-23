package cli

import (
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ChristianF88/flokbn/output"
)

// captureStdout runs fn with os.Stdout redirected and returns what it wrote.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	orig := os.Stdout
	os.Stdout = w

	done := make(chan string, 1)
	go func() {
		data, _ := io.ReadAll(r)
		done <- string(data)
	}()

	fn()

	os.Stdout = orig
	if err := w.Close(); err != nil {
		t.Fatalf("closing pipe writer: %v", err)
	}
	out := <-done
	if err := r.Close(); err != nil {
		t.Fatalf("closing pipe reader: %v", err)
	}
	return out
}

// plainTestOutput builds a one-trie result for the plain renderer.
func plainTestOutput() *output.JSONOutput {
	out := output.NewJSONOutput("static", time.Now())
	out.General.LogFile = "access.log"
	out.Tries = []output.TrieResult{{
		Name:  "cli_trie",
		Stats: output.TrieStats{TotalRequestsAfterFiltering: 100},
		Data: []output.ClusterResult{{
			Parameters: output.ClusterParameters{
				MinClusterSize:       1000,
				MinDepth:             24,
				MaxDepth:             32,
				MeanSubnetDifference: 0.25,
			},
		}},
	}}
	return out
}

// TestOutputPlain_InfoOnlyWarningsPrintNoDiagnostics is the regression test for
// the empty diagnostics block: info-type warnings (e.g. "Heatmap generated in
// ...") are skipped by the plain renderer, but the "DIAGNOSTICS" section and
// its "Warnings:" header were still printed, leaving a header with nothing
// under it on every run that wrote a heatmap.
func TestOutputPlain_InfoOnlyWarningsPrintNoDiagnostics(t *testing.T) {
	out := plainTestOutput()
	out.AddWarning("info", "Heatmap generated in 89ms at /tmp/heatmap.html", 0)

	got := captureStdout(t, func() { outputPlain(out) })

	for _, unwanted := range []string{"DIAGNOSTICS", "Warnings:", "Errors:", "Heatmap generated"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("plain output contains %q although the only warning is of type info\noutput:\n%s", unwanted, got)
		}
	}
}

// TestOutputPlain_RealWarningsAndErrorsArePrinted pins the other side: real
// warnings and errors keep their headers, and an info warning mixed in is
// still skipped without suppressing the section.
func TestOutputPlain_RealWarningsAndErrorsArePrinted(t *testing.T) {
	t.Run("warning next to info", func(t *testing.T) {
		out := plainTestOutput()
		out.AddWarning("info", "Heatmap generated in 89ms at /tmp/heatmap.html", 0)
		out.AddWarning("whitelist_applied", "Whitelist filtering prevented 2 CIDRs from being added to jail", 0)

		got := captureStdout(t, func() { outputPlain(out) })

		for _, want := range []string{"DIAGNOSTICS", "Warnings:\n  • Whitelist filtering prevented 2 CIDRs"} {
			if !strings.Contains(got, want) {
				t.Errorf("plain output is missing %q\noutput:\n%s", want, got)
			}
		}
		for _, unwanted := range []string{"Heatmap generated", "Errors:"} {
			if strings.Contains(got, unwanted) {
				t.Errorf("plain output contains %q\noutput:\n%s", unwanted, got)
			}
		}
	})

	t.Run("error next to info", func(t *testing.T) {
		out := plainTestOutput()
		out.AddWarning("info", "Heatmap generated in 89ms at /tmp/heatmap.html", 0)
		out.AddError("jail_processing", "failed to process jail", 1)

		got := captureStdout(t, func() { outputPlain(out) })

		for _, want := range []string{"DIAGNOSTICS", "Errors:\n  • failed to process jail"} {
			if !strings.Contains(got, want) {
				t.Errorf("plain output is missing %q\noutput:\n%s", want, got)
			}
		}
		if strings.Contains(got, "Warnings:") {
			t.Errorf("plain output prints a \"Warnings:\" header with only an info warning\noutput:\n%s", got)
		}
	})
}

// TestOutputPlain_ClusterSetLine pins the cluster-set line the docs quote; the
// TUI renders the same parameters through output.FormatClusterParameters.
func TestOutputPlain_ClusterSetLine(t *testing.T) {
	got := captureStdout(t, func() { outputPlain(plainTestOutput()) })

	if want := "  Set 1: min_size=1000, depth=24-32, threshold=0.25\n"; !strings.Contains(got, want) {
		t.Errorf("plain output is missing %q\noutput:\n%s", want, got)
	}
}
