package cli

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ChristianF88/flokbn/accesslog"
	"github.com/ChristianF88/flokbn/output"
)

// heatmapTestRequests is a tiny request corpus for the heatmap writer.
func heatmapTestRequests() []accesslog.Request {
	return []accesslog.Request{
		{IPUint32: 10<<24 | 5<<16 | 5<<8 | 1},
		{IPUint32: 192<<24 | 168<<16 | 3},
	}
}

// captureStderr runs fn with os.Stderr redirected and returns what it wrote.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	orig := os.Stderr
	os.Stderr = w

	done := make(chan string, 1)
	go func() {
		data, _ := io.ReadAll(r)
		done <- string(data)
	}()

	fn()

	os.Stderr = orig
	if err := w.Close(); err != nil {
		t.Fatalf("closing pipe writer: %v", err)
	}
	out := <-done
	if err := r.Close(); err != nil {
		t.Fatalf("closing pipe reader: %v", err)
	}
	return out
}

// TestTUIHeatmap_WritesPlotPath is the regression test for the heatmap that
// --tui silently skipped: with plotPath set, the TUI path must write the file,
// stay silent while the TUI owns the terminal, and report afterwards.
func TestTUIHeatmap_WritesPlotPath(t *testing.T) {
	plotPath := filepath.Join(t.TempDir(), "heatmap.html")
	result := output.NewJSONOutput("static", time.Now())

	var h tuiHeatmap
	var stdout, stderr string
	stdout = captureStdout(t, func() {
		stderr = captureStderr(t, func() {
			h.write(context.Background(), plotPath, heatmapTestRequests(), result)
		})
	})

	if stdout != "" || stderr != "" {
		t.Errorf("write printed stdout=%q stderr=%q, want nothing while the TUI owns the terminal", stdout, stderr)
	}

	fi, err := os.Stat(plotPath)
	if err != nil {
		t.Fatalf("heatmap not written: %v", err)
	}
	if fi.Size() == 0 {
		t.Error("heatmap file is empty")
	}

	if len(result.Errors) != 0 {
		t.Errorf("result.Errors = %+v, want none", result.Errors)
	}
	if len(result.Warnings) != 1 || result.Warnings[0].Type != "info" ||
		!strings.Contains(result.Warnings[0].Message, plotPath) {
		t.Errorf("result.Warnings = %+v, want one info warning naming %s", result.Warnings, plotPath)
	}

	var report bytes.Buffer
	h.report(&report)
	if want := "Heatmap saved to " + plotPath + "\n"; report.String() != want {
		t.Errorf("report = %q, want %q", report.String(), want)
	}
}

// TestTUIHeatmap_FailureIsReported: a heatmap that cannot be written becomes an
// error on the result (shown in the Diagnostics panel) and is reported after
// the TUI exits, instead of vanishing.
func TestTUIHeatmap_FailureIsReported(t *testing.T) {
	plotPath := filepath.Join(t.TempDir(), "does-not-exist", "heatmap.html")
	result := output.NewJSONOutput("static", time.Now())

	var h tuiHeatmap
	h.write(context.Background(), plotPath, heatmapTestRequests(), result)

	if len(result.Errors) != 1 || result.Errors[0].Type != "heatmap" {
		t.Fatalf("result.Errors = %+v, want one heatmap error", result.Errors)
	}
	if len(result.Warnings) != 0 {
		t.Errorf("result.Warnings = %+v, want none", result.Warnings)
	}

	var report bytes.Buffer
	h.report(&report)
	if !strings.HasPrefix(report.String(), "Heatmap not written: ") {
		t.Errorf("report = %q, want a \"Heatmap not written\" notice", report.String())
	}
}

// TestTUIHeatmap_Skipped covers the no-op cases: no plotPath configured, no
// request data, and a TUI that was already quit (cancelled context).
func TestTUIHeatmap_Skipped(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	plotPath := filepath.Join(t.TempDir(), "heatmap.html")

	for name, tc := range map[string]struct {
		ctx      context.Context
		plotPath string
		requests []accesslog.Request
	}{
		"no plotPath":   {context.Background(), "", heatmapTestRequests()},
		"no requests":   {context.Background(), plotPath, nil},
		"TUI was quit":  {cancelled, plotPath, heatmapTestRequests()},
		"nothing asked": {cancelled, "", nil},
	} {
		t.Run(name, func(t *testing.T) {
			result := output.NewJSONOutput("static", time.Now())

			var h tuiHeatmap
			h.write(tc.ctx, tc.plotPath, tc.requests, result)

			if _, err := os.Stat(plotPath); err == nil {
				t.Errorf("heatmap was written at %s, want none", plotPath)
			}
			if len(result.Warnings) != 0 || len(result.Errors) != 0 {
				t.Errorf("result warnings=%+v errors=%+v, want none", result.Warnings, result.Errors)
			}
			var report bytes.Buffer
			h.report(&report)
			if report.Len() != 0 {
				t.Errorf("report = %q, want nothing", report.String())
			}
		})
	}
}
