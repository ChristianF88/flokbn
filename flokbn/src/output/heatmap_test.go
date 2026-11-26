package output

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/ChristianF88/flokbn/accesslog"
)

// ipv4Request builds an IPv4-only request from four octets (flokbn is
// IPv4-only; the heatmap buckets on the first two octets via GetIPNet().To4()).
func ipv4Request(o1, o2, o3, o4 byte) accesslog.Request {
	return accesslog.Request{
		IPUint32: uint32(o1)<<24 | uint32(o2)<<16 | uint32(o3)<<8 | uint32(o4),
	}
}

// TestPlotHeatmap_HappyPath writes a heatmap for a small valid IPv4 fixture to
// a writable temp path and asserts success plus a non-empty rendered file.
func TestPlotHeatmap_HappyPath(t *testing.T) {
	requests := []accesslog.Request{
		ipv4Request(10, 5, 5, 1),
		ipv4Request(10, 5, 6, 2),
		ipv4Request(192, 168, 0, 3),
	}
	out := filepath.Join(t.TempDir(), "heatmap.html")

	if err := PlotHeatmap(requests, out); err != nil {
		t.Fatalf("PlotHeatmap returned error: %v", err)
	}

	fi, err := os.Stat(out)
	if err != nil {
		t.Fatalf("heatmap file not written: %v", err)
	}
	if fi.Size() == 0 {
		t.Error("heatmap file is empty, want a rendered (non-empty) file")
	}
}

// TestPlotHeatmap_StdoutStaysClean is the regression guard for the "Heatmap
// saved to ..." notice: it must go to stderr, never stdout. stdout carries the
// JSON document in the default and --compact static modes, so a single stray
// line there makes the entire output unparseable
// (jq: "Invalid numeric literal at line 1, column 8").
func TestPlotHeatmap_StdoutStaysClean(t *testing.T) {
	requests := []accesslog.Request{
		ipv4Request(10, 5, 5, 1),
		ipv4Request(192, 168, 0, 3),
	}
	out := filepath.Join(t.TempDir(), "heatmap.html")

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	orig := os.Stdout
	os.Stdout = w

	plotErr := PlotHeatmap(requests, out)

	os.Stdout = orig
	if closeErr := w.Close(); closeErr != nil {
		t.Fatalf("closing pipe writer: %v", closeErr)
	}
	captured, readErr := io.ReadAll(r)
	if readErr != nil {
		t.Fatalf("reading captured stdout: %v", readErr)
	}
	if closeErr := r.Close(); closeErr != nil {
		t.Fatalf("closing pipe reader: %v", closeErr)
	}

	if plotErr != nil {
		t.Fatalf("PlotHeatmap returned error: %v", plotErr)
	}
	if len(captured) != 0 {
		t.Errorf("PlotHeatmap wrote %q to stdout, want nothing (notice belongs on stderr)", captured)
	}
}

// TestPlotHeatmap_UncreatablePathErrors asserts the create-failure path returns
// the wrapped error (and nothing is reported as saved). A path under a
// nonexistent directory cannot be created.
//
// Note: the Close-error branch (ENOSPC / NFS commit failure after a successful
// Render) is environment-dependent and cannot be forced deterministically in a
// portable test; it is verified by code review. The fix closes f explicitly and
// propagates a "closing heatmap file" error, printing "Heatmap saved" only on a
// fully-committed file.
func TestPlotHeatmap_UncreatablePathErrors(t *testing.T) {
	out := filepath.Join(t.TempDir(), "does-not-exist", "heatmap.html")

	err := PlotHeatmap(nil, out)
	if err == nil {
		t.Fatal("PlotHeatmap returned nil for an uncreatable path, want an error")
	}
	if _, statErr := os.Stat(out); statErr == nil {
		t.Error("heatmap file exists for an uncreatable path, want none")
	}
}

// TestWriteHeatmap_IsSilent: WriteHeatmap is the variant for callers that must
// not touch the terminal (the TUI). It writes the same file as PlotHeatmap but
// prints nothing, on stdout or stderr.
func TestWriteHeatmap_IsSilent(t *testing.T) {
	requests := []accesslog.Request{
		ipv4Request(10, 5, 5, 1),
		ipv4Request(192, 168, 0, 3),
	}
	out := filepath.Join(t.TempDir(), "heatmap.html")

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	origStdout, origStderr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = w, w

	writeErr := WriteHeatmap(requests, out)

	os.Stdout, os.Stderr = origStdout, origStderr
	if closeErr := w.Close(); closeErr != nil {
		t.Fatalf("closing pipe writer: %v", closeErr)
	}
	captured, readErr := io.ReadAll(r)
	if readErr != nil {
		t.Fatalf("reading captured output: %v", readErr)
	}
	if closeErr := r.Close(); closeErr != nil {
		t.Fatalf("closing pipe reader: %v", closeErr)
	}

	if writeErr != nil {
		t.Fatalf("WriteHeatmap returned error: %v", writeErr)
	}
	if len(captured) != 0 {
		t.Errorf("WriteHeatmap printed %q, want nothing", captured)
	}
	if fi, statErr := os.Stat(out); statErr != nil || fi.Size() == 0 {
		t.Errorf("heatmap file missing or empty (stat error: %v)", statErr)
	}
}
