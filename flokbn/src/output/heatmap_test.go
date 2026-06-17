package output

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ChristianF88/flokbn/ingestor"
)

// ipv4Request builds an IPv4-only request from four octets (flokbn is
// IPv4-only; the heatmap buckets on the first two octets via GetIPNet().To4()).
func ipv4Request(o1, o2, o3, o4 byte) ingestor.Request {
	return ingestor.Request{
		IPUint32: uint32(o1)<<24 | uint32(o2)<<16 | uint32(o3)<<8 | uint32(o4),
	}
}

// TestPlotHeatmap_HappyPath writes a heatmap for a small valid IPv4 fixture to
// a writable temp path and asserts success plus a non-empty rendered file.
func TestPlotHeatmap_HappyPath(t *testing.T) {
	requests := []ingestor.Request{
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
