package output

import (
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/ChristianF88/flokbn/accesslog"
)

// scriptTagRe matches every external script tag of the rendered page.
var scriptTagRe = regexp.MustCompile(`<script[^>]*\bsrc="[^"]*"[^>]*>`)

// writeTestHeatmap renders a small heatmap and returns the HTML.
func writeTestHeatmap(t *testing.T) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "heatmap.html")
	requests := []accesslog.Request{ipv4Request(10, 5, 5, 1), ipv4Request(192, 168, 0, 3)}
	if err := WriteHeatmap(requests, out); err != nil {
		t.Fatalf("WriteHeatmap returned error: %v", err)
	}
	html, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("reading heatmap: %v", err)
	}
	return string(html)
}

// TestHeatmapScriptsArePinned is the regression test for the unpinned remote
// scripts: the page loaded echarts.min.js and the theme from go-echarts'
// default AssetsHost (https://go-echarts.github.io/go-echarts-assets/assets/),
// a mutable GitHub Pages site, with no integrity check - whoever controls that
// site (or its next push) controls script running in the report.
//
// Every external script must come from the commit-pinned URL and carry a
// Subresource Integrity hash.
func TestHeatmapScriptsArePinned(t *testing.T) {
	html := writeTestHeatmap(t)

	if strings.Contains(html, "go-echarts.github.io") {
		t.Error("heatmap still references the unpinned default host go-echarts.github.io")
	}

	tags := scriptTagRe.FindAllString(html, -1)
	if len(tags) != len(heatmapScripts) {
		t.Fatalf("heatmap has %d external script tags, want %d (one per pinned script):\n%s",
			len(tags), len(heatmapScripts), strings.Join(tags, "\n"))
	}
	for i, tag := range tags {
		want := heatmapScripts[i]
		for _, attr := range []string{
			`src="` + heatmapAssetsHost + want.path + `"`,
			`integrity="` + want.integrity + `"`,
			`crossorigin="anonymous"`,
		} {
			if !strings.Contains(tag, attr) {
				t.Errorf("script tag %d = %s\nis missing %s", i, tag, attr)
			}
		}
	}

	// The library must come first: the theme registers itself on echarts.
	if len(tags) == 2 && !strings.Contains(tags[0], "echarts.min.js") {
		t.Errorf("first script is %s, want echarts.min.js before the theme", tags[0])
	}
}

// TestHeatmapAssetsHostIsCommitPinned pins the shape of the host constant: a
// full 40-hex commit of go-echarts-assets, not a branch or a floating tag.
func TestHeatmapAssetsHostIsCommitPinned(t *testing.T) {
	re := regexp.MustCompile(`^https://cdn\.jsdelivr\.net/gh/go-echarts/go-echarts-assets@[0-9a-f]{40}/assets/$`)
	if !re.MatchString(heatmapAssetsHost) {
		t.Errorf("heatmapAssetsHost = %q, want a jsDelivr URL pinned to a full commit SHA", heatmapAssetsHost)
	}
	for _, s := range heatmapScripts {
		if !strings.HasPrefix(s.integrity, "sha384-") {
			t.Errorf("script %s: integrity %q is not a sha384 SRI hash", s.path, s.integrity)
		}
	}
}

// TestPinnedScriptTagsRejectsUnknownAsset: if a go-echarts upgrade (or a chart
// option change) makes the page need a script that has no pinned hash, the
// heatmap must fail loudly instead of quietly loading it unpinned.
func TestPinnedScriptTagsRejectsUnknownAsset(t *testing.T) {
	if _, err := pinnedScriptTags([]string{"echarts.min.js", "themes/vintage.js"}); err != nil {
		t.Errorf("pinnedScriptTags(known assets) returned error: %v", err)
	}

	_, err := pinnedScriptTags([]string{"echarts.min.js", "echarts-gl.min.js"})
	if err == nil {
		t.Fatal("pinnedScriptTags accepted echarts-gl.min.js, which has no pinned hash")
	}
	if !strings.Contains(err.Error(), "echarts-gl.min.js") {
		t.Errorf("error %q does not name the unpinned asset", err)
	}
}

// TestHeatmapPageTitle: the page title was go-echarts' placeholder ("Awesome
// go-echarts") because the title was set on the chart, which a Page ignores.
func TestHeatmapPageTitle(t *testing.T) {
	html := writeTestHeatmap(t)
	if want := "<title>IP /16 Heatmap</title>"; !strings.Contains(html, want) {
		t.Errorf("heatmap is missing %s", want)
	}
}

// TestWriteHeatmap_ReplacesAtomically is the regression test for the in-place
// rewrite: os.Create truncated the existing heatmap and then filled it, so a
// reader (a browser reload, a web server, rsync) could see an empty or
// half-written file. The new file must be built next to the target and renamed
// over it: a reader that already has the old file open keeps seeing the
// complete old content, and no temp file is left behind.
func TestWriteHeatmap_ReplacesAtomically(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("an open file cannot be replaced on Windows")
	}

	dir := t.TempDir()
	out := filepath.Join(dir, "heatmap.html")
	const old = "<html>previous heatmap</html>"
	if err := os.WriteFile(out, []byte(old), 0o644); err != nil {
		t.Fatalf("seeding old heatmap: %v", err)
	}

	reader, err := os.Open(out)
	if err != nil {
		t.Fatalf("opening old heatmap: %v", err)
	}
	defer reader.Close()

	requests := []accesslog.Request{ipv4Request(10, 5, 5, 1)}
	if err := WriteHeatmap(requests, out); err != nil {
		t.Fatalf("WriteHeatmap returned error: %v", err)
	}

	seen, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("reading through the old handle: %v", err)
	}
	if string(seen) != old {
		t.Errorf("a reader holding the old heatmap open saw %d bytes starting %q, want the complete old content %q "+
			"(the file was rewritten in place instead of being replaced)", len(seen), firstBytes(seen, 40), old)
	}

	current, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("reading new heatmap: %v", err)
	}
	if !strings.Contains(string(current), "<title>IP /16 Heatmap</title>") {
		t.Errorf("target does not hold the new heatmap (%d bytes)", len(current))
	}

	assertNoTempFiles(t, dir)
}

// TestWriteHeatmap_FailureLeavesNoTempFile: when the final rename fails (the
// target is a directory) the temp file is removed and the error is returned.
func TestWriteHeatmap_FailureLeavesNoTempFile(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "heatmap.html")
	if err := os.Mkdir(out, 0o755); err != nil {
		t.Fatalf("creating directory at the target path: %v", err)
	}

	if err := WriteHeatmap([]accesslog.Request{ipv4Request(10, 5, 5, 1)}, out); err == nil {
		t.Fatal("WriteHeatmap returned nil although the target is a directory")
	}

	assertNoTempFiles(t, dir)
}

// assertNoTempFiles fails if dir holds anything besides heatmap.html.
func assertNoTempFiles(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}
	for _, e := range entries {
		if e.Name() != "heatmap.html" {
			t.Errorf("leftover file %s in the heatmap directory", e.Name())
		}
	}
}

// firstBytes returns at most n leading bytes of b as a string.
func firstBytes(b []byte, n int) string {
	if len(b) > n {
		b = b[:n]
	}
	return string(b)
}
