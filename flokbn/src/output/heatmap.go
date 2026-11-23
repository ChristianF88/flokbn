package output

import (
	"fmt"
	"io"
	"math/rand"
	"os"

	"github.com/ChristianF88/flokbn/ingestor"
	"github.com/go-echarts/go-echarts/v2/charts"
	"github.com/go-echarts/go-echarts/v2/components"
	"github.com/go-echarts/go-echarts/v2/opts"
	"github.com/go-echarts/go-echarts/v2/types"
)

// heatmapPageTitle is the HTML <title> of the heatmap page.
const heatmapPageTitle = "IP /16 Heatmap"

// heatmapAssetsHost is where the heatmap page loads its scripts from.
//
// go-echarts' default AssetsHost is
// https://go-echarts.github.io/go-echarts-assets/assets/ - the GitHub Pages
// site of the go-echarts-assets repository. That URL is mutable (it serves
// whatever was pushed last) and go-echarts emits plain <script src> tags, so
// the report executed whatever that site served on the day it was opened.
//
// The scripts are loaded from the same repository instead, pinned to one exact
// commit through jsDelivr's GitHub endpoint, which serves the files of a given
// commit unmodified and immutably. The commit is the repository head since
// 2023-10-16, i.e. the very files the default host serves for go-echarts
// v2.6.0 (see go.mod); it ships Apache ECharts 5.4.3.
const heatmapAssetsHost = "https://cdn.jsdelivr.net/gh/go-echarts/go-echarts-assets@41f247b1cbb649b029a2d3fffb04f469de372aa7/assets/"

// heatmapScripts lists every script the heatmap page loads, in load order
// (the library first: the theme registers itself on it), with the Subresource
// Integrity hash of the file at the pinned commit. The browser refuses to run a
// script whose content does not match, so even the CDN cannot substitute it.
//
// The hashes are the sha384 of the files in go-echarts-assets at that commit:
//
//	openssl dgst -sha384 -binary assets/<path> | openssl base64 -A
//
// When bumping go-echarts, re-pin the commit and recompute both hashes.
var heatmapScripts = []struct{ path, integrity string }{
	{"echarts.min.js", "sha384-PpgrXpnquO1pL7h9CGCAR6K7B62r8ZFzdHKzC/FtQ/0Pm4MLQNTcS2yt12JX+rkb"},
	{"themes/vintage.js", "sha384-Wk4fmW9d6Cge1x37E67uTBSfXlS0fRGOF0a9XLNuc5eHhPk8vrX5lG5CWxXylR6x"},
}

// pinnedScriptTags turns the script assets a go-echarts page asks for (paths
// relative to the assets host, in load order) into <script> tags that load the
// pinned copy with its integrity hash. An asset without a pinned hash is an
// error: a go-echarts upgrade or a new chart option that pulls in another
// script must be pinned here first, never loaded unchecked.
func pinnedScriptTags(assets []string) ([]string, error) {
	tags := make([]string, 0, len(assets))
	for _, asset := range assets {
		integrity := ""
		for _, s := range heatmapScripts {
			if s.path == asset {
				integrity = s.integrity
				break
			}
		}
		if integrity == "" {
			return nil, fmt.Errorf("heatmap script %q has no pinned integrity hash (see heatmapScripts)", asset)
		}
		tags = append(tags, fmt.Sprintf(`<script src="%s%s" integrity="%s" crossorigin="anonymous"></script>`,
			heatmapAssetsHost, asset, integrity))
	}
	return tags, nil
}

// PlotHeatmap creates an interactive heatmap for /16 IP ranges (A.B.0.0/16)
// and announces the written file on stderr.
func PlotHeatmap(requests []ingestor.Request, filename string) error {
	if err := WriteHeatmap(requests, filename); err != nil {
		return err
	}

	// Progress notice goes to STDERR, never stdout: stdout carries the
	// machine-readable document in the default and --compact JSON modes, and a
	// stray line there makes the whole output unparseable
	// (jq: "Invalid numeric literal at line 1, column 8"). The same fact is also
	// recorded as an "info" warning in the JSON itself (see executeStaticAnalysis).
	fmt.Fprintf(os.Stderr, "Heatmap saved to %s\n", filename)
	return nil
}

// WriteHeatmap is PlotHeatmap without the stderr notice: it writes the file and
// prints nothing. The TUI uses it, because nothing may be written to the
// terminal while tview owns it.
func WriteHeatmap(requests []ingestor.Request, filename string) error {
	var counts [256][256]uint32

	// Fast bucketing into A.B.0.0/16
	for _, req := range requests {
		ip := req.GetIPNet().To4()
		if ip == nil {
			continue
		}
		a, b := ip[0], ip[1]
		counts[a][b]++
	}

	// Prepare data with hover info
	var heatmapData []opts.HeatMapData
	var maxCount uint32
	for x := 0; x <= 255; x++ {
		for y := 0; y <= 255; y++ {
			count := counts[x][y]
			if count > maxCount {
				maxCount = count
			}
			if count > 0 {
				label := fmt.Sprintf("%d.%d.0.0/16", x, y)
				heatmapData = append(heatmapData, opts.HeatMapData{
					Value: [3]interface{}{x, y, count},
					Name:  label, // This appears in tooltip via {b}
				})
			}
		}
	}

	// Create heatmap chart
	heatmap := charts.NewHeatMap()
	heatmap.SetGlobalOptions(

		charts.WithLegendOpts(opts.Legend{
			Show: opts.Bool(false),
		}),
		charts.WithInitializationOpts(opts.Initialization{
			PageTitle:       heatmapPageTitle,
			AssetsHost:      heatmapAssetsHost,
			Width:           "180vh",
			Height:          "100vh",
			Theme:           types.ThemeVintage,
			BackgroundColor: "transparent",
		}),
		charts.WithTitleOpts(opts.Title{
			Title: "IP Distribution by /16 Range (A.B.0.0/16)",
			Left:  "center",
		}),
		charts.WithTooltipOpts(opts.Tooltip{
			Trigger: "item",
			Formatter: opts.FuncOpts(`function (params) {
		return params.name + '<br />Count: ' + params.value[2];
	}`),
		}),

		charts.WithVisualMapOpts(opts.VisualMap{
			Show: opts.Bool(true),
			Min:  0,
			Max:  float32(maxCount),
			InRange: &opts.VisualMapInRange{
				Color: []string{"#ffff8f", "#ff0000", "#000000"},
			},
			Orient: "vertical",
			Right:  "5%",
			Top:    "middle",
		}),
		charts.WithXAxisOpts(opts.XAxis{
			Name:        "A (First Octet)",
			Type:        "category",
			Data:        makeRange(0, 255),
			SplitNumber: 16,
		}),
		charts.WithYAxisOpts(opts.YAxis{
			Name:        "B (Second Octet)",
			Type:        "category",
			Data:        makeRange(0, 255),
			SplitNumber: 16,
		}),
	)

	heatmap.AddSeries("Heatmap", heatmapData)

	page := components.NewPage()
	page.SetLayout(components.PageFlexLayout)
	page.SetPageTitle(heatmapPageTitle)
	page.SetAssetsHost(heatmapAssetsHost)
	page.AddCharts(heatmap)

	// Replace go-echarts' plain <script src> tags (the "preset" assets the
	// charts asked for) with pinned, integrity-checked ones. See
	// heatmapAssetsHost.
	scriptTags, err := pinnedScriptTags(page.JSAssets.Values)
	if err != nil {
		return err
	}
	page.ClearPresetJSAssets()
	page.AddCustomizedHeaders(scriptTags...)

	return writeFileAtomically(filename, page.Render)
}

// writeFileAtomically creates filename by rendering into a temp file in the
// same directory and renaming it over the target, so a reader (a browser
// reload, a web server, a copy job) sees either the complete old file or the
// complete new one - never the truncated or half-written file an in-place
// os.Create produces. On any failure the temp file is removed and an existing
// target is left untouched.
//
// The temp file is created with mode 0666 before umask, exactly like os.Create,
// so the heatmap keeps the permissions it always had (os.CreateTemp would make
// it 0600). No fsync: the heatmap is a report that the next run regenerates,
// not state; the guarantee wanted here is atomicity towards readers.
func writeFileAtomically(filename string, render func(io.Writer) error) error {
	tmp, err := createTempSibling(filename)
	if err != nil {
		return fmt.Errorf("could not create heatmap file %s: %w", filename, err)
	}
	tmpName := tmp.Name()

	if err := render(tmp); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("rendering heatmap: %w", err)
	}

	// Close explicitly and propagate: a Close failure (ENOSPC / NFS commit)
	// means the temp file is truncated. Surface that as an error - and keep the
	// previous heatmap - instead of reporting a false success.
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("closing heatmap file %s: %w", filename, err)
	}

	if err := os.Rename(tmpName, filename); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("could not create heatmap file %s: %w", filename, err)
	}
	return nil
}

// createTempSibling exclusively creates a new, uniquely named file next to
// filename ("<filename>.tmp-<pid>-<random>"), with os.Create's permissions.
// O_EXCL makes the creation fail rather than follow or reuse anything that
// already exists under that name.
func createTempSibling(filename string) (*os.File, error) {
	var lastErr error
	for attempt := 0; attempt < 100; attempt++ {
		name := fmt.Sprintf("%s.tmp-%d-%d", filename, os.Getpid(), rand.Uint32())
		f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o666)
		if err == nil {
			return f, nil
		}
		if !os.IsExist(err) {
			return nil, err
		}
		lastErr = err
	}
	return nil, lastErr
}

// makeRange creates an integer slice [min..max]
func makeRange(min, max int) []int {
	r := make([]int, max-min+1)
	for i := range r {
		r[i] = min + i
	}
	return r
}
