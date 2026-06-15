package output

import (
	"fmt"
	"os"

	"github.com/ChristianF88/flokbn/ingestor"
	"github.com/go-echarts/go-echarts/v2/charts"
	"github.com/go-echarts/go-echarts/v2/components"
	"github.com/go-echarts/go-echarts/v2/opts"
	"github.com/go-echarts/go-echarts/v2/types"
)

// PlotHeatmap creates an interactive heatmap for /16 IP ranges (A.B.0.0/16)
func PlotHeatmap(requests []ingestor.Request, filename string) error {
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
			PageTitle:       "IP /16 Heatmap",
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
	page.AddCharts(heatmap)

	f, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("could not create heatmap file %s: %w", filename, err)
	}
	defer f.Close()

	if err := page.Render(f); err != nil {
		return fmt.Errorf("rendering heatmap: %w", err)
	}

	fmt.Printf("Heatmap saved to %s\n", filename)
	return nil
}

// makeRange creates an integer slice [min..max]
func makeRange(min, max int) []int {
	r := make([]int, max-min+1)
	for i := range r {
		r[i] = min + i
	}
	return r
}
