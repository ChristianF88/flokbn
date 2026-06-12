package tui

import (
	"fmt"
	"math"
	"math/rand"
	"net"
	"strings"
	"testing"

	"github.com/ChristianF88/cidrx/ingestor"
	"github.com/ChristianF88/cidrx/iputils"
	"github.com/ChristianF88/cidrx/output"
	"github.com/rivo/tview"
)

// newClusterSet builds a ClusterResult whose MergedRanges are the given CIDRs.
func newClusterSet(cidrs ...string) *output.ClusterResult {
	cs := &output.ClusterResult{}
	for _, c := range cidrs {
		cs.MergedRanges = append(cs.MergedRanges, output.CIDRRange{CIDR: c})
	}
	return cs
}

// reqFor builds a synthetic request for the given dotted IP.
func reqFor(ip string) ingestor.Request {
	return ingestor.Request{IPUint32: iputils.IPToUint32(net.ParseIP(ip))}
}

// bruteContains reports membership via net.Contains over the parsed CIDRs —
// the independent reference the fast interval path must match.
func bruteContains(cidrs []*net.IPNet, ipu uint32) bool {
	ip := iputils.Uint32ToIP(ipu)
	for _, n := range cidrs {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// buildGridReference computes the clustered-traffic grid by brute force.
func buildGridReference(reqs []ingestor.Request, cidrs []*net.IPNet) [256][256]uint32 {
	var grid [256][256]uint32
	for i := range reqs {
		ip := reqs[i].IPUint32
		if ip == 0 {
			continue
		}
		if bruteContains(cidrs, ip) {
			grid[byte(ip>>24)][byte(ip>>16)]++
		}
	}
	return grid
}

func mustCIDRs(t testing.TB, cidrs ...string) []*net.IPNet {
	t.Helper()
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			t.Fatalf("parse %q: %v", c, err)
		}
		out = append(out, n)
	}
	return out
}

// newOverlayView builds a legacy-mode view with a single cluster set made of
// the given CIDRs and runs ProcessTrafficData over reqs.
func newOverlayView(reqs []ingestor.Request, cidrs ...string) *VisualizationView {
	app := &App{}
	app.jsonResult = &output.JSONOutput{}
	app.jsonResult.Clustering.Data = []output.ClusterResult{*newClusterSet(cidrs...)}

	v := &VisualizationView{
		app:                 app,
		totalClusterSets:    1,
		currentClusterSet:   0,
		cachedClusteredData: make(map[clusterKey][256][256]uint32),
	}
	v.ProcessTrafficData(reqs)
	return v
}

// repeatReq returns n copies of a request for the given dotted IP.
func repeatReq(ip string, n int) []ingestor.Request {
	out := make([]ingestor.Request, n)
	r := reqFor(ip)
	for i := range out {
		out[i] = r
	}
	return out
}

// TestClusteredTrafficGrid verifies the per-/16 clustered grid built by
// ProcessTrafficData equals an independent net.Contains reference, covering a
// /32, /24, a shallow /12 spanning many /16 cells, and IPs outside all ranges.
func TestClusteredTrafficGrid(t *testing.T) {
	cidrStrs := []string{
		"20.171.207.2/32", // single host
		"45.40.50.192/26", // sub-/24
		"45.40.51.0/24",   // full /24
		"14.160.0.0/12",   // shallow, spans 14.160 .. 14.175 (16 /16 cells)
		"152.88.205.0/24", // another /24
	}

	reqs := []ingestor.Request{
		reqFor("20.171.207.2"),   // in /32
		reqFor("20.171.207.3"),   // NOT in /32 (adjacent)
		reqFor("45.40.50.200"),   // in /26
		reqFor("45.40.50.191"),   // just below /26 -> out
		reqFor("45.40.51.77"),    // in /24
		reqFor("14.160.0.1"),     // in /12 (first cell)
		reqFor("14.175.255.254"), // in /12 (last cell)
		reqFor("14.176.0.1"),     // just past /12 -> out
		reqFor("152.88.205.91"),  // in /24
		reqFor("8.8.8.8"),        // out of everything
		reqFor("203.0.113.5"),    // out of everything
	}

	v := &VisualizationView{
		cachedClusteredData: make(map[clusterKey][256][256]uint32),
	}
	v.requests = reqs
	v.maxTraffic = 0
	// Build the grid directly via the same intervals the renderer uses.
	intervals := buildClusterIntervals(newClusterSet(cidrStrs...))
	for i := range reqs {
		ip := reqs[i].IPUint32
		a := byte(ip >> 24)
		b := byte(ip >> 16)
		v.trafficData[a][b]++
		if intervals.Contains(ip) {
			v.clusteredData[a][b]++
		}
	}

	want := buildGridReference(reqs, mustCIDRs(t, cidrStrs...))

	for a := 0; a < 256; a++ {
		for b := 0; b < 256; b++ {
			if v.clusteredData[a][b] != want[a][b] {
				t.Errorf("clusteredData[%d][%d] = %d, want %d", a, b, v.clusteredData[a][b], want[a][b])
			}
		}
	}

	// Spot checks for the documented cases.
	if v.clusteredData[20][171] != 1 {
		t.Errorf("/32 cell 20.171 = %d, want 1", v.clusteredData[20][171])
	}
	if v.clusteredData[45][40] != 2 { // /26 hit + /24 hit both land in 45.40
		t.Errorf("45.40 cell = %d, want 2", v.clusteredData[45][40])
	}
	// /12 spans 14.160..14.175; the two in-range requests are in cells 14.160 and 14.175.
	if v.clusteredData[14][160] != 1 || v.clusteredData[14][175] != 1 {
		t.Errorf("/12 cells: 14.160=%d 14.175=%d, want 1 and 1", v.clusteredData[14][160], v.clusteredData[14][175])
	}
	if v.clusteredData[14][176] != 0 {
		t.Errorf("14.176 (past /12) = %d, want 0", v.clusteredData[14][176])
	}
	if v.clusteredData[8][8] != 0 {
		t.Errorf("8.8 (outside) = %d, want 0", v.clusteredData[8][8])
	}
}

// TestProcessTrafficDataLegacyMode exercises the public ProcessTrafficData entry
// point (legacy/no-config) to ensure traffic + clustered grids are both built in
// one pass and match the reference.
func TestProcessTrafficDataLegacyMode(t *testing.T) {
	cidrStrs := []string{"45.40.50.192/26", "14.160.0.0/12"}
	reqs := []ingestor.Request{
		reqFor("45.40.50.200"),
		reqFor("45.40.50.201"),
		reqFor("14.170.1.1"),
		reqFor("8.8.8.8"),
	}

	app := &App{}
	cs := newClusterSet(cidrStrs...)
	app.jsonResult = &output.JSONOutput{}
	app.jsonResult.Clustering.Data = []output.ClusterResult{*cs}

	v := &VisualizationView{
		app:                 app,
		totalClusterSets:    1,
		currentClusterSet:   0,
		cachedClusteredData: make(map[clusterKey][256][256]uint32),
	}

	v.ProcessTrafficData(reqs)

	wantClustered := buildGridReference(reqs, mustCIDRs(t, cidrStrs...))
	for a := 0; a < 256; a++ {
		for b := 0; b < 256; b++ {
			if v.clusteredData[a][b] != wantClustered[a][b] {
				t.Fatalf("clusteredData[%d][%d]=%d want %d", a, b, v.clusteredData[a][b], wantClustered[a][b])
			}
		}
	}
	// Traffic grid totals all requests.
	var total uint32
	for a := 0; a < 256; a++ {
		for b := 0; b < 256; b++ {
			total += v.trafficData[a][b]
		}
	}
	if total != uint32(len(reqs)) {
		t.Errorf("traffic total = %d, want %d", total, len(reqs))
	}
}

// TestOverlayRatioSemantics verifies that the overlay dot tier matches the
// share of a cell's traffic captured by clusters: fully-in -> "●", none -> "",
// half-in -> "•".
func TestOverlayRatioSemantics(t *testing.T) {
	cases := []struct {
		name             string
		clustered, total uint32
		wantDot          string
	}{
		{"entirely inside -> full", 1000, 1000, "●"},
		{"high traffic none captured -> no dot", 0, 5000, ""},
		{"half inside -> medium", 500, 1000, "•"},
		{"exactly 80pct -> full", 80, 100, "●"},
		{"just below 80pct -> medium", 79, 100, "•"},
		{"exactly 20pct -> medium", 20, 100, "•"},
		{"just below 20pct -> minimal", 19, 100, "·"},
		{"one in many -> minimal", 1, 100000, "·"},
		{"zero traffic guard -> no dot", 0, 0, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := getRatioMarker(ratioOf(tc.clustered, tc.total))
			if got != tc.wantDot {
				t.Errorf("clustered=%d total=%d: dot=%q want %q", tc.clustered, tc.total, got, tc.wantDot)
			}
		})
	}
}

// TestMembershipEquivalence is a property test: over a large random corpus of
// IPs and random cluster CIDRs, the fast interval membership must agree with
// net.Contains exactly. Split into prefix bands so wide (low-prefix) CIDRs —
// including /0../7, which the original /8../32 band never generated — get
// dedicated coverage. 70000 random IPs per band (3 bands, 210000 total,
// roughly the original 200000).
func TestMembershipEquivalence(t *testing.T) {
	bands := []struct {
		name     string
		min, max int
	}{
		{"full_0_32", 0, 32},
		{"low_0_7", 0, 7},
		{"orig_8_32", 8, 32},
	}
	boundaryIPs := []uint32{
		0x00000000, 0x00000001, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFE, 0xFFFFFFFF,
	}

	for _, band := range bands {
		t.Run(band.name, func(t *testing.T) {
			rng := rand.New(rand.NewSource(0xC1D8))

			// Generate random non-overlapping-ish CIDRs within the band's
			// prefix range. Note ipNetString handles prefix 0: the variable
			// shift `^uint32(0) << 32` yields 0 in Go, so net0 becomes 0 and
			// ParseCIDR("0.0.0.0/0") round-trips correctly.
			var cidrStrs []string
			for i := 0; i < 40; i++ {
				prefix := band.min + rng.Intn(band.max-band.min+1)
				base := rng.Uint32()
				// Zero the host bits so ParseCIDR keeps the network address.
				mask := ^uint32(0) << (32 - prefix)
				net0 := base & mask
				ip := iputils.Uint32ToIP(net0)
				cidrStrs = append(cidrStrs, ipNetString(ip, prefix))
			}

			cs := newClusterSet(cidrStrs...)
			intervals := buildClusterIntervals(cs)
			refNets := mustCIDRs(t, cidrStrs...)

			check := func(ip uint32) {
				got := intervals.Contains(ip)
				want := bruteContains(refNets, ip)
				if got != want {
					t.Fatalf("ip %s: interval=%v net.Contains=%v", iputils.Uint32ToIP(ip), got, want)
				}
			}
			for i := 0; i < 70000; i++ {
				check(rng.Uint32())
			}
			for _, ip := range boundaryIPs {
				check(ip)
			}
		})
	}
}

func ipNetString(ip net.IP, prefix int) string {
	_, n, _ := net.ParseCIDR(ip.String() + "/" + itoa(prefix))
	return n.String()
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [3]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// TestBlockStatsCellSums verifies cell-total aggregation over an 8x8 block:
// traffic and clustered counts are summed over all bins in the block, and
// neighbors outside the block are ignored.
func TestBlockStatsCellSums(t *testing.T) {
	cases := []struct {
		name           string
		setup          func(tr, cl *[256][256]uint32)
		aStart, bStart int
		wantT, wantC   uint32
	}{
		{
			// Hot clustered bin plus 63 siblings of 100: cell totals are the
			// sums, capture ratio = 50000/56300.
			name: "hot clustered bin summed with 63 siblings",
			setup: func(tr, cl *[256][256]uint32) {
				for aa := 0; aa < 8; aa++ {
					for bb := 0; bb < 8; bb++ {
						tr[aa][bb] = 100
					}
				}
				tr[3][4] = 50000
				cl[3][4] = 50000
			},
			wantT: 50000 + 63*100, wantC: 50000,
		},
		{
			name: "clustered counts sum across bins",
			setup: func(tr, cl *[256][256]uint32) {
				tr[0][0] = 1000
				tr[0][1] = 10
				cl[0][1] = 10
				cl[0][0] = 250
			},
			wantT: 1010, wantC: 260,
		},
		{
			name:  "empty block",
			setup: func(tr, cl *[256][256]uint32) {},
			wantT: 0, wantC: 0,
		},
		{
			name: "bins outside block boundary excluded",
			setup: func(tr, cl *[256][256]uint32) {
				tr[7][7] = 5 // last bin inside block (0,0)
				cl[7][7] = 5
				tr[8][0] = 999 // first bin of next block on A axis
				tr[0][8] = 888 // first bin of next block on B axis
			},
			wantT: 5, wantC: 5,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var traffic, clustered [256][256]uint32
			tc.setup(&traffic, &clustered)
			gotT, gotC := blockStats(&traffic, &clustered, tc.aStart, tc.bStart, 8)
			if gotT != tc.wantT || gotC != tc.wantC {
				t.Errorf("blockStats = (%d, %d), want (%d, %d)", gotT, gotC, tc.wantT, tc.wantC)
			}
		})
	}
}

// TestRenderHeatmapCellCapture is the end-to-end bug repro: the busiest cell's
// traffic is nearly all captured by a cluster. The cell must render white
// (busiest cell = 100% linear brightness) with a full ● dot (>=80% of the
// cell's requests captured) — dot size from request share, never from
// address-space geometry.
func TestRenderHeatmapCellCapture(t *testing.T) {
	// Cell containing 9.9/9.10: 110 requests, 100 captured (91% -> ●), busiest
	// cell on the map -> white. 200.200 is a distant uncaptured cell.
	reqs := repeatReq("9.9.0.1", 100)
	reqs = append(reqs, repeatReq("9.10.0.1", 10)...)
	reqs = append(reqs, repeatReq("200.200.0.1", 30)...)
	v := newOverlayView(reqs, "9.9.0.0/16")

	text := v.generateRenderText()
	if !strings.Contains(text, "[white]█[red]●") {
		t.Errorf("render text missing white+● cell for mostly-captured busiest cell")
	}
	if !strings.Contains(text, "requests in cell") {
		t.Errorf("legend missing cell-total semantics (\"requests in cell\")")
	}
}

// TestRenderHeatmapEdges covers edge cases of the cell-sum renderer.
func TestRenderHeatmapEdges(t *testing.T) {
	t.Run("cluster 0.0.0.0/0 dots every nonzero cell", func(t *testing.T) {
		reqs := repeatReq("1.1.0.1", 10)
		reqs = append(reqs, repeatReq("100.100.0.1", 5)...)
		reqs = append(reqs, repeatReq("200.200.0.1", 2)...)
		v := newOverlayView(reqs, "0.0.0.0/0")

		text := v.generateRenderText()
		// 3 populated blocks each get a full ● (ratio 1.0), plus exactly one
		// "[red]●" in the dot legend line.
		if got, want := strings.Count(text, "[red]●"), 3+1; got != want {
			t.Errorf("count of [red]● = %d, want %d", got, want)
		}
	})

	t.Run("single populated bin half captured", func(t *testing.T) {
		// 2 requests inside the /24, 2 in the same /16 bin but outside it.
		reqs := repeatReq("10.20.0.1", 2)
		reqs = append(reqs, repeatReq("10.20.1.1", 2)...)
		v := newOverlayView(reqs, "10.20.0.0/24")

		text := v.generateRenderText()
		// Only populated cell == busiest cell -> white; capture 2/4 = 0.5 -> •.
		if !strings.Contains(text, "[white]█[red]•[white]█[white]") {
			t.Errorf("render text missing white+• cell for half-captured single bin")
		}
	})

	t.Run("maxTraffic zero shows loading", func(t *testing.T) {
		v := newOverlayView(nil)
		text := v.generateRenderText()
		if !strings.Contains(text, "Loading traffic data") {
			t.Errorf("render text missing loading message for empty data")
		}
	})
}

// newBenchRenderView builds a fully populated 256x256 view with a ~10-range
// cluster set and the clustered grid pre-seeded in the cache, so render
// benchmarks isolate rendering cost.
func newBenchRenderView() *VisualizationView {
	cidrStrs := []string{
		"14.169.0.0/16", "14.186.0.0/15", "14.191.0.0/16",
		"113.172.0.0/15", "123.20.0.0/16", "45.40.50.192/26",
		"20.171.207.2/32", "152.88.205.0/24", "14.160.0.0/12", "10.0.0.0/8",
	}

	app := &App{}
	app.jsonResult = &output.JSONOutput{}
	app.jsonResult.Clustering.Data = []output.ClusterResult{*newClusterSet(cidrStrs...)}

	v := &VisualizationView{
		app:                 app,
		totalClusterSets:    1,
		currentClusterSet:   0,
		cachedClusteredData: make(map[clusterKey][256][256]uint32),
	}

	rng := rand.New(rand.NewSource(7))
	for a := 0; a < 256; a++ {
		for bb := 0; bb < 256; bb++ {
			tr := uint32(rng.Intn(10000))
			v.trafficData[a][bb] = tr
			if tr > v.maxTraffic {
				v.maxTraffic = tr
			}
			v.clusteredData[a][bb] = tr / uint32(1+rng.Intn(4))
		}
	}
	// Seed the clustered-grid cache so ensureClusteredData is a cache hit.
	v.cachedClusteredData[v.clusteredCacheKey()] = v.clusteredData
	return v
}

// BenchmarkGenerateRenderText measures full render-text generation over fully
// populated 256x256 grids with a ~10-range cluster set, at every supported
// display resolution (blockScale = /16 bins per cell side; 8 is the default).
func BenchmarkGenerateRenderText(b *testing.B) {
	for _, scale := range []int{16, 8, 4, 2, 1} {
		grid := 256 / scale
		b.Run(fmt.Sprintf("grid_%dx%d_scale_%d", grid, grid, scale), func(b *testing.B) {
			v := newBenchRenderView()
			v.blockScale = scale
			text := v.generateRenderText()
			b.ReportMetric(float64(len(text)), "text-bytes")
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = v.generateRenderText()
			}
		})
	}
}

// BenchmarkSetRenderText measures tview.TextView.SetText with the rendered
// heatmap at every resolution — the one-time cost paid when a (trie, cluster
// set) view is swapped in. Drawing afterwards only touches visible lines.
func BenchmarkSetRenderText(b *testing.B) {
	for _, scale := range []int{16, 8, 4, 2, 1} {
		grid := 256 / scale
		b.Run(fmt.Sprintf("grid_%dx%d_scale_%d", grid, grid, scale), func(b *testing.B) {
			v := newBenchRenderView()
			v.blockScale = scale
			text := v.generateRenderText()
			view := tview.NewTextView().SetDynamicColors(true).SetScrollable(true).SetWrap(false)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				view.SetText(text)
			}
		})
	}
}

// makeClusteredRequests synthesizes n requests with a clustered IP distribution:
// a configurable fraction lands inside the given cluster CIDRs, the rest is
// spread across random /16s outside them.
func makeClusteredRequests(n int, clusteredFrac float64, cidrs []*net.IPNet) []ingestor.Request {
	rng := rand.New(rand.NewSource(42))
	reqs := make([]ingestor.Request, n)
	for i := range reqs {
		var ip uint32
		if rng.Float64() < clusteredFrac && len(cidrs) > 0 {
			cn := cidrs[rng.Intn(len(cidrs))]
			base := iputils.IPToUint32(cn.IP)
			ones, _ := cn.Mask.Size()
			hostBits := 32 - ones
			var off uint32
			if hostBits > 0 && hostBits < 32 {
				off = rng.Uint32() & ((1 << hostBits) - 1)
			}
			ip = base | off
		} else {
			ip = rng.Uint32()
		}
		if ip == 0 {
			ip = 1
		}
		reqs[i].IPUint32 = ip
	}
	return reqs
}

// BenchmarkProcessTrafficData measures the single-pass build of the traffic grid
// PLUS the clustered-overlay grid over 1,000,000 requests with a representative
// cluster set. The clustered membership test must add only a small constant
// overhead, not multiply the cost.
func BenchmarkProcessTrafficData(b *testing.B) {
	cidrStrs := []string{
		"14.169.0.0/16", "14.186.0.0/15", "14.191.0.0/16",
		"113.172.0.0/15", "123.20.0.0/16", "45.40.50.192/26",
		"20.171.207.2/32", "152.88.205.0/24", "14.160.0.0/12", "10.0.0.0/8",
	}
	refNets := mustCIDRs(b, cidrStrs...)
	reqs := makeClusteredRequests(1_000_000, 0.3, refNets)

	app := &App{}
	cs := newClusterSet(cidrStrs...)
	app.jsonResult = &output.JSONOutput{}
	app.jsonResult.Clustering.Data = []output.ClusterResult{*cs}

	v := &VisualizationView{
		app:                 app,
		totalClusterSets:    1,
		currentClusterSet:   0,
		cachedClusteredData: make(map[clusterKey][256][256]uint32),
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		v.ProcessTrafficData(reqs)
	}
}

// BenchmarkProcessTrafficDataNoClusters is the baseline: same pass but with an
// empty cluster set, isolating the membership-test overhead.
func BenchmarkProcessTrafficDataNoClusters(b *testing.B) {
	reqs := makeClusteredRequests(1_000_000, 0.0, nil)

	app := &App{}
	cs := newClusterSet()
	app.jsonResult = &output.JSONOutput{}
	app.jsonResult.Clustering.Data = []output.ClusterResult{*cs}

	v := &VisualizationView{
		app:                 app,
		totalClusterSets:    1,
		currentClusterSet:   0,
		cachedClusteredData: make(map[clusterKey][256][256]uint32),
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		v.ProcessTrafficData(reqs)
	}
}

// TestIntensityOfMapping checks both brightness mappings: linear endpoints and
// midpoint, log endpoints, strict monotonicity, and that the log legend
// thresholds round-trip through the inverse map.
func TestIntensityOfMapping(t *testing.T) {
	v := &VisualizationView{}
	const max = uint32(50000)

	// Linear mode.
	if got := v.intensityOf(0, max); got != 0 {
		t.Errorf("linear intensityOf(0) = %v, want 0", got)
	}
	if got := v.intensityOf(max, max); got != 1 {
		t.Errorf("linear intensityOf(max) = %v, want 1", got)
	}
	if got := v.intensityOf(25000, max); math.Abs(got-0.5) > 1e-9 {
		t.Errorf("linear intensityOf(max/2) = %v, want 0.5", got)
	}

	// Sqrt mode (power scale): sqrt(x/max), endpoints exact, middle lifted.
	v.scaleMode = scaleSqrt
	if got := v.intensityOf(0, max); got != 0 {
		t.Errorf("sqrt intensityOf(0) = %v, want 0", got)
	}
	if got := v.intensityOf(max, max); math.Abs(got-1) > 1e-12 {
		t.Errorf("sqrt intensityOf(max) = %v, want 1", got)
	}
	if got := v.intensityOf(500, max); math.Abs(got-0.1) > 1e-9 {
		t.Errorf("sqrt intensityOf(1%% of max) = %v, want 0.1", got)
	}
	if got := v.intensityOf(25000, max); math.Abs(got-math.Sqrt(0.5)) > 1e-9 {
		t.Errorf("sqrt intensityOf(max/2) = %v, want %v", got, math.Sqrt(0.5))
	}

	// Log mode.
	v.scaleMode = scaleLog
	if got := v.intensityOf(0, max); got != 0 {
		t.Errorf("log intensityOf(0) = %v, want 0", got)
	}
	if got := v.intensityOf(max, max); math.Abs(got-1) > 1e-12 {
		t.Errorf("log intensityOf(max) = %v, want 1", got)
	}
	if got := v.intensityOf(50, max); got < 0.3 || got > 0.45 {
		t.Errorf("log intensityOf(50) = %v, want visible mid-grey (~0.36)", got)
	}
	prev := -1.0
	for _, x := range []uint32{0, 1, 2, 10, 100, 1000, 10000, 50000} {
		got := v.intensityOf(x, max)
		if got <= prev {
			t.Errorf("log intensityOf not strictly increasing at %d: %v <= %v", x, got, prev)
		}
		prev = got
	}

	// Threshold round-trip in every mode: the count at the lower bound of
	// each legend step must map back to an intensity at or just above it.
	for _, mode := range []int{scaleLinear, scaleSqrt, scaleLog} {
		v.scaleMode = mode
		for step := 1; step <= 9; step++ {
			bound := float64(step) / 10
			count := v.intensityThresholdCount(bound, max)
			if got := v.intensityOf(count, max); got < bound || got > bound+0.05 {
				t.Errorf("mode %d threshold round-trip step %.1f: count %d maps to %v", mode, bound, count, got)
			}
		}
		// Zero max never divides by zero.
		if got := v.intensityOf(5, 0); got != 0 {
			t.Errorf("mode %d intensityOf with max=0 = %v, want 0", mode, got)
		}
	}
}

// TestLogScaleRenderAndCacheKeys checks that log mode renders its own legend,
// that the grid info line is present, and that linear/log render-text cache
// keys never collide.
func TestLogScaleRenderAndCacheKeys(t *testing.T) {
	v := newBenchRenderView()

	linear := v.generateRenderText()
	if !strings.Contains(linear, "(linear, 100% = busiest cell)") {
		t.Errorf("linear render missing linear legend")
	}
	if !strings.Contains(linear, "Grid: 32×32 cells - 1 cell = 8×8 /16 bins") {
		t.Errorf("render missing grid info line")
	}
	linKey := v.renderCacheKey(0, 0)

	v.scaleMode = scaleSqrt
	sqrtText := v.generateRenderText()
	if !strings.Contains(sqrtText, "(sqrt scale, 100% = busiest cell)") {
		t.Errorf("sqrt render missing sqrt legend")
	}
	if !strings.Contains(sqrtText, "sqrt scale, step label = requests") {
		t.Errorf("sqrt render missing request-count ramp labels")
	}
	sqrtKey := v.renderCacheKey(0, 0)

	v.scaleMode = scaleLog
	logText := v.generateRenderText()
	if !strings.Contains(logText, "(log scale, 100% = busiest cell)") {
		t.Errorf("log render missing log legend")
	}
	if !strings.Contains(logText, "log scale, step label = requests") {
		t.Errorf("log render missing request-count ramp labels")
	}
	if logText == linear || sqrtText == linear || logText == sqrtText {
		t.Errorf("scale-mode renders not distinct")
	}
	logKey := v.renderCacheKey(0, 0)
	if linKey == sqrtKey || linKey == logKey || sqrtKey == logKey {
		t.Errorf("scale-mode cache keys collide: %v %v %v", linKey, sqrtKey, logKey)
	}
}

// TestCacheKeysNoCompositeCollision guards against the old trie*1000+set int
// scheme, where (trie=1, set=1000) and (trie=2, set=0) both mapped to 2000.
func TestCacheKeysNoCompositeCollision(t *testing.T) {
	v := &VisualizationView{app: &App{}}

	if k1, k2 := v.renderCacheKey(1, 1000), v.renderCacheKey(2, 0); k1 == k2 {
		t.Errorf("render cache keys collide: %v == %v", k1, k2)
	}
	// Old mode offset also collided: (trie=1000,set=0,mode=0) vs (trie=0,set=0,mode=1).
	v.scaleMode = scaleLinear
	a := v.renderCacheKey(1000, 0)
	v.scaleMode = scaleSqrt
	if b := v.renderCacheKey(0, 0); a == b {
		t.Errorf("mode/trie cache keys collide: %v == %v", a, b)
	}

	cache := make(map[clusterKey][256][256]uint32)
	v.app.currentTrie, v.currentClusterSet = 1, 1000
	cache[v.clusteredCacheKey()] = [256][256]uint32{}
	v.app.currentTrie, v.currentClusterSet = 2, 0
	cache[v.clusteredCacheKey()] = [256][256]uint32{}
	if len(cache) != 2 {
		t.Errorf("clustered cache keys collide: (1,1000) and (2,0) share an entry")
	}
}

// TestTrafficMatrixIsGroundTruth verifies the traffic matrix shows ALL parsed
// requests and is identical for every trie — only the clustered overlay may
// differ per trie. Guards against re-introducing per-trie traffic filtering.
func TestTrafficMatrixIsGroundTruth(t *testing.T) {
	reqs := []ingestor.Request{
		reqFor("14.169.1.1"), reqFor("14.169.1.1"), reqFor("14.169.2.2"),
		reqFor("45.40.50.200"), reqFor("8.8.8.8"), reqFor("203.0.113.5"),
	}

	ftc := NewTrieCache()
	trieA := output.TrieResult{Name: "a", Data: []output.ClusterResult{*newClusterSet("14.169.0.0/16")}}
	trieB := output.TrieResult{Name: "b", Data: []output.ClusterResult{*newClusterSet("45.40.0.0/16")}}
	ftc.cacheTrafficData(0, reqs, trieA)
	ftc.cacheTrafficData(1, reqs, trieB)

	mA, maxA, okA := ftc.GetTrafficData(0)
	mB, maxB, okB := ftc.GetTrafficData(1)
	if !okA || !okB {
		t.Fatalf("traffic data missing: A=%v B=%v", okA, okB)
	}
	if mA != mB || maxA != maxB {
		t.Errorf("traffic matrix differs between tries — must be ground truth")
	}
	var total uint32
	for a := 0; a < 256; a++ {
		for b := 0; b < 256; b++ {
			total += mA[a][b]
		}
	}
	if total != uint32(len(reqs)) {
		t.Errorf("traffic total = %d, want all %d requests", total, len(reqs))
	}
	if mA[14][169] != 3 || maxA != 3 {
		t.Errorf("hot bin 14.169 = %d (max %d), want 3", mA[14][169], maxA)
	}

	// Clustered overlays ARE trie-specific.
	gA, okA := ftc.GetClusteredData(0, 0)
	gB, okB := ftc.GetClusteredData(1, 0)
	if !okA || !okB {
		t.Fatalf("clustered data missing: A=%v B=%v", okA, okB)
	}
	if gA[14][169] != 3 || gA[45][40] != 0 {
		t.Errorf("trie A overlay: 14.169=%d 45.40=%d, want 3 and 0", gA[14][169], gA[45][40])
	}
	if gB[45][40] != 1 || gB[14][169] != 0 {
		t.Errorf("trie B overlay: 45.40=%d 14.169=%d, want 1 and 0", gB[45][40], gB[14][169])
	}
}
