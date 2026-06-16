package cidr

// Demo-data benchmark for the whitelist/ban-list publish path.
//
// It reconstructs the exact (source-IP, user-agent) pairs that
// `flokbn generate static-demo` would emit (same PCG seed, same draw order,
// same hotspot/UA weights as cli/synthlog.go) WITHOUT needing the full binary
// or any network-fetched dependency. It replays only that RNG sub-stream, not
// the rendered log lines (timestamps/sizes/etc. are drawn and discarded to keep
// the PRNG aligned). From that pair stream it derives a
// representative blacklist/whitelist of the SHAPE the static pipeline produces
// (the exact jailing heuristic here is a stand-in, not the real clusterer):
//
//   - blacklist : the 10 weighted /16 hotspots, plus — only at very large line
//                 counts — a handful of background /24s that happen to collect
//                 >=4 hits (B is 10 at 100k/300k lines, 16 at 1M).
//   - whitelist : the scattered /32 bot IPs (Googlebot/bingbot UA) that
//                 land inside the jailed hotspots — the "interior holes"
//                 described in DropFullyWhitelisted's doc comment.
//
// The load-bearing shape is a small blacklist (B≈10-16) against a LARGE
// whitelist of scattered /32s (W up to ~14k), which is what makes the old
// O(B*W) net.ParseCIDR re-parsing in RemoveWhitelisted dominate.

import (
	"fmt"
	"math/rand/v2"
	"sort"
	"testing"
)

// ---- mirror of cli/synthlog.go constants (kept local; cli/ is not
// buildable offline because its package imports network-fetched deps) ----

type demoHotspot struct {
	base   uint32
	weight float64
}

func demoIPv4(a, b, c, d byte) uint32 {
	return uint32(a)<<24 | uint32(b)<<16 | uint32(c)<<8 | uint32(d)
}

var demoHotspots = []demoHotspot{
	{demoIPv4(23, 253, 0, 0), 0.01988},
	{demoIPv4(143, 173, 0, 0), 0.01788},
	{demoIPv4(183, 77, 0, 0), 0.01688},
	{demoIPv4(87, 26, 0, 0), 0.01683},
	{demoIPv4(166, 94, 0, 0), 0.01399},
	{demoIPv4(50, 231, 0, 0), 0.01331},
	{demoIPv4(35, 217, 0, 0), 0.01274},
	{demoIPv4(154, 29, 0, 0), 0.01022},
	{demoIPv4(56, 110, 0, 0), 0.00889},
	{demoIPv4(129, 94, 0, 0), 0.00845},
}

// UA weights from cli/synthlog.go; indices 8 and 9 are Googlebot and
// bingbot (the UA-whitelisted bots, ~10.4% of traffic combined).
var demoUAWeights = []float64{
	0.2518, 0.1552, 0.1165, 0.0953, 0.0816,
	0.0718, 0.0648, 0.0586, 0.0539, 0.0505,
}

const demoSeed uint64 = 42

const (
	demoBytesMin = 1800
	demoBytesMax = 8800
)

func demoCumulative(weights []float64) []float64 {
	cum := make([]float64, len(weights))
	total := 0.0
	for i, w := range weights {
		total += w
		cum[i] = total
	}
	return cum
}

func demoPick(cum []float64, r float64) int {
	if len(cum) > 0 && r >= cum[len(cum)-1] {
		return len(cum) - 1
	}
	return sort.SearchFloat64s(cum, r)
}

func demoIsReserved(ip uint32) bool {
	a := byte(ip >> 24)
	b := byte(ip >> 16)
	switch {
	case a == 10 || a == 127:
		return true
	case a == 172 && b >= 16 && b < 32:
		return true
	case a == 192 && b == 168:
		return true
	case a == 169 && b == 254:
		return true
	}
	return false
}

func demoRandomBackgroundIP(rng *rand.Rand) uint32 {
	const lo, hi = uint32(0x01000000), uint32(0xDFFFFFFF)
	for {
		ip := lo + rng.Uint32N(hi-lo+1)
		if !demoIsReserved(ip) {
			return ip
		}
	}
}

func demoHotspotOf(ip uint32) (uint32, bool) {
	net16 := ip & 0xFFFF0000
	for _, h := range demoHotspots {
		if h.base == net16 {
			return net16, true
		}
	}
	return 0, false
}

// demoStream replays n lines of the synthetic generator's RNG draws in the
// SAME order as generateSyntheticLog, yielding (ip, uaIndex) per line so the
// derived (ip, ua) sequence matches the demo's for a given seed. It replays
// only the RNG sub-stream, not the log bytes (timestamps/sizes/etc. are drawn
// and discarded purely to keep the PRNG aligned).
func demoStream(n int, fn func(ip uint32, ua int)) {
	rng := rand.New(rand.NewPCG(demoSeed, demoSeed))

	hotspotWeights := make([]float64, len(demoHotspots))
	for i, h := range demoHotspots {
		hotspotWeights[i] = h.weight
	}
	hotspotCum := demoCumulative(hotspotWeights)
	hotspotTotal := hotspotCum[len(hotspotCum)-1]
	uaCum := demoCumulative(demoUAWeights)
	uaTotal := uaCum[len(uaCum)-1]

	for i := 0; i < n; i++ {
		var ip uint32
		if r := rng.Float64(); r < hotspotTotal {
			h := demoHotspots[demoPick(hotspotCum, r)]
			ip = h.base | rng.Uint32N(1<<16)
		} else {
			ip = demoRandomBackgroundIP(rng)
		}
		// jitter draw (value unused, but keeps RNG sequence aligned)
		_ = rng.Int64N(2*int64(5*60*1e9) + 1)
		_ = rng.Float64() // endpoint draw, value unused, keeps RNG aligned
		_ = rng.Float64() // status
		ua := demoPick(uaCum, rng.Float64()*uaTotal)
		_ = demoBytesMin + rng.IntN(demoBytesMax-demoBytesMin+1) // size
		_ = rng.IntN(2)                                          // proto
		fn(ip, ua)
	}
}

func cidrStr(ip uint32, prefix int) string {
	return fmt.Sprintf("%d.%d.%d.%d/%d", byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip), prefix)
}

// buildDemoBanData derives (blacklist, whitelist) for n demo lines.
func buildDemoBanData(n int) (blacklist, whitelist []string) {
	type void struct{}
	botHoles := make(map[uint32]void)    // /32 bot IPs inside hotspots -> whitelist
	bg24 := make(map[uint32]int)         // background /24 -> distinct-ish hit count
	hotspotSeen := make(map[uint32]void) // hotspot /16 networks actually hit

	demoStream(n, func(ip uint32, ua int) {
		isBot := ua == 8 || ua == 9
		if net16, ok := demoHotspotOf(ip); ok {
			hotspotSeen[net16] = void{}
			if isBot {
				botHoles[ip] = void{}
			}
			return
		}
		bg24[ip&0xFFFFFF00]++
	})

	// blacklist: jailed hotspot /16s + busy background /24s (>=4 hits).
	for net16 := range hotspotSeen {
		blacklist = append(blacklist, cidrStr(net16, 16))
	}
	for net24, hits := range bg24 {
		if hits >= 4 {
			blacklist = append(blacklist, cidrStr(net24, 24))
		}
	}
	sort.Strings(blacklist)

	// whitelist: scattered /32 bot holes inside the jailed hotspots.
	whitelist = make([]string, 0, len(botHoles))
	for ip := range botHoles {
		whitelist = append(whitelist, cidrStr(ip, 32))
	}
	sort.Strings(whitelist)
	return blacklist, whitelist
}

// BenchmarkDemoComposeBanLists exercises the publish choke point on the
// real demo distribution at a few line counts.
func BenchmarkDemoComposeBanLists(b *testing.B) {
	for _, n := range []int{100_000, 300_000, 1_000_000} {
		blacklist, whitelist := buildDemoBanData(n)
		b.Run(fmt.Sprintf("lines=%d/B=%d/W=%d", n, len(blacklist), len(whitelist)), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				pubBans, pubBlack := ComposeBanLists(blacklist, nil, whitelist)
				_ = pubBans
				_ = pubBlack
			}
		})
	}
}

// BenchmarkDemoDropFullyWhitelisted benchmarks the already-optimized
// O(B+W) path on the same data, as a reference point.
func BenchmarkDemoDropFullyWhitelisted(b *testing.B) {
	blacklist, whitelist := buildDemoBanData(300_000)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		kept, dropped := DropFullyWhitelisted(blacklist, whitelist)
		_ = kept
		_ = dropped
	}
}
