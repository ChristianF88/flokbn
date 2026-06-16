package cli

// Synthetic access-log generator backing `flokbn generate static-demo`.
//
// It produces an nginx/Apache-combined access log whose statistical shape
// matches the (git-ignored) fake-logs/ data set used by the complex static
// example config and the "Complex Static Analysis" guide. Output is
// deterministic for a given seed.
//
// Line format (real client IP in the trailing quoted field):
//
//	IP - - [02/Feb/2026:15:04:05 +0000] "GET /fake-endpoint-N HTTP/1.1" 200 1234 "-" "UA" "IP"
//
// Distributions (measured from the original fake_nginx_2m.log):
//   - ~13.9% of traffic concentrates in 10 weighted /16 hotspots
//     (23.253.0.0/16 is the heaviest at ~2%); the rest is uniform
//     public-IP background.
//   - 10 user agents with fixed weights, including the two EXACT strings
//     present in the example UA whitelist (Googlebot + bingbot, together
//     ~10.4%) — the whitelist collision is intentional.
//   - 100 endpoints /fake-endpoint-1 ... /fake-endpoint-100, Zipf-like
//     (s=1.1): the top endpoint carries ~23% of requests, the top 9 ~60%.
//   - Timestamps ascend over 72h starting 2026-02-03T23:56:44Z with
//     +-5 min jitter; statuses 200:60% 301/304/404/500:10% each;
//     bytes uniform in [1800, 8800]; protocol HTTP/1.0 or HTTP/1.1.

import (
	"bufio"
	"fmt"
	"io"
	"math"
	"math/rand/v2"
	"sort"
	"strconv"
	"time"
)

// synthStartTime is the timestamp of the (jitter-free) first line; the last
// line lands ~72h later, matching the original fake-logs data set.
var synthStartTime = time.Date(2026, time.February, 3, 23, 56, 44, 0, time.UTC)

// synthLogSpan is the time range covered by the generated log.
const synthLogSpan = 72 * time.Hour

// synthJitter is the maximum forward/backward deviation of each timestamp from
// its ascending base, making the log "ascending-ish" like real traffic.
const synthJitter = 5 * time.Minute

// synthDefaultSeed preserves reproducibility with the historical generator.
const synthDefaultSeed uint64 = 42

// synthDefaultLines is the fixed line count `flokbn generate static-demo`
// always writes: large enough to showcase clustering while staying snappy to
// analyze, and the size the embedded config's cluster thresholds are calibrated
// for.
const synthDefaultLines int64 = 1_000_000

// synthHotspot is a weighted /16 source-IP hotspot.
type synthHotspot struct {
	base   uint32  // network address of the /16, host byte order
	weight float64 // fraction of total traffic
}

// synthHotspots are the 10 weighted /16 hotspots; weights are the shares
// measured in the original fake_nginx_2m.log. IPs inside a hotspot are uniform
// within its /16.
//
// NOTE: mirrored (with the UA weights, seed, byte range and the per-line draw
// order in generateSyntheticLog) in cidr/demo_compose_bench_test.go, which
// can't import this package offline. Keep the two in sync — a draw-order or
// weight change here silently desyncs that benchmark's derived data.
var synthHotspots = []synthHotspot{
	{synthIPv4(23, 253, 0, 0), 0.01988},
	{synthIPv4(143, 173, 0, 0), 0.01788},
	{synthIPv4(183, 77, 0, 0), 0.01688},
	{synthIPv4(87, 26, 0, 0), 0.01683},
	{synthIPv4(166, 94, 0, 0), 0.01399},
	{synthIPv4(50, 231, 0, 0), 0.01331},
	{synthIPv4(35, 217, 0, 0), 0.01274},
	{synthIPv4(154, 29, 0, 0), 0.01022},
	{synthIPv4(56, 110, 0, 0), 0.00889},
	{synthIPv4(129, 94, 0, 0), 0.00845},
}

// synthUserAgents and synthUAWeights are the 10 fake user agents with their
// measured shares. The Googlebot and bingbot strings are EXACT matches for
// entries in the example UA whitelist — deliberate, to demonstrate
// UA-whitelist precedence (~10.4% of all requests are whitelisted away).
var synthUserAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
	"Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
	"Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0 Mobile Safari/537.36",
	"curl/8.4.0",
	"python-requests/2.31.0",
	"Anubis-OGTag-Fetcher/1.0",
	"Googlebot/2.1 (+http://www.google.com/bot.html)",
	"Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
}

var synthUAWeights = []float64{
	0.2518, 0.1552, 0.1165, 0.0953, 0.0816,
	0.0718, 0.0648, 0.0586, 0.0539, 0.0505,
}

// synthStatuses and synthStatusWeights are the HTTP status codes with their
// measured shares.
var synthStatuses = []string{"200", "301", "304", "404", "500"}
var synthStatusWeights = []float64{0.60, 0.10, 0.10, 0.10, 0.10}

const (
	synthNumEndpoints = 100
	synthZipfS        = 1.1 // endpoint popularity ~ 1/rank^s
	synthBytesMin     = 1800
	synthBytesMax     = 8800
)

func synthIPv4(a, b, c, d byte) uint32 {
	return uint32(a)<<24 | uint32(b)<<16 | uint32(c)<<8 | uint32(d)
}

// synthCumulative turns weights into a cumulative distribution over [0, sum).
func synthCumulative(weights []float64) []float64 {
	cum := make([]float64, len(weights))
	total := 0.0
	for i, w := range weights {
		total += w
		cum[i] = total
	}
	return cum
}

// synthPick returns the index of the first cumulative bucket containing r.
// r must be in [0, cum[len(cum)-1]).
func synthPick(cum []float64, r float64) int {
	// Floating-point rounding (e.g. r computed as rng.Float64()*uaTotal where
	// uaTotal is itself an accumulated sum) can push r to or just past the
	// final cumulative weight. Clamp to the last bucket so SearchFloat64s never
	// returns len(cum), which callers would index out of bounds.
	if len(cum) > 0 && r >= cum[len(cum)-1] {
		return len(cum) - 1
	}
	return sort.SearchFloat64s(cum, r)
}

// synthEndpointWeights returns the Zipf(s) popularity weights for the
// endpoints, normalized to sum to 1.
func synthEndpointWeights() []float64 {
	w := make([]float64, synthNumEndpoints)
	total := 0.0
	for i := range w {
		w[i] = 1.0 / math.Pow(float64(i+1), synthZipfS)
		total += w[i]
	}
	for i := range w {
		w[i] /= total
	}
	return w
}

// synthIsReserved reports whether the /16 containing ip overlaps private,
// loopback, or link-local space that must not appear as background traffic
// (and would collide with the example whitelist).
func synthIsReserved(ip uint32) bool {
	a := byte(ip >> 24)
	b := byte(ip >> 16)
	switch {
	case a == 10 || a == 127: // 10.0.0.0/8, 127.0.0.0/8
		return true
	case a == 172 && b >= 16 && b < 32: // 172.16.0.0/12
		return true
	case a == 192 && b == 168: // 192.168.0.0/16
		return true
	case a == 169 && b == 254: // 169.254.0.0/16
		return true
	}
	return false
}

// synthRandomBackgroundIP returns a uniform public unicast IPv4 address
// (1.0.0.0 - 223.255.255.255 minus reserved ranges).
func synthRandomBackgroundIP(rng *rand.Rand) uint32 {
	const lo, hi = uint32(0x01000000), uint32(0xDFFFFFFF) // 1.0.0.0 .. 223.255.255.255
	for {
		ip := lo + rng.Uint32N(hi-lo+1)
		if !synthIsReserved(ip) {
			return ip
		}
	}
}

// synthAppendIP appends the dotted-quad form of ip to buf.
func synthAppendIP(buf []byte, ip uint32) []byte {
	buf = strconv.AppendUint(buf, uint64(ip>>24), 10)
	buf = append(buf, '.')
	buf = strconv.AppendUint(buf, uint64(ip>>16&0xFF), 10)
	buf = append(buf, '.')
	buf = strconv.AppendUint(buf, uint64(ip>>8&0xFF), 10)
	buf = append(buf, '.')
	buf = strconv.AppendUint(buf, uint64(ip&0xFF), 10)
	return buf
}

// generateSyntheticLog writes n synthetic log lines to w using a PRNG seeded
// with seed. It is deterministic: identical (n, seed) produce byte-identical
// output. It returns an error if n is not positive or if writing to w fails.
func generateSyntheticLog(w io.Writer, n int64, seed uint64) error {
	if n <= 0 {
		return fmt.Errorf("synthlog: lines must be positive, got %d", n)
	}
	rng := rand.New(rand.NewPCG(seed, seed))

	hotspotWeights := make([]float64, len(synthHotspots))
	for i, h := range synthHotspots {
		hotspotWeights[i] = h.weight
	}
	hotspotCum := synthCumulative(hotspotWeights)
	hotspotTotal := hotspotCum[len(hotspotCum)-1]
	uaCum := synthCumulative(synthUAWeights)
	uaTotal := uaCum[len(uaCum)-1]
	epCum := synthCumulative(synthEndpointWeights())
	statusCum := synthCumulative(synthStatusWeights)

	step := float64(synthLogSpan) / float64(n)
	jit := int64(synthJitter)

	bw := bufio.NewWriterSize(w, 1<<20)
	buf := make([]byte, 0, 512)
	for i := range n {
		// Source IP: weighted hotspot or uniform public background.
		var ip uint32
		if r := rng.Float64(); r < hotspotTotal {
			h := synthHotspots[synthPick(hotspotCum, r)]
			ip = h.base | rng.Uint32N(1<<16)
		} else {
			ip = synthRandomBackgroundIP(rng)
		}

		// Ascending base time + uniform jitter.
		offset := max(int64(float64(i)*step)+rng.Int64N(2*jit+1)-jit, 0)
		ts := synthStartTime.Add(time.Duration(offset))

		endpoint := synthPick(epCum, rng.Float64()) + 1
		status := synthStatuses[synthPick(statusCum, rng.Float64())]
		ua := synthUserAgents[synthPick(uaCum, rng.Float64()*uaTotal)]
		size := synthBytesMin + rng.IntN(synthBytesMax-synthBytesMin+1)
		proto := "HTTP/1.1"
		if rng.IntN(2) == 0 {
			proto = "HTTP/1.0"
		}

		buf = buf[:0]
		buf = synthAppendIP(buf, ip)
		buf = append(buf, " - - ["...)
		buf = ts.AppendFormat(buf, "02/Jan/2006:15:04:05 -0700")
		buf = append(buf, `] "GET /fake-endpoint-`...)
		buf = strconv.AppendInt(buf, int64(endpoint), 10)
		buf = append(buf, ' ')
		buf = append(buf, proto...)
		buf = append(buf, `" `...)
		buf = append(buf, status...)
		buf = append(buf, ' ')
		buf = strconv.AppendInt(buf, int64(size), 10)
		buf = append(buf, ` "-" "`...)
		buf = append(buf, ua...)
		buf = append(buf, `" "`...)
		buf = synthAppendIP(buf, ip)
		buf = append(buf, '"', '\n')
		if _, err := bw.Write(buf); err != nil {
			return err
		}
	}
	return bw.Flush()
}
