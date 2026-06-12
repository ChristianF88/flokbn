// Command fakeloggen generates a fake nginx/Apache-combined access log whose
// statistical shape matches the (git-ignored) fake-logs/ data set used by
// config_examples/complex-static.toml and the docs guide
// "Complex Static Analysis".
//
// Usage (from cidrx/src):
//
//	go run ./cmd/fakeloggen --lines 10000000 --out ../../fake-logs/fake_nginx_10m.log
//
// The output is deterministic for a given --seed (default 42).
//
// Line format (real client IP in the trailing quoted field):
//
//	IP - - [02/Feb/2026:15:04:05 +0000] "GET /fake-endpoint-N HTTP/1.1" 200 1234 "-" "UA" "IP"
//
// Distributions (measured from the original fake_nginx_2m.log):
//   - ~13% of traffic concentrates in 10 weighted /16 hotspots
//     (23.253.0.0/16 is the heaviest at ~2%); the rest is uniform
//     public-IP background.
//   - 10 user agents with fixed weights, including the two EXACT strings
//     present in config_examples/ua_whitelist.txt (Googlebot + bingbot,
//     together ~10.4%) — the whitelist collision is intentional.
//   - 100 endpoints /fake-endpoint-1 ... /fake-endpoint-100, Zipf-like
//     (s=1.1): the top endpoint carries ~23% of requests, the top 9 ~60%.
//   - Timestamps ascend over 72h starting 2026-02-03T23:56:44Z with
//     +-5 min jitter; statuses 200:60% 301/304/404/500:10% each;
//     bytes uniform in [1800, 8800]; protocol HTTP/1.0 or HTTP/1.1.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"math"
	"math/rand/v2"
	"os"
	"sort"
	"strconv"
	"time"
)

// startTime is the timestamp of the (jitter-free) first line; the last line
// lands ~72h later, matching the original fake-logs data set.
var startTime = time.Date(2026, time.February, 3, 23, 56, 44, 0, time.UTC)

// logSpan is the time range covered by the generated log.
const logSpan = 72 * time.Hour

// jitter is the maximum forward/backward deviation of each timestamp from
// its ascending base, making the log "ascending-ish" like real traffic.
const jitter = 5 * time.Minute

// hotspot is a weighted /16 source-IP hotspot.
type hotspot struct {
	base   uint32  // network address of the /16, host byte order
	weight float64 // fraction of total traffic
}

// hotspots are the 10 weighted /16 hotspots; weights are the shares measured
// in the original fake_nginx_2m.log. IPs inside a hotspot are uniform within
// its /16.
var hotspots = []hotspot{
	{ipv4(23, 253, 0, 0), 0.01988},
	{ipv4(143, 173, 0, 0), 0.01788},
	{ipv4(183, 77, 0, 0), 0.01688},
	{ipv4(87, 26, 0, 0), 0.01683},
	{ipv4(166, 94, 0, 0), 0.01399},
	{ipv4(50, 231, 0, 0), 0.01331},
	{ipv4(35, 217, 0, 0), 0.01274},
	{ipv4(154, 29, 0, 0), 0.01022},
	{ipv4(56, 110, 0, 0), 0.00889},
	{ipv4(129, 94, 0, 0), 0.00845},
}

// userAgents and uaWeights are the 10 fake user agents with their measured
// shares. The Googlebot and bingbot strings are EXACT matches for entries in
// config_examples/ua_whitelist.txt — deliberate, to demonstrate UA-whitelist
// precedence (~10.4% of all requests are whitelisted away).
var userAgents = []string{
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

var uaWeights = []float64{
	0.2518, 0.1552, 0.1165, 0.0953, 0.0816,
	0.0718, 0.0648, 0.0586, 0.0539, 0.0505,
}

// statuses and statusWeights are the HTTP status codes with their measured
// shares.
var statuses = []string{"200", "301", "304", "404", "500"}
var statusWeights = []float64{0.60, 0.10, 0.10, 0.10, 0.10}

const (
	numEndpoints = 100
	zipfS        = 1.1 // endpoint popularity ~ 1/rank^s
	bytesMin     = 1800
	bytesMax     = 8800
)

func ipv4(a, b, c, d byte) uint32 {
	return uint32(a)<<24 | uint32(b)<<16 | uint32(c)<<8 | uint32(d)
}

// cumulative turns weights into a cumulative distribution over [0, sum).
func cumulative(weights []float64) []float64 {
	cum := make([]float64, len(weights))
	total := 0.0
	for i, w := range weights {
		total += w
		cum[i] = total
	}
	return cum
}

// pick returns the index of the first cumulative bucket containing r.
// r must be in [0, cum[len(cum)-1]).
func pick(cum []float64, r float64) int {
	return sort.SearchFloat64s(cum, r)
}

// endpointWeights returns the Zipf(s) popularity weights for the endpoints,
// normalized to sum to 1.
func endpointWeights() []float64 {
	w := make([]float64, numEndpoints)
	total := 0.0
	for i := range w {
		w[i] = 1.0 / math.Pow(float64(i+1), zipfS)
		total += w[i]
	}
	for i := range w {
		w[i] /= total
	}
	return w
}

// isReserved reports whether the /16 containing ip overlaps private,
// loopback, or link-local space that must not appear as background traffic
// (and would collide with config_examples/whitelist.txt).
func isReserved(ip uint32) bool {
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

// randomBackgroundIP returns a uniform public unicast IPv4 address
// (1.0.0.0 - 223.255.255.255 minus reserved ranges).
func randomBackgroundIP(rng *rand.Rand) uint32 {
	const lo, hi = uint32(0x01000000), uint32(0xDFFFFFFF) // 1.0.0.0 .. 223.255.255.255
	for {
		ip := lo + rng.Uint32N(hi-lo+1)
		if !isReserved(ip) {
			return ip
		}
	}
}

// appendIP appends the dotted-quad form of ip to buf.
func appendIP(buf []byte, ip uint32) []byte {
	buf = strconv.AppendUint(buf, uint64(ip>>24), 10)
	buf = append(buf, '.')
	buf = strconv.AppendUint(buf, uint64(ip>>16&0xFF), 10)
	buf = append(buf, '.')
	buf = strconv.AppendUint(buf, uint64(ip>>8&0xFF), 10)
	buf = append(buf, '.')
	buf = strconv.AppendUint(buf, uint64(ip&0xFF), 10)
	return buf
}

// generate writes n log lines to w using the seeded rng. It is the testable
// core of the command.
func generate(w io.Writer, n int64, seed uint64) error {
	rng := rand.New(rand.NewPCG(seed, seed))

	hotspotWeights := make([]float64, len(hotspots))
	for i, h := range hotspots {
		hotspotWeights[i] = h.weight
	}
	hotspotCum := cumulative(hotspotWeights)
	hotspotTotal := hotspotCum[len(hotspotCum)-1]
	uaCum := cumulative(uaWeights)
	uaTotal := uaCum[len(uaCum)-1]
	epCum := cumulative(endpointWeights())
	statusCum := cumulative(statusWeights)

	step := float64(logSpan) / float64(n)
	jit := int64(jitter)

	bw := bufio.NewWriterSize(w, 1<<20)
	buf := make([]byte, 0, 512)
	for i := range n {
		// Source IP: weighted hotspot or uniform public background.
		var ip uint32
		if r := rng.Float64(); r < hotspotTotal {
			h := hotspots[pick(hotspotCum, r)]
			ip = h.base | rng.Uint32N(1<<16)
		} else {
			ip = randomBackgroundIP(rng)
		}

		// Ascending base time + uniform jitter.
		offset := max(int64(float64(i)*step)+rng.Int64N(2*jit+1)-jit, 0)
		ts := startTime.Add(time.Duration(offset))

		endpoint := pick(epCum, rng.Float64()) + 1
		status := statuses[pick(statusCum, rng.Float64())]
		ua := userAgents[pick(uaCum, rng.Float64()*uaTotal)]
		size := bytesMin + rng.IntN(bytesMax-bytesMin+1)
		proto := "HTTP/1.1"
		if rng.IntN(2) == 0 {
			proto = "HTTP/1.0"
		}

		buf = buf[:0]
		buf = appendIP(buf, ip)
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
		buf = appendIP(buf, ip)
		buf = append(buf, '"', '\n')
		if _, err := bw.Write(buf); err != nil {
			return err
		}
	}
	return bw.Flush()
}

func main() {
	lines := flag.Int64("lines", 10_000_000, "number of log lines to generate")
	out := flag.String("out", "", "output file path (required)")
	seed := flag.Uint64("seed", 42, "PRNG seed (same seed => identical output)")
	flag.Parse()

	if *out == "" {
		fmt.Fprintln(os.Stderr, "fakeloggen: --out is required")
		flag.Usage()
		os.Exit(2)
	}
	if *lines <= 0 {
		fmt.Fprintln(os.Stderr, "fakeloggen: --lines must be positive")
		os.Exit(2)
	}

	f, err := os.Create(*out)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fakeloggen: %v\n", err)
		os.Exit(1)
	}
	if err := generate(f, *lines, *seed); err != nil {
		f.Close()
		fmt.Fprintf(os.Stderr, "fakeloggen: %v\n", err)
		os.Exit(1)
	}
	if err := f.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "fakeloggen: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("fakeloggen: wrote %d lines to %s (seed %d)\n", *lines, *out, *seed)
}
