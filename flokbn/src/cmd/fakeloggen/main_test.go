package main

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

const testLines = 10_000

// lineRe matches the exact generated line shape, capturing the leading IP,
// the timestamp, and the trailing quoted IP.
var lineRe = regexp.MustCompile(
	`^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - - \[(\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2} \+0000)\] ` +
		`"GET /fake-endpoint-(\d{1,3}) HTTP/1\.[01]" (200|301|304|404|500) \d+ "-" "([^"]+)" "(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"$`)

func TestGenerateShapeAndDistributions(t *testing.T) {
	out := filepath.Join(t.TempDir(), "fake.log")
	f, err := os.Create(out)
	if err != nil {
		t.Fatalf("create temp log: %v", err)
	}
	if err := generate(f, testLines, 42); err != nil {
		t.Fatalf("generate: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close temp log: %v", err)
	}

	f, err = os.Open(out)
	if err != nil {
		t.Fatalf("reopen temp log: %v", err)
	}
	defer f.Close()

	minTime := startTime.Add(-jitter)
	maxTime := startTime.Add(logSpan + jitter)

	var (
		total        int
		hotspotHits  = make(map[uint32]int) // /16 prefix -> count
		uaSeen       = make(map[string]bool)
		endpointHits = make(map[string]int)
	)
	hotspotSet := make(map[uint32]bool, len(hotspots))
	for _, h := range hotspots {
		hotspotSet[h.base>>16] = true
	}

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<16), 1<<16)
	for sc.Scan() {
		line := sc.Text()
		m := lineRe.FindStringSubmatch(line)
		if m == nil {
			t.Fatalf("line %d does not match expected shape: %q", total+1, line)
		}
		if m[1] != m[6] {
			t.Fatalf("line %d: leading IP %q != trailing IP %q", total+1, m[1], m[6])
		}

		ts, err := time.Parse("02/Jan/2006:15:04:05 -0700", m[2])
		if err != nil {
			t.Fatalf("line %d: bad timestamp %q: %v", total+1, m[2], err)
		}
		if ts.Before(minTime) || ts.After(maxTime) {
			t.Fatalf("line %d: timestamp %v outside [%v, %v]", total+1, ts, minTime, maxTime)
		}

		parts := strings.SplitN(m[1], ".", 3)
		a, err := strconv.ParseUint(parts[0], 10, 8)
		if err != nil {
			t.Fatalf("line %d: bad IP %q: %v", total+1, m[1], err)
		}
		b, err := strconv.ParseUint(parts[1], 10, 8)
		if err != nil {
			t.Fatalf("line %d: bad IP %q: %v", total+1, m[1], err)
		}
		if prefix := uint32(a)<<8 | uint32(b); hotspotSet[prefix] {
			hotspotHits[prefix]++
		}
		uaSeen[m[5]] = true
		endpointHits[m[3]]++
		total++
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if total != testLines {
		t.Fatalf("got %d lines, want %d", total, testLines)
	}

	// Both exact UA-whitelist strings must be present (intentional collision
	// with config_examples/ua_whitelist.txt).
	for _, ua := range []string{
		"Googlebot/2.1 (+http://www.google.com/bot.html)",
		"Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
	} {
		if !uaSeen[ua] {
			t.Errorf("exact whitelist UA %q not present in output", ua)
		}
	}

	// Heaviest hotspot 23.253.0.0/16 should carry ~2% of traffic.
	share := func(prefix uint32) float64 {
		return float64(hotspotHits[prefix]) / float64(total)
	}
	if s := share(23<<8 | 253); s < 0.012 || s > 0.030 {
		t.Errorf("23.253.0.0/16 share = %.4f, want ~0.020 (0.012..0.030)", s)
	}

	// All 10 hotspots together should carry ~12.9% of traffic.
	hotspotTotal := 0
	for _, c := range hotspotHits {
		hotspotTotal += c
	}
	if s := float64(hotspotTotal) / float64(total); s < 0.10 || s > 0.16 {
		t.Errorf("hotspot total share = %.4f, want ~0.129 (0.10..0.16)", s)
	}

	// Zipf endpoints: the top endpoint should carry ~23% of traffic.
	if s := float64(endpointHits["1"]) / float64(total); s < 0.19 || s > 0.28 {
		t.Errorf("/fake-endpoint-1 share = %.4f, want ~0.23 (0.19..0.28)", s)
	}
}

func TestGenerateDeterministic(t *testing.T) {
	var a, b bytes.Buffer
	if err := generate(&a, 1000, 7); err != nil {
		t.Fatalf("generate a: %v", err)
	}
	if err := generate(&b, 1000, 7); err != nil {
		t.Fatalf("generate b: %v", err)
	}
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Error("same seed produced different output")
	}
	var c bytes.Buffer
	if err := generate(&c, 1000, 8); err != nil {
		t.Fatalf("generate c: %v", err)
	}
	if bytes.Equal(a.Bytes(), c.Bytes()) {
		t.Error("different seeds produced identical output")
	}
}

func BenchmarkGenerate(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if err := generate(io.Discard, testLines, 42); err != nil {
			b.Fatal(err)
		}
	}
}
