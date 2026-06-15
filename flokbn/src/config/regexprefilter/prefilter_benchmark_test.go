package regexprefilter

import (
	"math/rand"
	"regexp"
	"strings"
	"testing"
)

// Representative patterns matching the production bot/endpoint filters.
const (
	uaPattern       = `(?i)(bot|crawl|spider|python-requests|curl|wget|nikto|sqlmap|scan|masscan|Mobile)`
	endpointPattern = `(?i)(/dataset|/psi|/islandora|/search|/admin|/api)`
	concatPattern   = `(?i)bot/\d+`
	dotStarPattern  = `.*`
)

// uaNeedles are tokens we sprinkle into ~17% of synthesized UA strings (near
// the end, the worst case for RE2 since it must scan the whole string first).
var uaNeedles = []string{"bot", "crawl", "spider", "python-requests", "curl", "wget", "nikto", "sqlmap", "scan", "masscan", "Mobile"}

// uaFiller mimics realistic long, non-matching User-Agent strings.
const uaFiller = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Version/14.0 Safari/605.1.15 Edition"

// makeUACorpus synthesizes n UA-like strings: ~83% non-matching long strings,
// ~17% containing a needle near the end.
func makeUACorpus(n int) []string {
	rng := rand.New(rand.NewSource(1))
	out := make([]string, n)
	for i := range out {
		base := uaFiller
		// Pad to 100-160 chars.
		for len(base) < 100+rng.Intn(60) {
			base += " compatible"
		}
		if rng.Intn(100) < 17 {
			base += " " + uaNeedles[rng.Intn(len(uaNeedles))] + "/1.0"
		}
		out[i] = base
	}
	return out
}

// makeEndpointCorpus synthesizes URI-like strings mostly starting with a
// non-matching path; ~17% contain a matching endpoint prefix.
func makeEndpointCorpus(n int) []string {
	rng := rand.New(rand.NewSource(2))
	eps := []string{"/dataset", "/psi", "/islandora", "/search", "/admin", "/api"}
	noise := []string{"/static/app.js", "/favicon.ico", "/images/logo.png", "/css/main.css", "/robots.txt"}
	out := make([]string, n)
	for i := range out {
		if rng.Intn(100) < 17 {
			out[i] = eps[rng.Intn(len(eps))] + "/resource/" + strings.Repeat("x", rng.Intn(40))
		} else {
			out[i] = noise[rng.Intn(len(noise))] + "?v=" + strings.Repeat("a", rng.Intn(40))
		}
	}
	return out
}

// makeConcatCorpus synthesizes inputs for the (?i)bot/\d+ pattern: ~17% contain
// "bot/<digits>", the rest are long non-matching UA strings.
func makeConcatCorpus(n int) []string {
	rng := rand.New(rand.NewSource(3))
	out := make([]string, n)
	for i := range out {
		base := uaFiller
		if rng.Intn(100) < 17 {
			base += " bot/42"
		}
		out[i] = base
	}
	return out
}

const corpusSize = 200_000

func benchScreen(b *testing.B, corpus []string, fn func(string) bool) {
	b.ReportAllocs()
	b.ResetTimer()
	var hits int
	for i := 0; i < b.N; i++ {
		if fn(corpus[i%len(corpus)]) {
			hits++
		}
	}
	_ = hits
}

func BenchmarkUA_PlainRE2(b *testing.B) {
	corpus := makeUACorpus(corpusSize)
	re := regexp.MustCompile(uaPattern)
	benchScreen(b, corpus, re.MatchString)
}

func BenchmarkUA_Prefilter(b *testing.B) {
	corpus := makeUACorpus(corpusSize)
	pf := Build(uaPattern)
	if pf == nil || !pf.Exact() {
		b.Fatalf("UA prefilter expected exact, got %+v", pf)
	}
	benchScreen(b, corpus, pf.MightMatch)
}

func BenchmarkEndpoint_PlainRE2(b *testing.B) {
	corpus := makeEndpointCorpus(corpusSize)
	re := regexp.MustCompile(endpointPattern)
	benchScreen(b, corpus, re.MatchString)
}

func BenchmarkEndpoint_Prefilter(b *testing.B) {
	corpus := makeEndpointCorpus(corpusSize)
	pf := Build(endpointPattern)
	if pf == nil || !pf.Exact() {
		b.Fatalf("endpoint prefilter expected exact, got %+v", pf)
	}
	benchScreen(b, corpus, pf.MightMatch)
}

func BenchmarkConcat_PlainRE2(b *testing.B) {
	corpus := makeConcatCorpus(corpusSize)
	re := regexp.MustCompile(concatPattern)
	benchScreen(b, corpus, re.MatchString)
}

// BenchmarkConcat_General exercises the necessary-screen path: prefilter screens
// then the RE2 confirms (non-exact). We model the full gate.
func BenchmarkConcat_General(b *testing.B) {
	corpus := makeConcatCorpus(corpusSize)
	re := regexp.MustCompile(concatPattern)
	pf := Build(concatPattern)
	if pf == nil || pf.Exact() {
		b.Fatalf("concat prefilter expected non-exact necessary screen, got %+v", pf)
	}
	gate := func(s string) bool {
		if !pf.MightMatch(s) {
			return false
		}
		return re.MatchString(s)
	}
	benchScreen(b, corpus, gate)
}

func BenchmarkBailed_DotStar_PlainRE2(b *testing.B) {
	corpus := makeUACorpus(corpusSize)
	re := regexp.MustCompile(dotStarPattern)
	benchScreen(b, corpus, re.MatchString)
}

// BenchmarkBailed_DotStar proves the prefilter path is not slower than plain
// when Build bails (pf==nil): the gate falls straight through to the regex,
// adding only a nil check.
func BenchmarkBailed_DotStar(b *testing.B) {
	corpus := makeUACorpus(corpusSize)
	re := regexp.MustCompile(dotStarPattern)
	pf := Build(dotStarPattern)
	if pf != nil {
		b.Fatalf("dotstar prefilter expected nil (bail), got %+v", pf)
	}
	gate := func(s string) bool {
		if pf != nil && !pf.MightMatch(s) {
			return false
		}
		return re.MatchString(s)
	}
	benchScreen(b, corpus, gate)
}
