package config

import (
	"math/rand"
	"regexp"
	"strings"
	"testing"

	"github.com/ChristianF88/flokbn/ingestor"
)

// referenceShouldInclude mirrors the ORIGINAL semantics of
// TrieConfig.ShouldIncludeRequest exactly (empty short-circuit + plain regex,
// no prefilter). It is the source of truth the prefilter-enabled path must
// match for every request.
func referenceShouldInclude(uaRE, epRE *regexp.Regexp, req ingestor.Request) bool {
	if uaRE != nil {
		if req.UserAgent == "" || !uaRE.MatchString(req.UserAgent) {
			return false
		}
	}
	if epRE != nil {
		if req.URI == "" || !epRE.MatchString(req.URI) {
			return false
		}
	}
	return true
}

// TestShouldIncludeRequest_PrefilterEqualsPlain proves that the wired-in
// prefilter (including the empty-field short-circuit) produces results
// identical to the plain-regex reference for a large generated request set.
func TestShouldIncludeRequest_PrefilterEqualsPlain(t *testing.T) {
	const (
		uaPat = `(?i)(bot|crawl|spider|python-requests|curl|wget|nikto|sqlmap|scan|masscan|Mobile)`
		epPat = `(?i)(/dataset|/psi|/islandora|/search|/admin|/api)`
	)

	cases := []struct {
		name  string
		uaPat string
		epPat string
	}{
		{"both filters", uaPat, epPat},
		{"ua only", uaPat, ""},
		{"endpoint only", "", epPat},
		{"concat ua general", `(?i)bot/\d+`, epPat},
		{"bailed ua dotstar", `.*`, epPat},
		{"no filters", "", ""},
	}

	reqs := generateRequests(2000)

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tc := &TrieConfig{UserAgentRegex: c.uaPat, EndpointRegex: c.epPat}
			if err := tc.CompileRegex(); err != nil {
				t.Fatalf("CompileRegex: %v", err)
			}
			stc := &SlidingTrieConfig{UserAgentRegex: c.uaPat, EndpointRegex: c.epPat}
			if err := stc.CompileRegex(); err != nil {
				t.Fatalf("CompileRegex (sliding): %v", err)
			}

			var refUA, refEP *regexp.Regexp
			if c.uaPat != "" {
				refUA = regexp.MustCompile(c.uaPat)
			}
			if c.epPat != "" {
				refEP = regexp.MustCompile(c.epPat)
			}

			for _, req := range reqs {
				want := referenceShouldInclude(refUA, refEP, req)
				if got := tc.ShouldIncludeRequest(req); got != want {
					t.Fatalf("TrieConfig mismatch UA=%q URI=%q got=%v want=%v", req.UserAgent, req.URI, got, want)
				}
				if got := stc.ShouldIncludeRequest(req); got != want {
					t.Fatalf("SlidingTrieConfig mismatch UA=%q URI=%q got=%v want=%v", req.UserAgent, req.URI, got, want)
				}
			}
		})
	}
}

// generateRequests builds a varied request set including empty UA / empty URI,
// matching and non-matching tokens, and mixed case.
func generateRequests(n int) []ingestor.Request {
	rng := rand.New(rand.NewSource(99))
	uaTokens := []string{"bot", "BOT", "crawl", "Spider", "python-requests", "curl", "WGET", "Mobile", "scan", "masscan", ""}
	uaFill := []string{"Mozilla/5.0", "AppleWebKit/537.36", "Safari", "Chrome/120", "compatible", ""}
	uris := []string{"/dataset/1", "/API/x", "/Search?q=1", "/admin", "/static/app.js", "/favicon.ico", "/home", ""}

	out := make([]ingestor.Request, n)
	for i := range out {
		ua := uaFill[rng.Intn(len(uaFill))]
		if rng.Intn(2) == 0 {
			t := uaTokens[rng.Intn(len(uaTokens))]
			if ua == "" {
				ua = t
			} else if t != "" {
				ua = ua + " " + t
			}
		}
		// Occasionally force a fully empty UA.
		if rng.Intn(8) == 0 {
			ua = ""
		}
		uri := uris[rng.Intn(len(uris))]
		out[i] = ingestor.Request{UserAgent: strings.TrimSpace(ua), URI: uri}
	}
	return out
}
