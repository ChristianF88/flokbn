package analysis

import (
	"fmt"
	"math/rand"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/ChristianF88/flokbn/accesslog"
	"github.com/ChristianF88/flokbn/cidr"
	"github.com/ChristianF88/flokbn/config"
)

// runFilter drives one of the two filter paths with the trie's own time bounds
// and returns everything it produced.
func runFilter(t *testing.T, concurrent bool, reqs []accesslog.Request, tc *config.TrieConfig, m *cidr.UserAgentMatcher) filterCounts {
	t.Helper()
	bounds := makeTimeBounds(tc)
	if concurrent {
		return toFilterCounts(filterConcurrent(reqs, tc, bounds, m))
	}
	return toFilterCounts(filterSequential(reqs, tc, bounds, m))
}

// parityCorpus builds n pseudo-random requests (fixed seed): repeated and
// zero IPs, listed and unlisted User-Agents, several endpoints, timestamps
// across three days in two zones.
func parityCorpus(n int) []accesslog.Request {
	rng := rand.New(rand.NewSource(42))
	uas := []string{"Mozilla/5.0", "curl/7.68.0", "python-requests/2.28", "GoodBot/1.0", "goodbot/1.0", "EvilScanner/9", ""}
	uris := []string{"/api/data", "/login", "/admin/login", "/static/app.js", "/", ""}
	zones := []*time.Location{time.UTC, time.FixedZone("", 2*3600)}
	base := time.Date(2025, 2, 1, 0, 0, 0, 0, time.UTC)

	reqs := make([]accesslog.Request, n)
	for i := range reqs {
		ip := uint32(10<<24) | uint32(rng.Intn(1<<14)) // heavy repetition
		switch rng.Intn(20) {
		case 0:
			ip = 0 // invalid
		case 1, 2, 3:
			ip = rng.Uint32() | 1<<24
		}
		reqs[i] = accesslog.Request{
			IPUint32:  ip,
			UserAgent: uas[rng.Intn(len(uas))],
			URI:       uris[rng.Intn(len(uris))],
			Timestamp: base.Add(time.Duration(rng.Intn(3*24*3600)) * time.Second).In(zones[rng.Intn(len(zones))]),
		}
	}
	return reqs
}

func sortedCopy(ips []uint32) []uint32 {
	out := append([]uint32(nil), ips...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func sortedStrings(s []string) []string {
	out := append([]string(nil), s...)
	sort.Strings(out)
	return out
}

// TestConcurrentSequentialParity_Corpus: the concurrent and the sequential
// filter must select the same requests - the same multiset of IPs to insert,
// the same counters and the same User-Agent derived IP sets - for every filter
// combination, at sizes on both sides of the chunking boundaries.
func TestConcurrentSequentialParity_Corpus(t *testing.T) {
	matcher := cidr.NewUserAgentMatcher([]string{"GoodBot/1.0"}, []string{"EvilScanner/9"})
	start := time.Date(2025, 2, 1, 18, 0, 0, 0, time.UTC)
	end := time.Date(2025, 2, 3, 6, 0, 0, 0, time.UTC)

	configs := map[string]func() *config.TrieConfig{
		"no_trie_filter": func() *config.TrieConfig { return &config.TrieConfig{} },
		"ua_regex": func() *config.TrieConfig {
			return &config.TrieConfig{TrieCommon: config.TrieCommon{UserAgentRegex: "(?i)curl|goodbot|evil"}}
		},
		"endpoint_regex": func() *config.TrieConfig {
			return &config.TrieConfig{TrieCommon: config.TrieCommon{EndpointRegex: "^/(api|admin)/"}}
		},
		"wall_clock_window": func() *config.TrieConfig {
			tc := &config.TrieConfig{}
			tc.SetStartTimeBound(start, false, "")
			tc.SetEndTimeBound(end, false, "")
			return tc
		},
		"instant_window_and_regexes": func() *config.TrieConfig {
			tc := &config.TrieConfig{TrieCommon: config.TrieCommon{UserAgentRegex: "curl|python|Evil", EndpointRegex: "login"}}
			tc.SetStartTimeBound(start, true, "")
			tc.SetEndTimeBound(end, true, "")
			return tc
		},
		"matches_nothing": func() *config.TrieConfig {
			return &config.TrieConfig{TrieCommon: config.TrieCommon{EndpointRegex: "^/nope$"}}
		},
	}
	matchers := map[string]*cidr.UserAgentMatcher{"ua_lists": matcher, "no_ua_lists": nil}

	all := parityCorpus(120001)
	for _, n := range []int{0, 1, 4999, 5000, 5001, 50001, 120001} {
		reqs := all[:n]
		for cfgName, build := range configs {
			for matcherName, m := range matchers {
				t.Run(fmt.Sprintf("%d/%s/%s", n, cfgName, matcherName), func(t *testing.T) {
					tc := build()
					if err := compileRegex(&tc.TrieCommon); err != nil {
						t.Fatal(err)
					}
					seq := runFilter(t, false, reqs, tc, m)
					con := runFilter(t, true, reqs, tc, m)

					if seq.filteredRequestCount != con.filteredRequestCount ||
						seq.invalidIPCount != con.invalidIPCount ||
						seq.uaWhitelistExcluded != con.uaWhitelistExcluded {
						t.Errorf("counters diverged: sequential=%d/%d/%d concurrent=%d/%d/%d (filtered/invalid/uaExcluded)",
							seq.filteredRequestCount, seq.invalidIPCount, seq.uaWhitelistExcluded,
							con.filteredRequestCount, con.invalidIPCount, con.uaWhitelistExcluded)
					}
					if seq.filteredRequestCount != len(seq.ipsToInsert) || con.filteredRequestCount != len(con.ipsToInsert) {
						t.Errorf("filtered count != inserted IPs: sequential %d/%d concurrent %d/%d",
							seq.filteredRequestCount, len(seq.ipsToInsert), con.filteredRequestCount, len(con.ipsToInsert))
					}
					if !reflect.DeepEqual(sortedCopy(seq.ipsToInsert), sortedCopy(con.ipsToInsert)) {
						t.Errorf("IPs to insert diverged (sequential %d, concurrent %d)", len(seq.ipsToInsert), len(con.ipsToInsert))
					}
					if !reflect.DeepEqual(sortedStrings(seq.whitelistIPs), sortedStrings(con.whitelistIPs)) {
						t.Errorf("UA whitelist IP sets diverged: sequential %d concurrent %d", len(seq.whitelistIPs), len(con.whitelistIPs))
					}
					if !reflect.DeepEqual(sortedStrings(seq.blacklistIPs), sortedStrings(con.blacklistIPs)) {
						t.Errorf("UA blacklist IP sets diverged: sequential %d concurrent %d", len(seq.blacklistIPs), len(con.blacklistIPs))
					}
				})
			}
		}
	}
}
