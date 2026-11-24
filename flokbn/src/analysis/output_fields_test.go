package analysis

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ChristianF88/flokbn/config"
	"github.com/ChristianF88/flokbn/output"
)

func writeTestFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
	return path
}

// compileTries compiles the regex filters of struct-literal trie configs (the
// TOML/CLI loaders do this; a bare literal leaves the filters inert).
func compileTries(t *testing.T, tries map[string]*config.TrieConfig) map[string]*config.TrieConfig {
	t.Helper()
	for name, tc := range tries {
		if err := tc.CompileRegex(); err != nil {
			t.Fatalf("CompileRegex(%q): %v", name, err)
		}
	}
	return tries
}

func logLine(ip, path, ua string) string {
	return fmt.Sprintf("%s - - [01/Jan/2023:12:00:00 +0000] \"GET %s HTTP/1.1\" 200 1 \"-\" \"%s\"\n", ip, path, ua)
}

// TestGeneralUniqueIPsCountsWholeLog: general.unique_ips describes the log, not
// a trie. It used to be the maximum of the per-trie (post-filter) counts, so
// with every trie filtered it under-reported the log's distinct client IPs.
func TestGeneralUniqueIPsCountsWholeLog(t *testing.T) {
	dir := t.TempDir()
	var sb strings.Builder
	// 5 distinct IPs; 10.0.0.1 appears three times.
	sb.WriteString(logLine("10.0.0.1", "/admin", "a"))
	sb.WriteString(logLine("10.0.0.1", "/admin", "a"))
	sb.WriteString(logLine("10.0.0.1", "/", "a"))
	sb.WriteString(logLine("10.0.0.2", "/admin", "a"))
	sb.WriteString(logLine("10.0.0.3", "/", "a"))
	sb.WriteString(logLine("10.0.0.4", "/", "GoodBot")) // UA-whitelisted
	sb.WriteString(logLine("10.0.0.5", "/login", "a"))

	cfg := &config.Config{
		Global: &config.GlobalConfig{
			UserAgentWhitelist: writeTestFile(t, dir, "ua_whitelist.txt", "GoodBot\n"),
		},
		Static: &config.StaticConfig{
			LogFile:   writeTestFile(t, dir, "access.log", sb.String()),
			LogFormat: publishLogFormat,
		},
		StaticTries: compileTries(t, map[string]*config.TrieConfig{
			"admin": {TrieCommon: config.TrieCommon{EndpointRegex: "^/admin"}},
			"login": {TrieCommon: config.TrieCommon{EndpointRegex: "^/login"}},
		}),
	}

	runs := map[string]func(*config.Config) (*output.JSONOutput, error){
		"Static": Static,
		"StaticWithRequests": func(cfg *config.Config) (*output.JSONOutput, error) {
			out, _, err := StaticWithRequests(cfg)
			return out, err
		},
	}
	for name, run := range runs {
		t.Run(name, func(t *testing.T) {
			out, err := run(cfg)
			if err != nil {
				t.Fatalf("run failed: %v", err)
			}
			perTrie := map[string]int{}
			for _, tr := range out.Tries {
				perTrie[tr.Name] = tr.Stats.UniqueIPs
			}
			if perTrie["admin"] != 2 || perTrie["login"] != 1 {
				t.Errorf("per-trie unique IPs = %v, want admin=2 login=1", perTrie)
			}
			if out.General.UniqueIPs != 5 {
				t.Errorf("General.UniqueIPs = %d, want 5 (distinct client IPs in the log, independent of trie filters)", out.General.UniqueIPs)
			}
		})
	}
}

// TestUserAgentIPListsSorted: useragent_whitelist_ips / useragent_blacklist_ips
// came out in map-iteration order (and, on the concurrent filter path, in
// goroutine-scheduling order), so two runs over the same log produced
// different JSON and fed the jail in a different order. They are now sorted
// ascending by address.
func TestUserAgentIPListsSorted(t *testing.T) {
	dir := t.TempDir()
	const perList = 300
	build := func(lines int) string {
		var sb strings.Builder
		for i := 0; i < lines; i++ {
			// Scrambled order; addresses span several octets so that numeric and
			// lexicographic order differ (9.x sorts before 10.x numerically).
			k := (i * 7919) % perList
			sb.WriteString(logLine(fmt.Sprintf("%d.%d.0.%d", 9+k%3, k%7, k%250+1), "/", "GoodBot"))
			sb.WriteString(logLine(fmt.Sprintf("%d.%d.1.%d", 9+k%3, k%7, k%250+1), "/", "BadBot"))
			sb.WriteString(logLine("192.0.2.1", "/", "plain"))
		}
		return sb.String()
	}

	ipLess := func(a, b string) bool {
		x, y := net.ParseIP(a).To4(), net.ParseIP(b).To4()
		for i := 0; i < 4; i++ {
			if x[i] != y[i] {
				return x[i] < y[i]
			}
		}
		return false
	}
	assertSortedUnique := func(t *testing.T, label string, ips []string) {
		t.Helper()
		if len(ips) < 2 {
			t.Fatalf("%s: only %d entries, test needs a real list", label, len(ips))
		}
		for i := 1; i < len(ips); i++ {
			if !ipLess(ips[i-1], ips[i]) {
				t.Fatalf("%s not strictly ascending at %d: %s then %s", label, i, ips[i-1], ips[i])
			}
		}
	}

	// 300 lines stay on the sequential filter path, 20000*3 = 60000 requests
	// cross the 50000-request threshold of the concurrent one.
	for _, lines := range []int{perList, 20000} {
		t.Run(fmt.Sprintf("%d_requests", lines*3), func(t *testing.T) {
			cfg := &config.Config{
				Global: &config.GlobalConfig{
					UserAgentWhitelist: writeTestFile(t, dir, "ua_whitelist.txt", "GoodBot\n"),
					UserAgentBlacklist: writeTestFile(t, dir, "ua_blacklist.txt", "BadBot\n"),
				},
				Static: &config.StaticConfig{
					LogFile:   writeTestFile(t, dir, fmt.Sprintf("access-%d.log", lines), build(lines)),
					LogFormat: publishLogFormat,
				},
				StaticTries: compileTries(t, map[string]*config.TrieConfig{
					"a": {},
					"b": {TrieCommon: config.TrieCommon{EndpointRegex: "^/"}},
				}),
			}
			first, _, err := StaticWithRequests(cfg)
			if err != nil {
				t.Fatalf("run failed: %v", err)
			}
			assertSortedUnique(t, "UserAgentWhitelistIPs", first.UserAgentWhitelistIPs)
			assertSortedUnique(t, "UserAgentBlacklistIPs", first.UserAgentBlacklistIPs)

			second, _, err := StaticWithRequests(cfg)
			if err != nil {
				t.Fatalf("second run failed: %v", err)
			}
			if !reflect.DeepEqual(first.UserAgentWhitelistIPs, second.UserAgentWhitelistIPs) ||
				!reflect.DeepEqual(first.UserAgentBlacklistIPs, second.UserAgentBlacklistIPs) {
				t.Error("UA IP lists differ between two runs over the same log")
			}
		})
	}
}

// TestInvalidIPWarningNamesTrie: the invalid_ips_skipped warning is emitted
// once per trie (the count depends on that trie's filters), so it must say
// which trie it is about instead of repeating an identical anonymous line.
func TestInvalidIPWarningNamesTrie(t *testing.T) {
	dir := t.TempDir()
	var sb strings.Builder
	sb.WriteString(logLine("10.0.0.1", "/", "a"))
	sb.WriteString(logLine("0.0.0.0", "/", "a")) // zero IP: parsed, but skipped as invalid
	sb.WriteString(logLine("10.0.0.2", "/", "a"))

	runs := map[string]struct {
		run   func(*config.Config) (*output.JSONOutput, error)
		tries map[string]*config.TrieConfig
	}{
		// No filters anywhere: IP-only fast path.
		"Static_fast_path": {Static, map[string]*config.TrieConfig{"alpha": {}, "beta": {}}},
		// A filter forces the full path.
		"StaticWithRequests_full_path": {
			func(cfg *config.Config) (*output.JSONOutput, error) {
				out, _, err := StaticWithRequests(cfg)
				return out, err
			},
			map[string]*config.TrieConfig{"alpha": {}, "beta": {TrieCommon: config.TrieCommon{EndpointRegex: "^/"}}},
		},
	}
	for name, tc := range runs {
		t.Run(name, func(t *testing.T) {
			cfg := &config.Config{
				Static: &config.StaticConfig{
					LogFile:   writeTestFile(t, dir, "access.log", sb.String()),
					LogFormat: publishLogFormat,
				},
				StaticTries: compileTries(t, tc.tries),
			}
			out, err := tc.run(cfg)
			if err != nil {
				t.Fatalf("run failed: %v", err)
			}
			named := map[string]int{}
			total := 0
			for _, w := range out.Warnings {
				if w.Type != "invalid_ips_skipped" {
					continue
				}
				total++
				for trieName := range tc.tries {
					if strings.Contains(w.Message, fmt.Sprintf("Trie %q:", trieName)) {
						named[trieName]++
					}
				}
			}
			if total != 2 || named["alpha"] != 1 || named["beta"] != 1 {
				t.Errorf("invalid_ips_skipped warnings: total=%d named=%v, want one per trie, each naming its trie; warnings: %+v",
					total, named, out.Warnings)
			}
		})
	}
}
