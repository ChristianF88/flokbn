package analysis

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ChristianF88/flokbn/config"
	"github.com/ChristianF88/flokbn/jail"
	"github.com/ChristianF88/flokbn/output"
)

// Characterization tests for the static pipeline. Each scenario runs both
// entrypoints (Static and StaticWithRequests) over one deterministic log and
// compares everything a user can observe - the JSON document minus timings,
// the published ban file and the jail's escalation state - against a golden
// file recorded before the two pipelines were merged into one.
//
// Regenerate (only for an intended behaviour change) with:
//
//	go test ./analysis -run TestStaticPipelineGolden -update
var updateGolden = flag.Bool("update", false, "rewrite the golden files under testdata/")

const (
	goldenLogFormat = `%h %^ %^ [%t] "%r" %s %b "%^" "%u"`
	// More than 50000 parsed requests, so filtered tries take the concurrent
	// filter; goldenSmallLogLines stays below it (sequential filter).
	goldenLogLines      = 60000
	goldenSmallLogLines = 9000
)

// writeGoldenLog writes a deterministic access log with two dense clusters, a
// few hot hosts, scattered noise, zero-IP lines, unparseable lines, mixed User
// Agents (two of them rare and exact-listed) and timestamps spread over three
// days in two time zones.
func writeGoldenLog(t *testing.T, dir string, lines int) string {
	t.Helper()
	uas := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/120.0",
		"curl/7.68.0",
		"python-requests/2.28",
		"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
	}
	paths := []string{"/api/data", "/login", "/static/app.js", "/admin/login", "/api/health", "/page/%d", "/"}

	var b strings.Builder
	b.Grow(lines * 140)
	lcg := uint32(0x2545F491)
	for i := 0; i < lines; i++ {
		if i%5003 == 17 {
			b.WriteString("this line is not an access log entry\n")
			continue
		}

		var ip string
		switch slot := i % 10; {
		case i%997 == 3:
			ip = "0.0.0.0" // parsed, then skipped as invalid
		case slot < 4: // dense cluster in 10.20.0.0/19
			k := (i * 7919) % 8192
			ip = fmt.Sprintf("10.20.%d.%d", k/256, k%256)
		case slot < 6: // dense cluster in 192.168.0.0/20
			k := (i * 104729) % 4096
			ip = fmt.Sprintf("192.168.%d.%d", k/256, k%256)
		case slot == 6: // four hot hosts
			ip = fmt.Sprintf("203.0.113.%d", 10+(i/10)%4)
		default: // noise
			lcg = lcg*1664525 + 1013904223
			ip = fmt.Sprintf("%d.%d.%d.%d", 11+(lcg>>24)%200, (lcg>>16)&0xff, (lcg>>8)&0xff, lcg&0xff)
		}

		ua := uas[(i/3)%len(uas)]
		switch {
		case i%600 == 5:
			ua = "GoodBot/1.0" // exact UA whitelist entry
		case i%600 == 305:
			ua = "goodbot/1.0" // same entry, other case
		case i%900 == 7:
			ua = "EvilScanner/9" // exact UA blacklist entry
		}

		path := paths[i%len(paths)]
		if strings.Contains(path, "%d") {
			path = fmt.Sprintf(path, i%100)
		}

		zone := "+0000"
		if i%11 == 0 {
			zone = "+0200"
		}
		ts := fmt.Sprintf("[%02d/Feb/2025:%02d:%02d:%02d %s]", 1+i%3, (i/3)%24, (i/72)%60, (i/4320)%60, zone)

		fmt.Fprintf(&b, "%s - - %s \"GET %s HTTP/1.1\" 200 1024 \"-\" \"%s\"\n", ip, ts, path, ua)
	}

	logFile := filepath.Join(dir, "access.log")
	if err := os.WriteFile(logFile, []byte(b.String()), 0o644); err != nil {
		t.Fatalf("writing log: %v", err)
	}
	return logFile
}

func goldenTime(t *testing.T, s string) *time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("parsing %q: %v", s, err)
	}
	return &v
}

// goldenScenario builds a fresh config (own directory, own jail/ban files) for
// one run of a scenario.
type goldenScenario struct {
	name  string
	lines int
	build func(t *testing.T, dir, logFile string) *config.Config
}

func goldenScenarios() []goldenScenario {
	clusterSets := []config.ClusterArgSet{
		{MinClusterSize: 2000, MinDepth: 16, MaxDepth: 24, MeanSubnetDifference: 0.2},
		{MinClusterSize: 300, MinDepth: 20, MaxDepth: 32, MeanSubnetDifference: 0.1},
	}

	unfiltered := func(t *testing.T, dir, logFile string) *config.Config {
		return &config.Config{
			Static: &config.StaticConfig{LogFile: logFile, LogFormat: goldenLogFormat},
			StaticTries: map[string]*config.TrieConfig{
				"all": {
					CIDRRanges: []string{"10.20.0.0/16", "192.168.0.0/20", "203.0.113.0/24", "not-a-cidr"},
					TrieCommon: config.TrieCommon{
						ClusterArgSets: clusterSets,
					},
				},
				"coarse": {
					TrieCommon: config.TrieCommon{
						ClusterArgSets: []config.ClusterArgSet{
							{MinClusterSize: 5000, MinDepth: 8, MaxDepth: 20, MeanSubnetDifference: 0.3},
							// Invalid on purpose: the placeholder entry must stay.
							{MinClusterSize: 10, MinDepth: 24, MaxDepth: 16, MeanSubnetDifference: 0.1},
						},
					},
				},
				"no_clustering": {},
			},
		}
	}

	filtered := func(t *testing.T, dir, logFile string) *config.Config {
		window := &config.TrieConfig{
			CIDRRanges: []string{"10.20.0.0/16"},
			TrieCommon: config.TrieCommon{
				ClusterArgSets: clusterSets[1:],
			},
		}
		// Zone-less bounds: compared against each line's wall clock.
		window.SetStartTimeBound(*goldenTime(t, "2025-02-02T06:00:00Z"), false, "2025-02-02 06")
		window.SetEndTimeBound(*goldenTime(t, "2025-02-03T03:30:00Z"), false, "2025-02-03 03:30")

		combined := &config.TrieConfig{
			TrieCommon: config.TrieCommon{
				UserAgentRegex: "curl|python-requests",
				EndpointRegex:  "^/(api|admin)/",
				ClusterArgSets: clusterSets[1:],
			},
		}
		// Bounds with an explicit offset: compared as instants.
		combined.SetStartTimeBound(*goldenTime(t, "2025-02-01T12:00:00+01:00"), true, "2025-02-01T12:00:00+01:00")

		nothing := &config.TrieConfig{TrieCommon: config.TrieCommon{ClusterArgSets: clusterSets}}
		nothing.SetStartTimeBound(*goldenTime(t, "2030-01-01T00:00:00Z"), true, "2030-01-01T00:00:00Z")

		return &config.Config{
			Static: &config.StaticConfig{LogFile: logFile, LogFormat: goldenLogFormat},
			StaticTries: compileTries(t, map[string]*config.TrieConfig{
				// No filter of its own in a config that needs the full parse.
				"baseline": {CIDRRanges: []string{"203.0.113.0/24"}, TrieCommon: config.TrieCommon{ClusterArgSets: clusterSets}},
				"bots":     {TrieCommon: config.TrieCommon{UserAgentRegex: "(?i)curl|python-requests|googlebot", ClusterArgSets: clusterSets}},
				"api":      {TrieCommon: config.TrieCommon{EndpointRegex: "^/api/", ClusterArgSets: clusterSets}, CIDRRanges: []string{"192.168.0.0/20"}},
				"window":   window,
				"combined": combined,
				"nothing":  nothing,
			}),
		}
	}

	lists := func(t *testing.T, dir, logFile string) *config.Config {
		endpoint := &config.TrieConfig{
			TrieCommon: config.TrieCommon{
				EndpointRegex:  "^/(login|admin)",
				ClusterArgSets: clusterSets,
				UseForJail:     []bool{false, true},
			},
		}
		return &config.Config{
			Global: &config.GlobalConfig{
				JailFile: filepath.Join(dir, "jail.json"),
				BanFile:  filepath.Join(dir, "ban.txt"),
				// 10.20.0.0/19 covers a whole detected range (dropped before the
				// jail); 192.168.3.0/24 only overlaps one (carved at publish).
				Whitelist:          writeTestFile(t, dir, "whitelist.txt", "# never ban\n10.20.0.0/19\n192.168.3.0/24\n198.51.100.7\n"),
				Blacklist:          writeTestFile(t, dir, "blacklist.txt", "198.51.100.0/24\n100.64.0.0/10\n"),
				UserAgentWhitelist: writeTestFile(t, dir, "ua_whitelist.txt", "# trusted\nGoodBot/1.0\n"),
				UserAgentBlacklist: writeTestFile(t, dir, "ua_blacklist.txt", "EvilScanner/9\n"),
			},
			Static: &config.StaticConfig{LogFile: logFile, LogFormat: goldenLogFormat},
			StaticTries: compileTries(t, map[string]*config.TrieConfig{
				"baseline": {
					CIDRRanges: []string{"10.20.0.0/16"},
					TrieCommon: config.TrieCommon{
						ClusterArgSets: clusterSets,
						UseForJail:     []bool{true, false},
					},
				},
				"endpoint": endpoint,
			}),
		}
	}

	// IP whitelist/blacklist and jail but no request filter: Static stays on
	// the IP-only path and still has to publish.
	jailOnly := func(t *testing.T, dir, logFile string) *config.Config {
		cfg := unfiltered(t, dir, logFile)
		cfg.Global = &config.GlobalConfig{
			JailFile:  filepath.Join(dir, "jail.json"),
			BanFile:   filepath.Join(dir, "ban.txt"),
			Whitelist: writeTestFile(t, dir, "whitelist.txt", "192.168.0.0/16\n"),
			Blacklist: writeTestFile(t, dir, "blacklist.txt", "198.51.100.0/24\n"),
		}
		cfg.StaticTries["all"].UseForJail = []bool{true, true}
		cfg.StaticTries["coarse"].UseForJail = []bool{false, true}
		return cfg
	}

	return []goldenScenario{
		{"unfiltered", goldenLogLines, unfiltered},
		{"filtered", goldenLogLines, filtered},
		{"filtered_small", goldenSmallLogLines, filtered},
		{"lists_and_jail", goldenLogLines, lists},
		{"lists_and_jail_small", goldenSmallLogLines, lists},
		{"jail_unfiltered", goldenLogLines, jailOnly},
	}
}

// goldenSnapshot is the observable outcome of one static run.
type goldenSnapshot struct {
	Output  json.RawMessage `json:"output"`
	BanFile []string        `json:"ban_file"`
	// Jail lists every prisoner as "cell <id>: <cidr> active=<bool>".
	Jail []string `json:"jail"`
}

// normalizeOutput renders out as JSON with every run-dependent value removed:
// timings, the version stamp, the temp directory, and the order of warnings
// and errors (tries run concurrently).
func normalizeOutput(t *testing.T, out *output.JSONOutput, dir string) json.RawMessage {
	t.Helper()
	raw, err := out.ToJSON()
	if err != nil {
		t.Fatalf("marshal output: %v", err)
	}
	raw = bytes.ReplaceAll(raw, []byte(dir), []byte("<DIR>"))

	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	volatile := map[string]bool{
		"duration_ms": true, "rate_per_second": true, "insert_time_ms": true,
		"execution_time_us": true, "generated_at": true, "version": true,
	}
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, child := range x {
				if volatile[k] {
					delete(x, k)
					continue
				}
				if k == "warnings" || k == "errors" {
					if list, ok := child.([]any); ok {
						sort.Slice(list, func(i, j int) bool {
							return fmt.Sprint(list[i]) < fmt.Sprint(list[j])
						})
					}
				}
				walk(child)
			}
		case []any:
			for _, child := range x {
				walk(child)
			}
		}
	}
	walk(doc)

	norm, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatalf("marshal normalized output: %v", err)
	}
	return norm
}

func snapshotRun(t *testing.T, cfg *config.Config, out *output.JSONOutput, dir string) goldenSnapshot {
	t.Helper()
	snap := goldenSnapshot{Output: normalizeOutput(t, out, dir), BanFile: []string{}, Jail: []string{}}
	if cfg.Global == nil || cfg.Global.BanFile == "" {
		return snap
	}

	data, err := os.ReadFile(cfg.GetBanFile())
	if err != nil {
		t.Fatalf("reading ban file: %v", err)
	}
	for _, line := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		if strings.HasPrefix(line, "# This file was generated automatically") {
			continue // carries the write time
		}
		snap.BanFile = append(snap.BanFile, line)
	}

	j, err := jail.FileToJail(cfg.GetJailFile())
	if err != nil {
		t.Fatalf("reading jail: %v", err)
	}
	for _, cell := range j.Cells {
		for _, p := range cell.Prisoners {
			snap.Jail = append(snap.Jail, fmt.Sprintf("cell %d: %s active=%v", cell.ID, p.CIDR, p.BanActive))
		}
	}
	return snap
}

func TestStaticPipelineGolden(t *testing.T) {
	entrypoints := []struct {
		name string
		run  func(*config.Config) (*output.JSONOutput, int, error)
	}{
		{"Static", func(cfg *config.Config) (*output.JSONOutput, int, error) {
			out, err := Static(cfg)
			return out, -1, err
		}},
		{"StaticWithRequests", func(cfg *config.Config) (*output.JSONOutput, int, error) {
			out, requests, err := StaticWithRequests(cfg)
			return out, len(requests), err
		}},
	}

	logs := map[int]string{}
	logDir := t.TempDir()
	logFor := func(lines int) string {
		if _, ok := logs[lines]; !ok {
			sub := filepath.Join(logDir, fmt.Sprint(lines))
			if err := os.Mkdir(sub, 0o755); err != nil {
				t.Fatal(err)
			}
			logs[lines] = writeGoldenLog(t, sub, lines)
		}
		return logs[lines]
	}

	for _, sc := range goldenScenarios() {
		t.Run(sc.name, func(t *testing.T) {
			logFile := logFor(sc.lines)
			goldenPath := filepath.Join("testdata", "static_pipeline", sc.name+".golden.json")

			var first []byte
			for _, ep := range entrypoints {
				dir := t.TempDir()
				cfg := sc.build(t, dir, logFile)
				out, requests, err := ep.run(cfg)
				if err != nil {
					t.Fatalf("%s: %v", ep.name, err)
				}
				// The requests handed back are every parsed line.
				if requests >= 0 && requests != out.General.TotalRequests {
					t.Errorf("%s: returned %d requests, total_requests = %d", ep.name, requests, out.General.TotalRequests)
				}

				snap := snapshotRun(t, cfg, out, dir)
				snap.Output = bytes.ReplaceAll(snap.Output, []byte(filepath.Dir(logFile)), []byte("<LOGDIR>"))
				got, err := json.MarshalIndent(snap, "", "  ")
				if err != nil {
					t.Fatal(err)
				}
				got = append(got, '\n')

				// Both entrypoints must agree on everything observable.
				if first == nil {
					first = got
				} else if !bytes.Equal(first, got) {
					t.Errorf("%s differs from %s:\n%s", ep.name, entrypoints[0].name, firstDiff(first, got))
				}

				if *updateGolden {
					if ep.name != entrypoints[0].name {
						continue
					}
					if err := os.MkdirAll(filepath.Dir(goldenPath), 0o755); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(goldenPath, got, 0o644); err != nil {
						t.Fatal(err)
					}
					continue
				}
				want, err := os.ReadFile(goldenPath)
				if err != nil {
					t.Fatalf("reading golden file (run with -update to create it): %v", err)
				}
				if !bytes.Equal(want, got) {
					t.Errorf("%s differs from %s:\n%s", ep.name, goldenPath, firstDiff(want, got))
				}
			}
		})
	}
}

// firstDiff shows the first differing line of two texts with some context.
func firstDiff(want, got []byte) string {
	w := strings.Split(string(want), "\n")
	g := strings.Split(string(got), "\n")
	for i := 0; i < len(w) || i < len(g); i++ {
		var wl, gl string
		if i < len(w) {
			wl = w[i]
		}
		if i < len(g) {
			gl = g[i]
		}
		if wl != gl {
			from := i - 3
			if from < 0 {
				from = 0
			}
			return fmt.Sprintf("line %d (want %d lines, got %d)\ncontext:\n%s\n- want: %s\n+ got:  %s",
				i+1, len(w), len(g), strings.Join(w[from:i], "\n"), wl, gl)
		}
	}
	return "no difference"
}
