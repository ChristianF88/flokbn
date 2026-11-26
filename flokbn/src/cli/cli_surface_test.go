package cli

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// staticJSON runs `flokbn static <args> --compact` on a one-line log and
// decodes the JSON result. It fails the test on a non-zero exit.
func staticJSON(t *testing.T, logFile string, args ...string) (result map[string]any, stderr string) {
	t.Helper()
	full := append([]string{"static"}, args...)
	full = append(full, "--compact")
	stdout, stderr, code := runFlokbn(t, full...)
	if code != 0 {
		t.Fatalf("flokbn %v exited %d\nstdout:\n%s\nstderr:\n%s", full, code, stdout, stderr)
	}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("decode JSON output: %v\n%s", err, stdout)
	}
	return result, stderr
}

// firstTrie returns the first entry of the "tries" array of a static result.
func firstTrie(t *testing.T, result map[string]any) map[string]any {
	t.Helper()
	tries, _ := result["tries"].([]any)
	if len(tries) == 0 {
		t.Fatalf("result has no tries: %v", result)
	}
	trie, _ := tries[0].(map[string]any)
	return trie
}

// C4: `--rangesCidr 1.2.3.4` passed validation (IsValidCidrOrIP accepts a bare
// IP) and then failed in trie.CountInRange with an "invalid_cidr" warning and
// no count. A bare IPv4 is now normalised to /32 and counted.
func TestStaticRangesCidrBareIPIsCounted(t *testing.T) {
	dir := t.TempDir()
	logFile := writeFile(t, dir, "access.log", sampleLogLine)

	result, _ := staticJSON(t, logFile,
		"--logfile", logFile,
		"--clusterArgSets", "1,0,32,1.0",
		"--rangesCidr", "192.168.1.1")

	if warnings, _ := result["warnings"].([]any); len(warnings) != 0 {
		t.Errorf("want no warnings, got %v", warnings)
	}
	trie := firstTrie(t, result)
	params, _ := trie["parameters"].(map[string]any)
	ranges, _ := params["cidr_ranges"].([]any)
	if len(ranges) != 1 || ranges[0] != "192.168.1.1/32" {
		t.Errorf("cidr_ranges = %v, want [192.168.1.1/32]", ranges)
	}
	stats, _ := trie["stats"].(map[string]any)
	analysis, _ := stats["cidr_analysis"].([]any)
	if len(analysis) != 1 {
		t.Fatalf("want 1 cidr_analysis entry, got %v", stats["cidr_analysis"])
	}
	entry, _ := analysis[0].(map[string]any)
	if entry["cidr"] != "192.168.1.1/32" || entry["requests"] != float64(1) {
		t.Errorf("cidr_analysis entry = %v, want 192.168.1.1/32 with 1 request", entry)
	}
}

// A bare IPv6 address stays rejected at the barrier, with the message a TOML
// cidrRanges entry gets (it used to be a bare "invalid rangesCidr[0]").
func TestStaticRangesCidrBareIPv6Rejected(t *testing.T) {
	dir := t.TempDir()
	logFile := writeFile(t, dir, "access.log", sampleLogLine)
	_, stderr, code := runFlokbn(t, "static",
		"--logfile", logFile,
		"--clusterArgSets", "1,0,32,1.0",
		"--rangesCidr", "2001:db8::1",
		"--jailFile", filepath.Join(dir, "jail.json"),
		"--banFile", filepath.Join(dir, "ban.txt"))
	const want = `[static.cli_trie] IPv6 not supported (IPv4-only tool) in rangesCidr[0]: "2001:db8::1"`
	if code != 1 || !strings.Contains(stderr, want) {
		t.Fatalf("want exit 1 with %q, got exit %d:\n%s", want, code, stderr)
	}
}

// C8: the flag and TOML surfaces spell the same things differently
// (--logfile / logFile, --rangesCidr / cidrRanges, --clusterArgSets on static
// but --clusterArgSet on live). Each flag accepts the other spelling as an
// alias.
func TestStaticFlagAliases(t *testing.T) {
	dir := t.TempDir()
	logFile := writeFile(t, dir, "access.log", sampleLogLine)

	result, _ := staticJSON(t, logFile,
		"--logFile", logFile,
		"--clusterArgSet", "1,0,32,1.0",
		"--cidrRanges", "192.168.1.0/24")

	trie := firstTrie(t, result)
	stats, _ := trie["stats"].(map[string]any)
	analysis, _ := stats["cidr_analysis"].([]any)
	if len(analysis) != 1 {
		t.Fatalf("--cidrRanges should produce 1 cidr_analysis entry, got %v", stats["cidr_analysis"])
	}
	data, _ := trie["data"].([]any)
	if len(data) != 1 {
		t.Fatalf("--clusterArgSet should produce 1 cluster result, got %v", trie["data"])
	}
	params, _ := data[0].(map[string]any)["parameters"].(map[string]any)
	if params["min_cluster_size"] != float64(1) || params["max_depth"] != float64(32) {
		t.Errorf("--clusterArgSet 1,0,32,1.0 not applied, got parameters %v", params)
	}
}

// The live command accepts --clusterArgSets. The set is deliberately invalid so
// the run stops at argument parsing, before anything is bound: the error must
// come from the cluster-arg validator, not from an undefined flag.
func TestLiveClusterArgSetsAlias(t *testing.T) {
	dir := t.TempDir()
	for _, flag := range []string{"--clusterArgSet", "--clusterArgSets"} {
		_, stderr, code := runFlokbn(t, "live",
			"--port", "0",
			"--jailFile", filepath.Join(dir, "jail.json"),
			"--banFile", filepath.Join(dir, "ban.txt"),
			flag, "0,24,32,0.1")
		if code == 0 {
			t.Fatalf("%s 0,24,32,0.1 should be rejected", flag)
		}
		if strings.Contains(stderr, "flag provided but not defined") {
			t.Errorf("live must accept %s, got:\n%s", flag, stderr)
		}
		if !strings.Contains(stderr, "minClusterSize") {
			t.Errorf("%s should reach the cluster-arg validator, got:\n%s", flag, stderr)
		}
	}
}

// An alias must not slip past the "--config excludes other flags" rule, and the
// offender is named once (by its primary spelling), not once per spelling.
func TestConfigModeRejectsAliasedFlags(t *testing.T) {
	dir := t.TempDir()
	cfg := staticConfig(t, dir, `clusterArgSets = [[1, 0, 32, 1.0]]`, "")

	for _, tc := range []struct {
		args    []string
		primary string
		alias   string
	}{
		{[]string{"static", "--config", cfg, "--logFile", "x.log"}, `"--logfile"`, `"--logFile"`},
		{[]string{"static", "--config", cfg, "--cidrRanges", "10.0.0.0/8"}, `"--rangesCidr"`, `"--cidrRanges"`},
		{[]string{"static", "--config", cfg, "--clusterArgSet", "1,0,32,1.0"}, `"--clusterArgSets"`, `"--clusterArgSet"`},
		{[]string{"static", "--config", cfg, "--clusterArgSets", "1,0,32,1.0"}, `"--clusterArgSets"`, `"--clusterArgSet"`},
		{[]string{"live", "--config", cfg, "--clusterArgSets", "1,0,32,1.0"}, `"--clusterArgSet"`, `"--clusterArgSets"`},
	} {
		_, stderr, code := runFlokbn(t, tc.args...)
		if code == 0 || !strings.Contains(stderr, "--config cannot be combined with") {
			t.Errorf("%v: want a --config conflict error, got exit %d:\n%s", tc.args, code, stderr)
			continue
		}
		offenders := stderr[:strings.Index(stderr, "; with --config")]
		if !strings.Contains(offenders, tc.primary) || strings.Contains(offenders, tc.alias) {
			t.Errorf("%v: offenders should name only %s, got: %s", tc.args, tc.primary, offenders)
		}
	}
}

// --help: the --clusterArgSets text advertised a ';' separator that never
// worked, and the jail/ban examples pointed at world-writable /tmp.
func TestHelpText(t *testing.T) {
	for _, cmd := range []string{"static", "live"} {
		stdout, stderr, code := runFlokbn(t, cmd, "--help")
		if code != 0 {
			t.Fatalf("%s --help exited %d:\n%s", cmd, code, stderr)
		}
		if strings.Contains(stdout, ";...") {
			t.Errorf("%s --help still advertises ';...' separators:\n%s", cmd, stdout)
		}
		if strings.Contains(stdout, "/tmp/") {
			t.Errorf("%s --help should not suggest /tmp paths:\n%s", cmd, stdout)
		}
		for _, want := range []string{"--clusterArgSet", "--clusterArgSets", "/var/lib/flokbn/jail.json", "/var/lib/flokbn/ban.txt"} {
			if !strings.Contains(stdout, want) {
				t.Errorf("%s --help should mention %s:\n%s", cmd, want, stdout)
			}
		}
	}
	stdout, _, _ := runFlokbn(t, "static", "--help")
	for _, want := range []string{"--logFile", "--cidrRanges", "RFC3339"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("static --help should mention %s:\n%s", want, stdout)
		}
	}
}

// --startTime/--endTime accept RFC3339 (the TOML syntax) and the TOML keys
// accept the short flag syntax; both select the same single request.
func TestTimeBoundSyntaxesWorkOnBothSurfaces(t *testing.T) {
	dir := t.TempDir()
	logFile := writeFile(t, dir, "access.log", sampleLogLine) // 01/Jan/2025:00:00:00 +0000

	afterFiltering := func(result map[string]any) any {
		stats, _ := firstTrie(t, result)["stats"].(map[string]any)
		return stats["total_requests_after_filtering"]
	}

	result, _ := staticJSON(t, logFile,
		"--logfile", logFile, "--clusterArgSets", "1,0,32,1.0",
		"--startTime", "2024-12-31T23:00:00Z", "--endTime", "2025-01-01T01:00:00+00:00")
	if got := afterFiltering(result); got != float64(1) {
		t.Errorf("RFC3339 flags: total_requests_after_filtering = %v, want 1", got)
	}

	result, _ = staticJSON(t, logFile,
		"--logfile", logFile, "--clusterArgSets", "1,0,32,1.0",
		"--startTime", "2025-01-01T00:00:01Z")
	if got := afterFiltering(result); got != float64(0) {
		t.Errorf("RFC3339 --startTime after the request: total_requests_after_filtering = %v, want 0", got)
	}

	cfg := staticConfig(t, dir, "clusterArgSets = [[1, 0, 32, 1.0]]\nstartTime = \"2024-12-31 23:00\"\nendTime = \"2025-01-01 01\"", "")
	result, _ = staticJSON(t, logFile, "--config", cfg)
	if got := afterFiltering(result); got != float64(1) {
		t.Errorf("short-form TOML bounds: total_requests_after_filtering = %v, want 1", got)
	}
}

// A [live.<name>] key that does nothing is called out at startup. The config
// is otherwise invalid (no port) so the run stops at the barrier, after the
// warning and before any bind.
func TestLiveWarnsAboutInertKeys(t *testing.T) {
	dir := t.TempDir()
	cfg := writeFile(t, dir, "live.toml", `
[global]
jailFile = "`+filepath.Join(dir, "jail.json")+`"
banFile = "`+filepath.Join(dir, "ban.txt")+`"

[live]

[live.win]
slidingWindowMaxTime = "1m"
slidingWindowMaxSize = 1000
clusterArgSets = [[1, 0, 32, 1.0]]
startTime = "2025-01-01T00:00:00Z"
cidrRanges = ["10.0.0.0/8"]
`)
	_, stderr, code := runFlokbn(t, "live", "--config", cfg)
	if code != 1 || !strings.Contains(stderr, "port is required") {
		t.Fatalf("want the barrier to stop on the missing port, got exit %d:\n%s", code, stderr)
	}
	for _, want := range []string{"[live.win] startTime has no effect in live mode", "[live.win] cidrRanges has no effect in live mode"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr should warn %q, got:\n%s", want, stderr)
		}
	}
}
