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

// A bare IPv6 address stays rejected at the barrier.
func TestStaticRangesCidrBareIPv6Rejected(t *testing.T) {
	dir := t.TempDir()
	logFile := writeFile(t, dir, "access.log", sampleLogLine)
	_, stderr, code := runFlokbn(t, "static",
		"--logfile", logFile,
		"--clusterArgSets", "1,0,32,1.0",
		"--rangesCidr", "2001:db8::1",
		"--jailFile", filepath.Join(dir, "jail.json"),
		"--banFile", filepath.Join(dir, "ban.txt"))
	if code != 1 || !strings.Contains(stderr, "invalid rangesCidr") {
		t.Fatalf("want exit 1 with an invalid rangesCidr diagnostic, got exit %d:\n%s", code, stderr)
	}
}
