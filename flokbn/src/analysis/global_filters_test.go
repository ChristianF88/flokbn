package analysis

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ChristianF88/flokbn/config"
)

// writeTempFile writes content to a file inside dir and returns its path.
func writeTempFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write %s: %v", p, err)
	}
	return p
}

// newGlobalFiltersConfig builds a minimal static config with one filterless
// trie and an optional global IP whitelist / UA whitelist. Both list files (if
// any) live under t.TempDir() so there are no hardcoded paths.
func newGlobalFiltersConfig(whitelistPath, uaWhitelistPath string) *config.Config {
	return &config.Config{
		Global: &config.GlobalConfig{
			Whitelist:          whitelistPath,
			UserAgentWhitelist: uaWhitelistPath,
		},
		Static: &config.StaticConfig{
			LogFile:   getTestLogFile(),
			LogFormat: "%^ %^ %^ [%t] \"%r\" %s %b \"%^\" \"%u\" \"%h\"",
		},
		StaticTries: map[string]*config.TrieConfig{
			"baseline": {
				ClusterArgSets: []config.ClusterArgSet{
					{MinClusterSize: 1000, MinDepth: 30, MaxDepth: 32, MeanSubnetDifference: 0.2},
				},
			},
		},
	}
}

// TestStaticGlobalFiltersPopulated verifies a config that declares an IP
// whitelist + UA whitelist yields GlobalFilters counts matching the file
// contents. With no per-trie filters this exercises the IP-only fast path in
// Static.
func TestStaticGlobalFiltersPopulated(t *testing.T) {
	dir := t.TempDir()
	// 3 CIDRs (a comment + blank line must NOT be counted).
	wl := writeTempFile(t, dir, "whitelist.txt", "# comment\n10.0.0.0/8\n\n192.168.0.0/16\n172.16.0.0/12\n")
	// 2 UA patterns (comment + blank skipped).
	ua := writeTempFile(t, dir, "ua_whitelist.txt", "# bots we trust\nGoodBot\n\nUptimeRobot\n")

	cfg := newGlobalFiltersConfig(wl, ua)

	result, err := Static(cfg)
	if err != nil {
		t.Fatalf("Static failed: %v", err)
	}
	if got := result.GlobalFilters.IPWhitelistCIDRs; got != 3 {
		t.Errorf("IPWhitelistCIDRs = %d, want 3", got)
	}
	if got := result.GlobalFilters.UAWhitelistPatterns; got != 2 {
		t.Errorf("UAWhitelistPatterns = %d, want 2", got)
	}
}

// TestStaticGlobalFiltersZeroWhenNoWhitelistFiles verifies a config with no
// whitelist files yields zero counts (so the renderer prints "None").
func TestStaticGlobalFiltersZeroWhenNoWhitelistFiles(t *testing.T) {
	cfg := newGlobalFiltersConfig("", "")

	result, err := Static(cfg)
	if err != nil {
		t.Fatalf("Static failed: %v", err)
	}
	if got := result.GlobalFilters.IPWhitelistCIDRs; got != 0 {
		t.Errorf("IPWhitelistCIDRs = %d, want 0", got)
	}
	if got := result.GlobalFilters.UAWhitelistPatterns; got != 0 {
		t.Errorf("UAWhitelistPatterns = %d, want 0", got)
	}
}

// TestStaticWithRequestsGlobalFiltersPopulated verifies the full path
// (StaticWithRequests) populates GlobalFilters too. A per-trie UA regex forces
// the non-IP path, exercising the second assembly site.
func TestStaticWithRequestsGlobalFiltersPopulated(t *testing.T) {
	dir := t.TempDir()
	wl := writeTempFile(t, dir, "whitelist.txt", "10.0.0.0/8\n192.168.0.0/16\n")
	ua := writeTempFile(t, dir, "ua_whitelist.txt", "GoodBot\nUptimeRobot\nPingdom\n")

	cfg := newGlobalFiltersConfig(wl, ua)
	// Force the full (non-IP) path via a per-trie regex.
	cfg.StaticTries["baseline"].UserAgentRegex = "Mozilla"

	result, _, err := StaticWithRequests(cfg)
	if err != nil {
		t.Fatalf("StaticWithRequests failed: %v", err)
	}
	if got := result.GlobalFilters.IPWhitelistCIDRs; got != 2 {
		t.Errorf("IPWhitelistCIDRs = %d, want 2", got)
	}
	if got := result.GlobalFilters.UAWhitelistPatterns; got != 3 {
		t.Errorf("UAWhitelistPatterns = %d, want 3", got)
	}
}

// TestComputeGlobalFiltersMissingFileTreatedAsZero verifies that an unreadable
// whitelist path does not fail the computation — it is treated as zero.
func TestComputeGlobalFiltersMissingFileTreatedAsZero(t *testing.T) {
	dir := t.TempDir()
	cfg := newGlobalFiltersConfig(filepath.Join(dir, "does-not-exist.txt"), "")
	gf := computeGlobalFilters(cfg)
	if gf.IPWhitelistCIDRs != 0 || gf.UAWhitelistPatterns != 0 {
		t.Errorf("expected zero counts for missing whitelist, got %+v", gf)
	}
}
