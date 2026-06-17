package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// URGENT-08: config parsing is fail-loud at load time. These tests lock in that
// operator mistakes (wrong-typed scalars, malformed/under-specified/misordered
// clusterArgSets, unknown keys, present-but-mismatched useForJail) are hard
// errors at LoadConfig time instead of silent drops/defaults — and that
// legitimately omitted optional fields stay valid (do not over-fail).

func loadConfigString(t *testing.T, content string) (*Config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cfg.toml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return LoadConfig(path)
}

// minDepth > maxDepth in a TOML clusterArgSets row must error at load, naming
// the offending row. Previously this row was silently dropped, shifting the
// positional useForJail alignment.
func TestLoadConfig_ClusterMinDepthGtMaxDepthErrors(t *testing.T) {
	_, err := loadConfigString(t, `
[static.trie_1]
clusterArgSets = [[1000, 32, 24, 0.1]]
useForJail = [true]
`)
	if err == nil {
		t.Fatal("expected error for minDepth > maxDepth, got nil")
	}
	if !strings.Contains(err.Error(), "minDepth") || !strings.Contains(err.Error(), "row 0") {
		t.Fatalf("error should name minDepth and the row index, got: %v", err)
	}
}

// maxDepth > 32 (IPv4 bit width ceiling) must error at load.
func TestLoadConfig_ClusterMaxDepthOver32Errors(t *testing.T) {
	_, err := loadConfigString(t, `
[static.trie_1]
clusterArgSets = [[1000, 24, 33, 0.1]]
useForJail = [true]
`)
	if err == nil {
		t.Fatal("expected error for maxDepth > 32, got nil")
	}
	if !strings.Contains(err.Error(), "maxDepth") {
		t.Fatalf("error should name maxDepth, got: %v", err)
	}
}

// A clusterArgSets row with fewer than 4 numeric values must error, surfacing
// the row index. Previously the >=4 gate silently dropped it.
func TestLoadConfig_ClusterRowUnderFourErrors(t *testing.T) {
	_, err := loadConfigString(t, `
[static.trie_1]
clusterArgSets = [[1000, 24, 32, 0.1], [500, 24, 32]]
useForJail = [true, true]
`)
	if err == nil {
		t.Fatal("expected error for under-specified row, got nil")
	}
	if !strings.Contains(err.Error(), "row 1") || !strings.Contains(err.Error(), "4") {
		t.Fatalf("error should name row 1 and require 4 values, got: %v", err)
	}
}

// A non-numeric member in a clusterArgSets row must error (it can no longer be
// silently filtered, which used to drop a 4-element row below the threshold).
func TestLoadConfig_ClusterNonNumericMemberErrors(t *testing.T) {
	_, err := loadConfigString(t, `
[static.trie_1]
clusterArgSets = [[1000, 24, "32", 0.1]]
useForJail = [true]
`)
	if err == nil {
		t.Fatal("expected error for non-numeric cluster member, got nil")
	}
	if !strings.Contains(err.Error(), "non-numeric") {
		t.Fatalf("error should mention non-numeric, got: %v", err)
	}
}

// A PRESENT useForJail whose length differs from clusterArgSets must error:
// this is the silent-misalignment landmine the ticket calls out.
func TestLoadConfig_UseForJailLengthMismatchErrors(t *testing.T) {
	_, err := loadConfigString(t, `
[static.trie_1]
clusterArgSets = [[1000, 24, 32, 0.1], [500, 24, 32, 0.2]]
useForJail = [true]
`)
	if err == nil {
		t.Fatal("expected error for useForJail length mismatch, got nil")
	}
	if !strings.Contains(err.Error(), "useForJail") || !strings.Contains(err.Error(), "clusterArgSets") {
		t.Fatalf("error should name both arrays, got: %v", err)
	}
}

// OMITTED useForJail with non-empty clusterArgSets is the valid "cluster but
// never jail" default — it must NOT over-fail.
func TestLoadConfig_OmittedUseForJailIsValid(t *testing.T) {
	cfg, err := loadConfigString(t, `
[static.trie_1]
clusterArgSets = [[1000, 24, 32, 0.1]]
`)
	if err != nil {
		t.Fatalf("omitted useForJail should be valid, got: %v", err)
	}
	tr := cfg.StaticTries["trie_1"]
	if tr == nil {
		t.Fatal("expected trie_1 to load")
	}
	if len(tr.ClusterArgSets) != 1 {
		t.Fatalf("expected 1 cluster set, got %d", len(tr.ClusterArgSets))
	}
	if len(tr.UseForJail) != 0 {
		t.Fatalf("expected empty useForJail, got %v", tr.UseForJail)
	}
}

// A trie with NO filter and NO clustering (everything omitted) is valid and
// applies no filtering — must not over-fail.
func TestLoadConfig_FilterlessClusterlessTrieIsValid(t *testing.T) {
	cfg, err := loadConfigString(t, `
[static.trie_bare]
`)
	if err != nil {
		t.Fatalf("bare trie should be valid, got: %v", err)
	}
	if _, ok := cfg.StaticTries["trie_bare"]; !ok {
		t.Fatal("expected trie_bare to load")
	}
}

// port = 8080 (an integer — a natural mistake) must error AT LOAD time, not
// later as a misleading "port is required".
func TestLoadConfig_PortIntegerErrorsAtLoad(t *testing.T) {
	_, err := loadConfigString(t, `
[live]
port = 8080
`)
	if err == nil {
		t.Fatal("expected load-time error for integer port, got nil")
	}
	if !strings.Contains(err.Error(), "port") {
		t.Fatalf("error should name port, got: %v", err)
	}
	if strings.Contains(err.Error(), "required") {
		t.Fatalf("error should be a type error at load, not a misleading 'required': %v", err)
	}
}

// topTalkers with a wrong type must error at load.
func TestLoadConfig_TopTalkersWrongTypeErrors(t *testing.T) {
	_, err := loadConfigString(t, `
[live]
port = "8080"
topTalkers = "ten"
`)
	if err == nil {
		t.Fatal("expected error for string topTalkers, got nil")
	}
	if !strings.Contains(err.Error(), "topTalkers") {
		t.Fatalf("error should name topTalkers, got: %v", err)
	}
}

// Unknown/misspelled keys in [global] must error.
func TestLoadConfig_UnknownGlobalKeyErrors(t *testing.T) {
	_, err := loadConfigString(t, `
[global]
jailfile = "/x/jail.json"
`)
	if err == nil {
		t.Fatal("expected error for misspelled global key, got nil")
	}
	if !strings.Contains(err.Error(), "jailfile") || !strings.Contains(err.Error(), "global") {
		t.Fatalf("error should name the bad key and section, got: %v", err)
	}
}

// Unknown/misspelled keys in [static] (scalar section) must error.
func TestLoadConfig_UnknownStaticKeyErrors(t *testing.T) {
	_, err := loadConfigString(t, `
[static]
logfile = "/x/access.log"
`)
	if err == nil {
		t.Fatal("expected error for misspelled static key, got nil")
	}
	if !strings.Contains(err.Error(), "logfile") || !strings.Contains(err.Error(), "static") {
		t.Fatalf("error should name the bad key and section, got: %v", err)
	}
}

// Unknown/misspelled keys in [live] must error.
func TestLoadConfig_UnknownLiveKeyErrors(t *testing.T) {
	_, err := loadConfigString(t, `
[live]
port = "8080"
prt = "9090"
`)
	if err == nil {
		t.Fatal("expected error for misspelled live key, got nil")
	}
	if !strings.Contains(err.Error(), "prt") || !strings.Contains(err.Error(), "live") {
		t.Fatalf("error should name the bad key and section, got: %v", err)
	}
}

// A misspelled trie key (useForjail with lowercase j) must error rather than
// silently yielding default behavior.
func TestLoadConfig_MisspelledTrieKeyErrors(t *testing.T) {
	_, err := loadConfigString(t, `
[static.trie_1]
clusterArgSets = [[1000, 24, 32, 0.1]]
useForjail = [true]
`)
	if err == nil {
		t.Fatal("expected error for misspelled useForjail, got nil")
	}
	if !strings.Contains(err.Error(), "useForjail") {
		t.Fatalf("error should name the misspelled key, got: %v", err)
	}
}

// The singular clusterArgSet (vs clusterArgSets) misspelling must error.
func TestLoadConfig_SingularClusterArgSetKeyErrors(t *testing.T) {
	_, err := loadConfigString(t, `
[static.trie_1]
clusterArgSet = [[1000, 24, 32, 0.1]]
`)
	if err == nil {
		t.Fatal("expected error for singular clusterArgSet, got nil")
	}
	if !strings.Contains(err.Error(), "clusterArgSet") {
		t.Fatalf("error should name the misspelled key, got: %v", err)
	}
}

// A misspelled sliding-trie key must error.
func TestLoadConfig_MisspelledSlidingTrieKeyErrors(t *testing.T) {
	_, err := loadConfigString(t, `
[live]
port = "8080"

[live.win_1]
slidingWindowMaxSize = 100
slidingWindowMaxTime = "1h"
clusterArgSets = [[100, 24, 32, 0.1]]
slidingWindowMxTime = "2h"
`)
	if err == nil {
		t.Fatal("expected error for misspelled sliding trie key, got nil")
	}
	if !strings.Contains(err.Error(), "slidingWindowMxTime") {
		t.Fatalf("error should name the misspelled key, got: %v", err)
	}
}

// ValidateLive must reject a window missing slidingWindowMaxSize, naming the
// window (a zero size silently produces an inert empty window).
func TestValidateLive_WindowMissingMaxSizeErrors(t *testing.T) {
	cfg, err := loadConfigString(t, `
[global]
jailFile = "/x/jail.json"
banFile = "/x/ban.txt"

[live]
port = "8080"

[live.win_named]
slidingWindowMaxTime = "1h"
clusterArgSets = [[100, 24, 32, 0.1]]
useForJail = [true]
`)
	if err != nil {
		t.Fatalf("LoadConfig should succeed (validation is in ValidateLive): %v", err)
	}
	verr := cfg.ValidateLive()
	if verr == nil {
		t.Fatal("expected ValidateLive error for missing slidingWindowMaxSize, got nil")
	}
	if !strings.Contains(verr.Error(), "slidingWindowMaxSize") || !strings.Contains(verr.Error(), "win_named") {
		t.Fatalf("error should name the field and window, got: %v", verr)
	}
}

// ValidateLive must reject a window missing slidingWindowMaxTime.
func TestValidateLive_WindowMissingMaxTimeErrors(t *testing.T) {
	cfg, err := loadConfigString(t, `
[global]
jailFile = "/x/jail.json"
banFile = "/x/ban.txt"

[live]
port = "8080"

[live.win_named]
slidingWindowMaxSize = 1000
clusterArgSets = [[100, 24, 32, 0.1]]
useForJail = [true]
`)
	if err != nil {
		t.Fatalf("LoadConfig should succeed: %v", err)
	}
	verr := cfg.ValidateLive()
	if verr == nil {
		t.Fatal("expected ValidateLive error for missing slidingWindowMaxTime, got nil")
	}
	if !strings.Contains(verr.Error(), "slidingWindowMaxTime") || !strings.Contains(verr.Error(), "win_named") {
		t.Fatalf("error should name the field and window, got: %v", verr)
	}
}

// ValidateLive must reject a window with no clusterArgSets.
func TestValidateLive_WindowMissingClusterArgSetsErrors(t *testing.T) {
	cfg, err := loadConfigString(t, `
[global]
jailFile = "/x/jail.json"
banFile = "/x/ban.txt"

[live]
port = "8080"

[live.win_named]
slidingWindowMaxSize = 1000
slidingWindowMaxTime = "1h"
`)
	if err != nil {
		t.Fatalf("LoadConfig should succeed: %v", err)
	}
	verr := cfg.ValidateLive()
	if verr == nil {
		t.Fatal("expected ValidateLive error for missing clusterArgSets, got nil")
	}
	if !strings.Contains(verr.Error(), "clusterArgSets") || !strings.Contains(verr.Error(), "win_named") {
		t.Fatalf("error should name the field and window, got: %v", verr)
	}
}

// A fully-specified live window passes ValidateLive (no over-failing).
func TestValidateLive_FullySpecifiedWindowPasses(t *testing.T) {
	cfg, err := loadConfigString(t, `
[global]
jailFile = "/x/jail.json"
banFile = "/x/ban.txt"

[live]
port = "8080"

[live.win_named]
slidingWindowMaxSize = 1000
slidingWindowMaxTime = "1h"
clusterArgSets = [[100, 24, 32, 0.1]]
useForJail = [true]
`)
	if err != nil {
		t.Fatalf("LoadConfig should succeed: %v", err)
	}
	if verr := cfg.ValidateLive(); verr != nil {
		t.Fatalf("fully-specified window should pass ValidateLive, got: %v", verr)
	}
}

// Inline '#' comments after a value in pattern/CIDR list files are stripped,
// leaving the bare value.
func TestLoadPatternFile_StripsInlineComment(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ua.txt")
	content := "# header\nGooglebot   # the google crawler\n\nbingbot#no space before hash\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	patterns, err := loadPatternFile(path)
	if err != nil {
		t.Fatalf("loadPatternFile: %v", err)
	}
	want := []string{"Googlebot", "bingbot"}
	if len(patterns) != len(want) {
		t.Fatalf("expected %d patterns, got %d: %v", len(want), len(patterns), patterns)
	}
	for i := range want {
		if patterns[i] != want[i] {
			t.Errorf("pattern[%d] = %q, want %q", i, patterns[i], want[i])
		}
	}
}

// loadCIDRFile strips a trailing inline '#' comment and validates the bare CIDR.
func TestLoadCIDRFile_StripsInlineComment(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cidrs.txt")
	content := "192.168.1.0/24  # home LAN\n10.0.0.0/8# internal\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	cidrs, err := loadCIDRFile(path)
	if err != nil {
		t.Fatalf("loadCIDRFile: %v", err)
	}
	want := []string{"192.168.1.0/24", "10.0.0.0/8"}
	if len(cidrs) != len(want) {
		t.Fatalf("expected %d CIDRs, got %d: %v", len(want), len(cidrs), cidrs)
	}
	for i := range want {
		if cidrs[i] != want[i] {
			t.Errorf("cidr[%d] = %q, want %q", i, cidrs[i], want[i])
		}
	}
}

// An inline comment must not mask an invalid CIDR: the bare remainder is still
// validated, and the IPv4-only mask guard still rejects IPv6.
func TestLoadCIDRFile_InlineCommentStillValidatesAndRejectsIPv6(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v6.txt")
	if err := os.WriteFile(path, []byte("2001:db8::/32  # an IPv6 range with a comment\n"), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := loadCIDRFile(path)
	if err == nil {
		t.Fatal("expected IPv6 rejection even with inline comment, got nil")
	}
	if !strings.Contains(err.Error(), "IPv6 CIDR not supported") {
		t.Fatalf("error should mention IPv6 not supported, got: %v", err)
	}
}
