package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// MSG-02: every unknown-name rejection must name the offender AND list the
// valid set, and value tokens / locations must use one consistent grammar.
// These tests lock in the actionable-message contract so a future edit cannot
// silently drop the "(want: ...)" hint or revert the unified IPv6/location
// grammar.

// The unknown top-level section error must enumerate the valid sections so an
// operator who typed [gloabl] is told [global]/[static]/[live]/[log] are valid.
func TestUnknownTopLevelSection_ListsValidSet(t *testing.T) {
	_, err := loadConfigString(t, `
[gloabl]
jailFile = "/x/jail.json"
`)
	if err == nil {
		t.Fatal("expected error for unknown top-level section, got nil")
	}
	msg := err.Error()
	for _, want := range []string{"[global]", "[static]", "[live]", "[log]", "[static.<name>]", "[live.<name>]"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("top-level section error must list %q, got: %v", want, err)
		}
	}
}

// The [global] unknown-key error must list the recognized [global] keys.
func TestUnknownGlobalKey_ListsValidSet(t *testing.T) {
	msg := loadAndReport(t, `
[global]
jailfile = "/x/jail.json"
`, StaticMode)
	if !strings.Contains(msg, "want:") {
		t.Fatalf("[global] unknown-key error must list the valid set, got:\n%s", msg)
	}
	for _, want := range []string{"jailFile", "banFile", "whitelist", "blacklist", "userAgentWhitelist", "userAgentBlacklist"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("[global] unknown-key error must list %q, got:\n%s", want, msg)
		}
	}
}

// The [static] unknown-key error must list the recognized [static] keys.
func TestUnknownStaticKey_ListsValidSet(t *testing.T) {
	msg := loadAndReport(t, `
[static]
logfile = "/x/access.log"
`, StaticMode)
	for _, want := range []string{"want:", "logFile", "logFormat", "plotPath"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("[static] unknown-key error must list %q, got:\n%s", want, msg)
		}
	}
}

// The [live] unknown-key error must list the recognized [live] scalar keys.
func TestUnknownLiveKey_ListsValidSet(t *testing.T) {
	msg := loadAndReport(t, `
[live]
port = "8080"
prt = "9090"
`, LiveMode)
	for _, want := range []string{"want:", "port", "readTimeout", "statsListen", "topTalkers"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("[live] unknown-key error must list %q, got:\n%s", want, msg)
		}
	}
}

// An unknown trie key must be reported with the bracket-form, instance-named
// section label ([static.<name>] trie) AND the valid trie key set.
func TestUnknownTrieKey_ListsValidSetAndNamedSection(t *testing.T) {
	msg := loadAndReport(t, `
[static.trie_1]
clusterArgSets = [[1000, 24, 32, 0.1]]
useForjail = [true]
`, StaticMode)
	if !strings.Contains(msg, "[static.trie_1] trie") {
		t.Fatalf("trie unknown-key error must name the bracket-form section [static.trie_1] trie, got:\n%s", msg)
	}
	for _, want := range []string{"want:", "useForJail", "clusterArgSets", "cidrRanges"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("trie unknown-key error must list %q, got:\n%s", want, msg)
		}
	}
}

// An unknown sliding-trie key must be reported with the bracket-form,
// instance-named section label ([live.<name>] sliding-trie) AND the valid set.
func TestUnknownSlidingTrieKey_ListsValidSetAndNamedSection(t *testing.T) {
	msg := loadAndReport(t, `
[live]
port = "8080"

[live.win_1]
slidingWindowMaxSize = 100
slidingWindowMaxTime = "1h"
clusterArgSets = [[100, 24, 32, 0.1]]
slidingWindowMxTime = "2h"
`, LiveMode)
	if !strings.Contains(msg, "[live.win_1] sliding-trie") {
		t.Fatalf("sliding-trie unknown-key error must name [live.win_1] sliding-trie, got:\n%s", msg)
	}
	if !strings.Contains(msg, "want:") {
		t.Fatalf("sliding-trie unknown-key error must list the valid set, got:\n%s", msg)
	}
}

// validateCIDRRangeEntry must reject IPv6 with the unified base phrase
// "IPv6 not supported (IPv4-only tool)", the section[index] location grammar,
// and a %q-quoted value.
func TestCIDRRangeEntry_IPv6UnifiedMessage(t *testing.T) {
	msg := loadAndReport(t, `
[static.trie_1]
clusterArgSets = [[1000, 24, 32, 0.1]]
cidrRanges = ["2001:db8::/48"]
`, StaticMode)
	if !strings.Contains(msg, "IPv6 not supported (IPv4-only tool)") {
		t.Fatalf("cidrRanges IPv6 error must use the unified phrase, got:\n%s", msg)
	}
	if !strings.Contains(msg, "cidrRanges[0]") {
		t.Fatalf("cidrRanges IPv6 error must use the section[index] location grammar, got:\n%s", msg)
	}
	if !strings.Contains(msg, `"2001:db8::/48"`) {
		t.Fatalf("cidrRanges IPv6 error must quote the offending value with %%q, got:\n%s", msg)
	}
}

// loadCIDRFile must reject IPv6 with the unified phrase, the path:line location
// grammar, and a %q-quoted value.
func TestLoadCIDRFile_IPv6UnifiedMessage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wl.txt")
	if err := os.WriteFile(path, []byte("10.0.0.0/8\n2001:db8::/32\n"), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := loadCIDRFile(path)
	if err == nil {
		t.Fatal("expected error for IPv6 line, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "IPv6 not supported (IPv4-only tool)") {
		t.Fatalf("loadCIDRFile IPv6 error must use the unified phrase, got: %v", err)
	}
	if !strings.Contains(msg, path+":2:") {
		t.Fatalf("loadCIDRFile IPv6 error must use the path:line grammar, got: %v", err)
	}
	if !strings.Contains(msg, `"2001:db8::/32"`) {
		t.Fatalf("loadCIDRFile IPv6 error must quote the offending value with %%q, got: %v", err)
	}
}

// loadCIDRFile must reject a malformed (non-IPv6) CIDR with the path:line
// grammar and a %q-quoted value.
func TestLoadCIDRFile_InvalidCIDRUnifiedMessage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.txt")
	if err := os.WriteFile(path, []byte("10.0.0.0/8\nnot-a-cidr\n"), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := loadCIDRFile(path)
	if err == nil {
		t.Fatal("expected error for malformed CIDR, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "invalid CIDR format") {
		t.Fatalf("loadCIDRFile error must say invalid CIDR format, got: %v", err)
	}
	if !strings.Contains(msg, path+":2:") {
		t.Fatalf("loadCIDRFile error must use the path:line grammar, got: %v", err)
	}
	if !strings.Contains(msg, `"not-a-cidr"`) {
		t.Fatalf("loadCIDRFile error must quote the offending value with %%q, got: %v", err)
	}
}

// The CLI clusterArgSet bound checks must name the offending set index (0-based)
// and use integer formatting, matching the TOML path's row index.
func TestParseClusterArgSetsFromStrings_MinDepthGtMaxDepthNamesSet(t *testing.T) {
	// set 0 is valid; set 1 has minDepth(32) > maxDepth(24).
	_, err := ParseClusterArgSetsFromStrings([]string{
		"1000", "24", "32", "0.1",
		"1000", "32", "24", "0.1",
	})
	if err == nil {
		t.Fatal("expected error when minDepth > maxDepth, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "clusterArgSets set 1:") {
		t.Fatalf("error must name set 1, got: %v", err)
	}
	if !strings.Contains(msg, "minDepth (32)") || !strings.Contains(msg, "maxDepth (24)") {
		t.Fatalf("error must use integer formatting for the depths, got: %v", err)
	}
}

// The CLI maxDepth>32 bound check must name the offending set index and use
// integer formatting.
func TestParseClusterArgSetsFromStrings_MaxDepthOver32NamesSet(t *testing.T) {
	_, err := ParseClusterArgSetsFromStrings([]string{
		"1000", "24", "32", "0.1",
		"1000", "24", "33", "0.1",
	})
	if err == nil {
		t.Fatal("expected error when maxDepth > 32, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "clusterArgSets set 1:") {
		t.Fatalf("error must name set 1, got: %v", err)
	}
	if !strings.Contains(msg, "maxDepth (33)") {
		t.Fatalf("error must use integer formatting for maxDepth, got: %v", err)
	}
}

// The arity error uses the literal clusterArgSets key (terminology fix).
func TestParseClusterArgSetsFromStrings_ArityUsesLiteralKey(t *testing.T) {
	_, err := ParseClusterArgSetsFromStrings([]string{"1000", "24", "32"})
	if err == nil {
		t.Fatal("expected error for wrong arity, got nil")
	}
	if !strings.Contains(err.Error(), "invalid clusterArgSets") {
		t.Fatalf("arity error must use the literal clusterArgSets key, got: %v", err)
	}
}

// File-open and file-read failures use the "cannot open %q" verb + %q path.
func TestLoadCIDRFile_MissingFileUsesCannotOpenVerb(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist.txt")
	_, err := loadCIDRFile(missing)
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "cannot open") {
		t.Fatalf("missing-file error must use the cannot-open verb, got: %v", err)
	}
	if !strings.Contains(msg, `"`+missing+`"`) {
		t.Fatalf("missing-file error must quote the path with %%q, got: %v", err)
	}
}

// loadPatternFile shares the cannot-open verb + %q path.
func TestLoadPatternFile_MissingFileUsesCannotOpenVerb(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-patterns.txt")
	_, err := loadPatternFile(missing)
	if err == nil {
		t.Fatal("expected error for missing pattern file, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "cannot open") {
		t.Fatalf("missing-file error must use the cannot-open verb, got: %v", err)
	}
	if !strings.Contains(msg, `"`+missing+`"`) {
		t.Fatalf("missing-file error must quote the path with %%q, got: %v", err)
	}
}

// ValidateLive errors use "config" (not "configuration").
func TestValidateLive_UsesConfigTerminology(t *testing.T) {
	cfg := &Config{Live: nil}
	err := cfg.ValidateLive()
	if err == nil {
		t.Fatal("expected error for missing live section, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "live config") {
		t.Fatalf("ValidateLive must say \"live config\", got: %v", err)
	}
	if strings.Contains(msg, "configuration") {
		t.Fatalf("ValidateLive must not use \"configuration\", got: %v", err)
	}
}
