package config

import (
	"strings"
	"testing"
)

// AUDIT-03: config-file cidrRanges is a first-class input that previously
// appended verbatim with no IPv4-only gate (unlike loadCIDRFile and the CLI
// flag path). An IPv6 entry flowed unchecked into trie.CountInRange and either
// silently mis-counted (mask <=32) or panicked on a negative shift (mask >32).
// parseTrieConfig (static) and parseSlidingTrieConfig (live, validate-and-
// discard) now reject IPv6 at load, naming the offending entry. These tests
// lock in fail-loud rejection for both modes and confirm IPv4 still loads.

// reuses loadConfigString from config_failloud_test.go (same package).

// Static config: an IPv6 cidrRanges entry with prefix >32 (the historical
// panic case) must fail at load with an error naming the entry.
func TestLoadConfig_StaticCIDRRangesRejectsIPv6Over32(t *testing.T) {
	report := loadAndReport(t, `
[static.trie_1]
cidrRanges = ["2001:db8::/48"]
`, StaticMode)
	if !strings.Contains(report, "IPv6") || !strings.Contains(report, "2001:db8::/48") {
		t.Fatalf("report should mention IPv6 and name the entry, got:\n%s", report)
	}
}

// Static config: an IPv6 cidrRanges entry with prefix <=32 (silent mis-count
// case, no panic) must also fail at load.
func TestLoadConfig_StaticCIDRRangesRejectsIPv6Under32(t *testing.T) {
	report := loadAndReport(t, `
[static.trie_1]
cidrRanges = ["2001:db8::/32"]
`, StaticMode)
	if !strings.Contains(report, "IPv6") || !strings.Contains(report, "2001:db8::/32") {
		t.Fatalf("report should mention IPv6 and name the entry, got:\n%s", report)
	}
}

// Static config: an IPv4-mapped IPv6 cidrRanges entry (non-nil To4() but a
// 16-byte mask) must be rejected by the len(Mask)!=4 gate, not slip through.
func TestLoadConfig_StaticCIDRRangesRejectsIPv4MappedIPv6(t *testing.T) {
	report := loadAndReport(t, `
[static.trie_1]
cidrRanges = ["::ffff:192.168.1.0/120"]
`, StaticMode)
	if !strings.Contains(report, "IPv6") {
		t.Fatalf("report should mention IPv6, got:\n%s", report)
	}
}

// Static config: a malformed (non-CIDR) cidrRanges entry must fail at load.
func TestLoadConfig_StaticCIDRRangesRejectsMalformed(t *testing.T) {
	report := loadAndReport(t, `
[static.trie_1]
cidrRanges = ["not-a-cidr"]
`, StaticMode)
	if !strings.Contains(report, "cidrRanges") {
		t.Fatalf("report should name the cidrRanges field, got:\n%s", report)
	}
}

// Static config: a valid IPv4 cidrRanges entry must still load and be stored.
func TestLoadConfig_StaticCIDRRangesAcceptsIPv4(t *testing.T) {
	cfg, err := loadConfigString(t, `
[static.trie_1]
cidrRanges = ["10.0.0.0/8", "192.168.1.0/24"]
`)
	if err != nil {
		t.Fatalf("valid IPv4 cidrRanges should load, got: %v", err)
	}
	tc, ok := cfg.StaticTries["trie_1"]
	if !ok {
		t.Fatal("expected static trie_1 to be parsed")
	}
	if len(tc.CIDRRanges) != 2 || tc.CIDRRanges[0] != "10.0.0.0/8" || tc.CIDRRanges[1] != "192.168.1.0/24" {
		t.Fatalf("IPv4 cidrRanges not stored verbatim, got: %v", tc.CIDRRanges)
	}
}

// Live config: cidrRanges is accepted-but-not-consumed for sliding tries, but
// an IPv6 entry must now fail at load (deliberate strictness increase: a live
// config that previously tolerated IPv6 cidrRanges now fails loud).
func TestLoadConfig_LiveCIDRRangesRejectsIPv6(t *testing.T) {
	report := loadAndReport(t, `
[live.win_1]
cidrRanges = ["2001:db8::/48"]
`, LiveMode)
	if !strings.Contains(report, "IPv6") || !strings.Contains(report, "2001:db8::/48") {
		t.Fatalf("report should mention IPv6 and name the entry, got:\n%s", report)
	}
}

// Live config: a valid IPv4 cidrRanges entry must still load (tolerated and
// ignored, exactly as before — no CIDRRanges field on SlidingTrieConfig).
func TestLoadConfig_LiveCIDRRangesAcceptsIPv4(t *testing.T) {
	cfg, err := loadConfigString(t, `
[live.win_1]
cidrRanges = ["10.0.0.0/8"]
`)
	if err != nil {
		t.Fatalf("valid IPv4 cidrRanges in live config should load, got: %v", err)
	}
	if _, ok := cfg.LiveTries["win_1"]; !ok {
		t.Fatal("expected live win_1 to be parsed")
	}
}
