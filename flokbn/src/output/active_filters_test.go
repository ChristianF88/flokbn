package output

import (
	"strings"
	"testing"
	"time"
)

// strPtr is a tiny helper for the optional regex fields in TrieParameters.
func strPtr(s string) *string { return &s }

// hasEntry reports whether want appears verbatim in the filter list.
func hasEntry(filters []string, want string) bool {
	for _, f := range filters {
		if f == want {
			return true
		}
	}
	return false
}

// TestActiveFilters_WhitelistsOnly is the regression guard for the bug: a
// baseline trie with no per-trie filters but with active global whitelists must
// still list those whitelists (TYPE + COUNT), not report "None".
func TestActiveFilters_WhitelistsOnly(t *testing.T) {
	gf := GlobalFilters{IPWhitelistCIDRs: 3, UAWhitelistPatterns: 5}
	filters := ActiveFilters(TrieParameters{}, gf)

	if len(filters) == 0 {
		t.Fatalf("expected non-empty filters for active whitelists, got empty (renderer would print None)")
	}
	if !hasEntry(filters, "IP whitelist (3 CIDRs)") {
		t.Errorf("missing IP whitelist entry, got %v", filters)
	}
	if !hasEntry(filters, "UA whitelist (5 patterns)") {
		t.Errorf("missing UA whitelist entry, got %v", filters)
	}
}

// TestActiveFilters_TrulyNone verifies that with no per-trie filters AND zero
// whitelist counts the result is empty, so the renderer prints "None".
func TestActiveFilters_TrulyNone(t *testing.T) {
	filters := ActiveFilters(TrieParameters{}, GlobalFilters{})
	if len(filters) != 0 {
		t.Fatalf("expected empty filters (=> None), got %v", filters)
	}
}

// TestActiveFilters_PerTrieAndWhitelist verifies per-trie filters and global
// whitelists coexist, with the whitelist entries appended AFTER the per-trie
// entries.
func TestActiveFilters_PerTrieAndWhitelist(t *testing.T) {
	params := TrieParameters{UserAgentRegex: strPtr("badbot")}
	gf := GlobalFilters{IPWhitelistCIDRs: 2, UAWhitelistPatterns: 1}
	filters := ActiveFilters(params, gf)

	if !hasEntry(filters, "User-Agent: badbot") {
		t.Errorf("missing per-trie User-Agent regex entry, got %v", filters)
	}
	if !hasEntry(filters, "IP whitelist (2 CIDRs)") {
		t.Errorf("missing IP whitelist entry, got %v", filters)
	}
	if !hasEntry(filters, "UA whitelist (1 patterns)") {
		t.Errorf("missing UA whitelist entry, got %v", filters)
	}

	// Whitelist entries must come after the per-trie ones.
	joined := strings.Join(filters, "|")
	uaRegexIdx := strings.Index(joined, "User-Agent: badbot")
	ipWLIdx := strings.Index(joined, "IP whitelist")
	if uaRegexIdx < 0 || ipWLIdx < 0 || ipWLIdx < uaRegexIdx {
		t.Errorf("expected whitelist entries appended after per-trie entries, got %v", filters)
	}
}

// TestActiveFilters_OnlyNonzeroWhitelistsListed verifies each whitelist is
// listed independently and only when its count > 0.
func TestActiveFilters_OnlyNonzeroWhitelistsListed(t *testing.T) {
	onlyIP := ActiveFilters(TrieParameters{}, GlobalFilters{IPWhitelistCIDRs: 4})
	if !hasEntry(onlyIP, "IP whitelist (4 CIDRs)") {
		t.Errorf("expected IP whitelist entry, got %v", onlyIP)
	}
	if hasEntry(onlyIP, "UA whitelist (0 patterns)") || len(onlyIP) != 1 {
		t.Errorf("expected only the IP whitelist entry, got %v", onlyIP)
	}

	onlyUA := ActiveFilters(TrieParameters{}, GlobalFilters{UAWhitelistPatterns: 7})
	if !hasEntry(onlyUA, "UA whitelist (7 patterns)") {
		t.Errorf("expected UA whitelist entry, got %v", onlyUA)
	}
	if len(onlyUA) != 1 {
		t.Errorf("expected only the UA whitelist entry, got %v", onlyUA)
	}
}

// TestActiveFilters_TimeRangeStillWorks guards that the extracted helper kept
// the existing per-trie behaviour (time range entry) intact.
func TestActiveFilters_TimeRangeStillWorks(t *testing.T) {
	start := time.Date(2025, 1, 2, 3, 4, 0, 0, time.UTC)
	params := TrieParameters{TimeRange: &TimeRange{Start: start}}
	filters := ActiveFilters(params, GlobalFilters{})
	if len(filters) != 1 || !strings.HasPrefix(filters[0], "Time: ") {
		t.Fatalf("expected a single Time entry, got %v", filters)
	}
}
