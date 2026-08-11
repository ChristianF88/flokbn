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

// TestActiveFilters_UAWhitelistOnly is the regression guard: a baseline trie
// with no per-trie filters but an active global UA whitelist must still list it
// (TYPE + COUNT), not report "None".
func TestActiveFilters_UAWhitelistOnly(t *testing.T) {
	gf := GlobalFilters{IPWhitelistCIDRs: 3, UAWhitelistPatterns: 5}
	filters := ActiveFilters(TrieParameters{}, gf)

	if len(filters) == 0 {
		t.Fatalf("expected non-empty filters for active UA whitelist, got empty (renderer would print None)")
	}
	if !hasEntry(filters, "UA whitelist (5 patterns)") {
		t.Errorf("missing UA whitelist entry, got %v", filters)
	}
}

// TestActiveFilters_IPWhitelistNeverListed guards the fix for the misleading
// display: the IP whitelist does not drop requests from any trie (it acts only
// in the jail/ban publish pipeline), so it must never appear as an active
// filter — an IP-whitelist-only config renders "None".
func TestActiveFilters_IPWhitelistNeverListed(t *testing.T) {
	onlyIP := ActiveFilters(TrieParameters{}, GlobalFilters{IPWhitelistCIDRs: 4})
	if len(onlyIP) != 0 {
		t.Fatalf("expected empty filters for IP-whitelist-only config (=> None), got %v", onlyIP)
	}

	both := ActiveFilters(TrieParameters{}, GlobalFilters{IPWhitelistCIDRs: 4, UAWhitelistPatterns: 7})
	for _, f := range both {
		if strings.Contains(f, "IP whitelist") {
			t.Errorf("IP whitelist must never be listed as an active filter, got %v", both)
		}
	}
}

// TestActiveFilters_TrulyNone verifies that with no per-trie filters AND a zero
// UA whitelist count the result is empty, so the renderer prints "None".
func TestActiveFilters_TrulyNone(t *testing.T) {
	filters := ActiveFilters(TrieParameters{}, GlobalFilters{})
	if len(filters) != 0 {
		t.Fatalf("expected empty filters (=> None), got %v", filters)
	}
}

// TestActiveFilters_PerTrieAndUAWhitelist verifies per-trie filters and the
// global UA whitelist coexist, with the UA whitelist entry appended AFTER the
// per-trie entries.
func TestActiveFilters_PerTrieAndUAWhitelist(t *testing.T) {
	params := TrieParameters{UserAgentRegex: strPtr("badbot")}
	gf := GlobalFilters{IPWhitelistCIDRs: 2, UAWhitelistPatterns: 1}
	filters := ActiveFilters(params, gf)

	if !hasEntry(filters, "User-Agent: badbot") {
		t.Errorf("missing per-trie User-Agent regex entry, got %v", filters)
	}
	if !hasEntry(filters, "UA whitelist (1 patterns)") {
		t.Errorf("missing UA whitelist entry, got %v", filters)
	}

	// The UA whitelist entry must come after the per-trie ones.
	joined := strings.Join(filters, "|")
	uaRegexIdx := strings.Index(joined, "User-Agent: badbot")
	uaWLIdx := strings.Index(joined, "UA whitelist")
	if uaRegexIdx < 0 || uaWLIdx < 0 || uaWLIdx < uaRegexIdx {
		t.Errorf("expected UA whitelist entry appended after per-trie entries, got %v", filters)
	}
}

// TestActiveFilters_OnlyNonzeroUAWhitelistListed verifies the UA whitelist is
// listed only when its count > 0.
func TestActiveFilters_OnlyNonzeroUAWhitelistListed(t *testing.T) {
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
