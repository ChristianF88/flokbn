package analysis

import (
	"fmt"

	"github.com/ChristianF88/flokbn/cidr"
	"github.com/ChristianF88/flokbn/config"
	"github.com/ChristianF88/flokbn/output"
)

// globalLists holds what one static run needs from the [global] list files.
// loadGlobalLists reads each file once; the request filter, the output summary
// and the publish step all work from this copy.
//
// The manual IP blacklist is not here: only the publish step uses it, and it
// reads the file itself when a jail and a ban file are configured.
type globalLists struct {
	// uaMatcher answers the exact-match User-Agent whitelist/blacklist lookup.
	// Never nil; empty when no User-Agent list is configured.
	uaMatcher *cidr.UserAgentMatcher
	// uaWhitelistPatterns is the number of entries in the User-Agent whitelist
	// file (as listed, before the matcher folds case and duplicates).
	uaWhitelistPatterns int

	// whitelist is the IP whitelist as CIDR strings. An unreadable file does
	// not fail the load: the analysis does not depend on it. whitelistErr keeps
	// the error for the publish step, which does.
	whitelist    []string
	whitelistErr error
}

// loadGlobalLists reads the User-Agent lists and the IP whitelist. A
// User-Agent list that is configured but unreadable is an error: running
// without it would skip all User-Agent filtering and publish a wrong ban file.
// The wrapped error names the file.
func loadGlobalLists(cfg *config.Config) (*globalLists, error) {
	uaWhitelist, err := cfg.LoadUserAgentWhitelistPatterns()
	if err != nil {
		return nil, fmt.Errorf("failed to load User-Agent whitelist: %w", err)
	}
	uaBlacklist, err := cfg.LoadUserAgentBlacklistPatterns()
	if err != nil {
		return nil, fmt.Errorf("failed to load User-Agent blacklist: %w", err)
	}

	lists := &globalLists{
		uaMatcher:           cidr.NewUserAgentMatcher(uaWhitelist, uaBlacklist),
		uaWhitelistPatterns: len(uaWhitelist),
	}
	lists.whitelist, lists.whitelistErr = cfg.LoadWhitelistCIDRs()
	return lists, nil
}

// globalFilters reports how many entries each global whitelist holds. Only the
// UA whitelist drops requests from every trie (and is rendered as an active
// filter); the IP whitelist acts solely in the jail/ban publish pipeline, so
// its count is surfaced in the JSON output only (see output.GlobalFilters).
// An unreadable IP whitelist counts as zero here. CLI runs never get that far:
// the pre-work barrier (config.Validate -> validateListFiles) rejects an
// unreadable or IPv6 list before any analysis.
func (l *globalLists) globalFilters() output.GlobalFilters {
	gf := output.GlobalFilters{UAWhitelistPatterns: l.uaWhitelistPatterns}
	if l.whitelistErr == nil {
		gf.IPWhitelistCIDRs = len(l.whitelist)
	}
	return gf
}
