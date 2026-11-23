package analysis

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/ChristianF88/flokbn/cidr"
	"github.com/ChristianF88/flokbn/config"
	"github.com/ChristianF88/flokbn/ingestor"
	"github.com/ChristianF88/flokbn/iputils"
	"github.com/ChristianF88/flokbn/logparser"
	"github.com/ChristianF88/flokbn/output"
	"github.com/ChristianF88/flokbn/trie"
)

// StaticWithRequests runs static analysis from config and also returns the parsed requests.
// It is a thin wrapper around StaticWithRequestsCtx using a background context
// (no cancellation), preserving the signature for the ~dozen existing call sites.
func StaticWithRequests(cfg *config.Config) (*output.JSONOutput, []ingestor.Request, error) {
	return StaticWithRequestsCtx(context.Background(), cfg)
}

// StaticWithRequestsCtx runs static analysis from config and also returns the
// parsed requests. The context provides coarse-grained cancellation for
// interactive callers (the TUI): cancelling it short-circuits before the heavy
// trie work materialises results and, critically, before the jail/ban-file side
// effects, so a quit-mid-analysis run never mutates on-disk state. The hot
// trie/clustering internals are NOT context-threaded (out of scope, and on the
// measured path); the checks below bracket the CPU-bound phase only.
func StaticWithRequestsCtx(ctx context.Context, cfg *config.Config) (*output.JSONOutput, []ingestor.Request, error) {
	analysisStart := time.Now()
	jsonOutput := output.NewJSONOutput("static", analysisStart)

	// Validate config (same as original)
	if cfg == nil {
		jsonOutput.AddError("config_error", "configuration is nil", 1)
		return jsonOutput, nil, fmt.Errorf("configuration is nil")
	}

	if cfg.Static == nil {
		jsonOutput.AddError("config_error", "static configuration section is missing", 1)
		return jsonOutput, nil, fmt.Errorf("static configuration section is missing")
	}

	// Early cancellation check: bail before any parsing/trie work begins.
	if err := ctx.Err(); err != nil {
		return jsonOutput, nil, err
	}

	if len(cfg.StaticTries) == 0 {
		jsonOutput.AddWarning("config_warning", "no static tries configured, analysis may have limited results", 1)
	}

	// Parse requests once
	logFormat := cfg.Static.LogFormat
	if logFormat == "" {
		logFormat = logparser.DefaultLogFormat
	}

	// Create parser. NewParser revalidates the format as defense-in-depth;
	// unreachable for a barrier-passed config (config.Validate already ran
	// logparser.ValidateFormat, a total precondition for NewParser success).
	parser, err := logparser.NewParser(logFormat)
	if err != nil {
		jsonOutput.AddError("parser_init", fmt.Sprintf("Failed to create parallel parser: %v", err), 1)
		return jsonOutput, nil, err
	}

	// Check if any trie config requires string fields (URI/UserAgent) or non-IP fields.
	// The User-Agent matcher depends only on global config (the same whitelist/blacklist
	// files for every trie), so it is built ONCE here and shared across all tries via
	// processTrie - avoiding N redundant disk reads (one matcher rebuild per trie).
	needsStringFields := false
	needsNonIPFields := false
	sharedUAMatcher, uaMatcherErr := cfg.CreateUserAgentMatcher()
	if uaMatcherErr != nil {
		// A configured-but-unreadable UA whitelist/blacklist file is a fatal
		// setup error: continuing would skip ALL UA filtering and persist a wrong
		// ban file (UA-whitelisted IPs bannable, UA-blacklisted bots not
		// force-banned) on a "successful" exit. Fail loud BEFORE any trie work or
		// the jail/ban-file side effects below - identical severity to the fast
		// path Static(). The wrapped loader error already names the file.
		jsonOutput.AddError("useragent_matcher_create", fmt.Sprintf("Failed to create User-Agent matcher: %v", uaMatcherErr), 1)
		return jsonOutput, nil, uaMatcherErr
	}
	hasGlobalUAFilters := sharedUAMatcher != nil && sharedUAMatcher.Count() > 0
	for _, tc := range cfg.StaticTries {
		if tc == nil {
			continue
		}
		if hasGlobalUAFilters || tc.UserAgentRegex != "" || tc.EndpointRegex != "" {
			needsStringFields = true
			needsNonIPFields = true
		}
		if tc.StartTime != nil || tc.EndTime != nil {
			needsNonIPFields = true
		}
	}
	parser.SkipStringFields = !needsStringFields
	parser.SkipNonIPFields = !needsNonIPFields

	parseStart := time.Now()
	requests, err := parser.ParseFile(cfg.Static.LogFile)
	parseDuration := time.Since(parseStart)
	if err != nil {
		jsonOutput.AddError("parse_file", fmt.Sprintf("Failed to parse log file %q: %v", cfg.Static.LogFile, err), 1)
		return jsonOutput, nil, err
	}

	// Lines longer than logparser.MaxLineLen are skipped by the parser, not
	// analysed: say so instead of dropping them silently.
	if n := parser.Stats().OversizedLines; n > 0 {
		jsonOutput.AddWarning("oversized_lines",
			fmt.Sprintf("%d line(s) longer than %d bytes were skipped", n, logparser.MaxLineLen), 1)
	}

	// Set general information
	jsonOutput.General.LogFile = cfg.Static.LogFile
	jsonOutput.General.TotalRequests = len(requests)
	jsonOutput.General.Parsing.DurationMS = parseDuration.Milliseconds()
	jsonOutput.General.Parsing.RatePerSecond = int64(float64(len(requests)) / parseDuration.Seconds())
	jsonOutput.General.Parsing.Format = logFormat

	// Surface malformed status/bytes fields (lines are KEPT with the field
	// zeroed; only the counts are reported). Structurally zero when
	// SkipNonIPFields is true (IP-only path never scans status/bytes).
	if ps := parser.Stats(); ps.MalformedStatus > 0 || ps.MalformedBytes > 0 {
		if ps.MalformedStatus > 0 {
			jsonOutput.AddWarning("malformed_field",
				fmt.Sprintf("%d requests (%.1f%%) had a non-numeric status field (%%s) - status recorded as 0, lines kept",
					ps.MalformedStatus, float64(ps.MalformedStatus)/float64(len(requests))*100), 1)
		}
		if ps.MalformedBytes > 0 {
			jsonOutput.AddWarning("malformed_field",
				fmt.Sprintf("%d requests (%.1f%%) had a non-numeric bytes field (%%b) - bytes recorded as 0, lines kept",
					ps.MalformedBytes, float64(ps.MalformedBytes)/float64(len(requests))*100), 1)
		}
	}

	if len(requests) == 0 {
		jsonOutput.AddWarning("empty_logfile", "No requests found in logfile", 1)
		// Nothing to analyse, but the publish step still has work: bans that ran
		// out since the last run must leave the ban file, and whitelist/blacklist
		// edits must be picked up. A cancelled (quit) TUI run must not mutate
		// on-disk jail/ban state.
		if err := ctx.Err(); err != nil {
			return jsonOutput, requests, err
		}
		if err := publishJailAndBans(cfg, jsonOutput); err != nil {
			return jsonOutput, requests, err
		}
		return jsonOutput, requests, nil
	}

	// Process tries in parallel
	var trieWG sync.WaitGroup
	var triesMutex sync.Mutex
	trieResults := make([]output.TrieResult, 0, len(cfg.StaticTries))

	// Channel for coordinating trie work
	type trieWork struct {
		name   string
		config *config.TrieConfig
	}

	// Accumulate User-Agent derived IPs across all tries (thread-safe via
	// triesMutex). Each trie contributes its own distinct IPs; the lists are
	// sorted and de-duplicated once after all tries finished.
	var globalUserAgentWhitelistIPs, globalUserAgentBlacklistIPs []uint32

	// General.UniqueIPs describes the whole log (distinct client IPs across all
	// parsed requests), independent of any trie's filters. Counted concurrently
	// with the trie work; joined right after it.
	var generalUniqueIPs int
	var uniqueWG sync.WaitGroup
	uniqueWG.Add(1)
	go func() {
		defer uniqueWG.Done()
		generalUniqueIPs = countUniqueRequestIPs(requests)
	}()

	trieWorkChan := make(chan trieWork, len(cfg.StaticTries))

	// Start trie workers (parallel trie building)
	numTrieWorkers := runtime.NumCPU()
	if len(cfg.StaticTries) < numTrieWorkers {
		numTrieWorkers = len(cfg.StaticTries)
	}

	for i := 0; i < numTrieWorkers; i++ {
		trieWG.Add(1)
		go func() {
			defer trieWG.Done()

			for work := range trieWorkChan {
				result, whitelistIPs, blacklistIPs := processTrie(work.name, work.config, requests, sharedUAMatcher, jsonOutput)

				// Thread-safe append to results and merge UA IPs
				triesMutex.Lock()
				trieResults = append(trieResults, result)
				globalUserAgentWhitelistIPs = append(globalUserAgentWhitelistIPs, whitelistIPs...)
				globalUserAgentBlacklistIPs = append(globalUserAgentBlacklistIPs, blacklistIPs...)
				triesMutex.Unlock()
			}
		}()
	}

	// Send work to trie workers
	for trieName, trieConfig := range cfg.StaticTries {
		trieWorkChan <- trieWork{name: trieName, config: trieConfig}
	}
	close(trieWorkChan)

	// Wait for all tries to complete
	trieWG.Wait()
	uniqueWG.Wait()

	// Cancellation check after the CPU-bound trie phase, before the jail/ban-file
	// side effects below. A cancelled (quit) TUI run must not mutate on-disk
	// jail/ban state.
	if err := ctx.Err(); err != nil {
		return jsonOutput, requests, err
	}

	// Sort results by name for consistency with sequential version
	sort.Slice(trieResults, func(i, j int) bool {
		return trieResults[i].Name < trieResults[j].Name
	})

	// Add results to output
	jsonOutput.Tries = trieResults

	// Record the global whitelist entry counts. Only the UA whitelist is a real
	// request filter (it drops requests from every trie) and is listed under
	// Active Filters; the IP whitelist count is informational only - it filters
	// nothing here (jail/ban publish pipeline only). Lists are tiny and loaded
	// once here; never in the hot loop.
	jsonOutput.GlobalFilters = computeGlobalFilters(cfg)

	jsonOutput.General.UniqueIPs = generalUniqueIPs

	// Publish the User-Agent derived IPs (also the input of the jail step below)
	// in a stable order: ascending by address, each IP once.
	jsonOutput.UserAgentWhitelistIPs = sortedUniqueIPStrings(globalUserAgentWhitelistIPs)
	jsonOutput.UserAgentBlacklistIPs = sortedUniqueIPStrings(globalUserAgentBlacklistIPs)

	// Process jail with whitelist/blacklist if configured
	if err := publishJailAndBans(cfg, jsonOutput); err != nil {
		return jsonOutput, requests, err
	}

	jsonOutput.UpdateDuration(analysisStart)
	return jsonOutput, requests, nil
}

// countUniqueRequestIPs returns the number of distinct client IPs across all
// parsed requests. Zero IPs (invalid/unparseable host field) are not counted,
// matching the IP-only fast path, whose IP slice never contains them.
func countUniqueRequestIPs(requests []ingestor.Request) int {
	ips := make([]uint32, 0, len(requests))
	for i := range requests {
		if ip := requests[i].IPUint32; ip != 0 {
			ips = append(ips, ip)
		}
	}
	iputils.RadixSortUint32(ips)
	return iputils.CountDistinctSorted(ips)
}

// sortedUniqueIPStrings sorts ips ascending (in place), drops duplicates and
// renders the dotted-quad strings. Returns nil for an empty input so the JSON
// field stays omitted.
func sortedUniqueIPStrings(ips []uint32) []string {
	if len(ips) == 0 {
		return nil
	}
	iputils.RadixSortUint32(ips)
	out := make([]string, 0, iputils.CountDistinctSorted(ips))
	for i, ip := range ips {
		if i > 0 && ip == ips[i-1] {
			continue
		}
		out = append(out, ingestor.Uint32ToIPString(ip))
	}
	return out
}

// ipSetToSlice returns the members of set in unspecified order.
func ipSetToSlice(set map[uint32]struct{}) []uint32 {
	if len(set) == 0 {
		return nil
	}
	out := make([]uint32, 0, len(set))
	for ip := range set {
		out = append(out, ip)
	}
	return out
}

// computeGlobalFilters loads the globally-configured whitelists and records
// their entry counts. Only the UA whitelist drops requests from every trie
// (and is rendered as an active filter); the IP whitelist acts solely in the
// jail/ban publish pipeline, so its count is surfaced in the JSON output only
// (see output.GlobalFilters). Only counts
// are needed (not the entries), and the files are tiny - loaded once per
// analysis here, never in the per-request hot loop. A loader error yields a
// zero count for that summary line. CFG-02: this is now strictly DOWNSTREAM of
// the pre-work barrier, which already validated every configured list file
// (config.Validate -> validateListFiles) and aborted on an unreadable/IPv6 list
// - so a broken list can no longer reach this summary as a phantom 0; the
// swallow here is a harmless belt-and-suspenders for the count line only.
func computeGlobalFilters(cfg *config.Config) output.GlobalFilters {
	var gf output.GlobalFilters
	if cfg == nil {
		return gf
	}
	if cidrs, err := cfg.LoadWhitelistCIDRs(); err == nil {
		gf.IPWhitelistCIDRs = len(cidrs)
	}
	if patterns, err := cfg.LoadUserAgentWhitelistPatterns(); err == nil {
		gf.UAWhitelistPatterns = len(patterns)
	}
	return gf
}

// processTrie builds and analyzes a single trie; callers run one goroutine per trie.
// Returns the trie result along with the distinct IPs this trie saw with a
// whitelisted / blacklisted User-Agent (numeric, unspecified order - the
// caller merges and sorts them across tries).
// userAgentMatcher is built once by the caller and shared across all tries (it
// depends only on global config), so processTrie never rebuilds it per trie.
func processTrie(trieName string, trieConfig *config.TrieConfig, requests []ingestor.Request,
	userAgentMatcher *cidr.UserAgentMatcher, jsonOutput *output.JSONOutput) (output.TrieResult, []uint32, []uint32) {

	insertStart := time.Now()

	trieResult := output.TrieResult{
		Name:       trieName,
		Parameters: output.TrieParameters{},
		Stats:      output.TrieStats{},
		Data:       []output.ClusterResult{},
	}

	if trieConfig == nil {
		jsonOutput.AddWarning("config_warning", fmt.Sprintf("Trie configuration %q is nil, skipping", trieName), 1)
		return trieResult, nil, nil
	}

	// Malformed/inverted startTime/endTime are now caught at config load and
	// reported by the pre-work barrier (CFG-01), which fails loud before analysis
	// runs - so the old invalid_time_format / invalid_time_range warnings here
	// are dead and removed. The time_filter_no_results warning (below, ~line 455)
	// is a RUNTIME observation on VALIDLY-parsed bounds and STAYS.

	// Set CIDRRanges after null check
	trieResult.Parameters.CIDRRanges = trieConfig.CIDRRanges

	// Create parallel trie backed by the seq allocator: this trie is built by a
	// single goroutine via BuildSorted (one of the radix-sorted branches
	// below), so the lock-free sequential allocator is safe here.
	trieInstance := trie.NewLockedTrieSeq()

	// Apply filtering and collect IPs for parallel insertion. The raw start/end
	// times feed the TimeRange output below; `bounds` carries the URGENT-09
	// wall-clock-vs-instant comparison semantics used by the filter loops.
	var startTime, endTime time.Time
	if trieConfig.StartTime != nil {
		startTime = *trieConfig.StartTime
	}
	if trieConfig.EndTime != nil {
		endTime = *trieConfig.EndTime
	}
	bounds := makeTimeBounds(trieConfig)

	// Add regex filters to parameters if they exist
	if trieConfig.UserAgentRegex != "" {
		trieResult.Parameters.UserAgentRegex = &trieConfig.UserAgentRegex
	}
	if trieConfig.EndpointRegex != "" {
		trieResult.Parameters.EndpointRegex = &trieConfig.EndpointRegex
	}

	// Add time range to parameters if set
	if !startTime.IsZero() || !endTime.IsZero() {
		trieResult.Parameters.TimeRange = &output.TimeRange{
			Start: startTime,
			End:   endTime,
		}
	}

	// Add UseForJail configuration if set
	if len(trieConfig.UseForJail) > 0 {
		trieResult.Parameters.UseForJail = trieConfig.UseForJail
	}

	// Count requests that pass filtering and are inserted into the trie. Only the
	// COUNT is ever consumed (TotalRequestsAfterFiltering and the zero-result time
	// warning below), so we thread an int counter rather than accumulating a full
	// []ingestor.Request that is never read.
	var filteredRequestCount int
	var ipsToInsertUint32 []uint32

	// User-Agent tracking: distinct IPs seen with a whitelisted / blacklisted
	// UA. Keyed by the numeric IP - no per-request string conversion.
	userAgentWhitelistIPSet := make(map[uint32]struct{})
	userAgentBlacklistIPSet := make(map[uint32]struct{})

	// Check if we have any filters that require per-request processing
	// Only consider User-Agent matcher a filter if it actually has patterns
	hasUserAgentFilters := userAgentMatcher != nil && userAgentMatcher.Count() > 0
	hasFilters := hasUserAgentFilters ||
		trieConfig.UserAgentRegex != "" ||
		trieConfig.EndpointRegex != "" ||
		!startTime.IsZero() ||
		!endTime.IsZero()

	// Track invalid IPs for warning
	var invalidIPCount int

	// Track requests dropped solely because their User-Agent matched the
	// global UA whitelist (surfaced in the summary so the request-count drop
	// is never unexplained when no per-trie filters are active).
	var uaWhitelistExcluded int

	// True unique-IP count, derived from the sorted insert slice in a single
	// linear pass - keeps the trie insert hot path untouched.
	var uniqueIPs int

	// Fast path for unfiltered data: use sorted insertion optimization
	if !hasFilters {
		// Use IPUint32 directly - no conversion needed (parsed directly to uint32)
		ipUints := make([]uint32, 0, len(requests))
		for _, r := range requests {
			// Skip 0 IPs (invalid or failed to parse)
			if r.IPUint32 == 0 {
				invalidIPCount++
				continue
			}
			ipUints = append(ipUints, r.IPUint32)
		}
		// Every nonzero IP was inserted, so the post-filter count is exactly len(ipUints).
		filteredRequestCount = len(ipUints)

		// Radix sort: O(n) vs sort.Slice O(n log n) - 10-15x faster for large arrays
		iputils.RadixSortUint32(ipUints)
		uniqueIPs = iputils.CountDistinctSorted(ipUints)

		// Use the seq prefix-stack build (bit-identical to InsertSorted
		// for ascending-sorted input, ~2x faster).
		trieInstance.BuildSorted(ipUints)
	} else {
		// Adaptive filtering: use concurrent processing only when complex patterns justify overhead
		usesConcurrency := len(requests) > 50000 && hasFilters

		if usesConcurrency {
			// Concurrent filtering for large datasets with complex patterns
			if err := filterRequestsConcurrent(
				requests, trieConfig, bounds,
				userAgentMatcher,
				userAgentWhitelistIPSet, userAgentBlacklistIPSet,
				&filteredRequestCount, &ipsToInsertUint32, &invalidIPCount, &uaWhitelistExcluded); err != nil {
				jsonOutput.AddError("concurrent_filtering", fmt.Sprintf("Failed to process requests concurrently: %v", err), 1)
			}
		} else {
			// Sequential filtering for simple cases (faster for small datasets)
			filterRequests(
				requests, trieConfig, bounds,
				userAgentMatcher,
				userAgentWhitelistIPSet, userAgentBlacklistIPSet,
				&filteredRequestCount, &ipsToInsertUint32, &invalidIPCount, &uaWhitelistExcluded)
		}

		// Radix sort + batch sorted insert - same optimization as unfiltered fast path
		if len(ipsToInsertUint32) > 0 {
			iputils.RadixSortUint32(ipsToInsertUint32)
			uniqueIPs = iputils.CountDistinctSorted(ipsToInsertUint32)
			trieInstance.BuildSorted(ipsToInsertUint32)
		}
	}

	insertDuration := time.Since(insertStart)

	// Add warning if invalid IPs were skipped
	if invalidIPCount > 0 {
		percentage := float64(invalidIPCount) / float64(len(requests)) * 100
		jsonOutput.AddWarning("invalid_ips_skipped",
			fmt.Sprintf("Trie %q: %d requests (%.1f%%) had invalid/missing IPs (nil or 0.0.0.0) and were skipped - check log format", trieName, invalidIPCount, percentage), 1)
	}

	// Set trie stats
	trieResult.Stats = output.TrieStats{
		TotalRequestsAfterFiltering: filteredRequestCount,
		UniqueIPs:                   uniqueIPs,
		SkippedInvalidIPs:           invalidIPCount,
		UAWhitelistExcluded:         uaWhitelistExcluded,
		InsertTimeMS:                insertDuration.Milliseconds(),
	}

	// Warn if time filter resulted in zero requests (non-overlapping time range)
	if filteredRequestCount == 0 && (!startTime.IsZero() || !endTime.IsZero()) {
		var timeRangeStr string
		if !startTime.IsZero() && !endTime.IsZero() {
			timeRangeStr = fmt.Sprintf("%s to %s", startTime.Format(time.RFC3339), endTime.Format(time.RFC3339))
		} else if !startTime.IsZero() {
			timeRangeStr = fmt.Sprintf("after %s", startTime.Format(time.RFC3339))
		} else {
			timeRangeStr = fmt.Sprintf("before %s", endTime.Format(time.RFC3339))
		}
		jsonOutput.AddWarning("time_filter_no_results",
			fmt.Sprintf("Trie %q: time filter %q resulted in 0 requests - the time range may not overlap with log data",
				trieName, timeRangeStr), 1)
	}

	// CIDR range analysis (same as original but with parallel trie)
	if len(trieConfig.CIDRRanges) > 0 {
		for _, cidrRange := range trieConfig.CIDRRanges {
			count, err := trieInstance.CountInRange(cidrRange)
			if err != nil {
				jsonOutput.AddWarning("invalid_cidr", fmt.Sprintf("Invalid CIDR range %q: %v", cidrRange, err), 1)
				continue
			}

			var percentage float64
			if trieInstance.CountAll() > 0 {
				percentage = float64(count) / float64(trieInstance.CountAll()) * 100
			}
			trieResult.Stats.CIDRAnalysis = append(trieResult.Stats.CIDRAnalysis, output.CIDRRange{
				CIDR:       cidrRange,
				Requests:   count,
				Percentage: percentage,
			})
		}
	}

	// Clustering (same as original but with parallel trie)
	processClustering(trieConfig, trieInstance.Trie, jsonOutput, &trieResult)

	return trieResult, ipSetToSlice(userAgentWhitelistIPSet), ipSetToSlice(userAgentBlacklistIPSet)
}

// Static runs static analysis from config and returns
// the same *output.JSONOutput as StaticWithRequests, but never
// returns the parsed []ingestor.Request. For the common unfiltered case (no
// UA/endpoint/time filters on any trie) it takes an IP-only parse fast path that
// never materialises ingestor.Request structs, cutting allocations sharply.
//
// When any trie requires non-IP fields (filters present) it delegates to
// StaticWithRequests and drops the requests, since correct
// filtering needs the full request fields.
func Static(cfg *config.Config) (*output.JSONOutput, error) {
	analysisStart := time.Now()
	jsonOutput := output.NewJSONOutput("static", analysisStart)

	// Validate config (mirror StaticWithRequests exactly).
	if cfg == nil {
		jsonOutput.AddError("config_error", "configuration is nil", 1)
		return jsonOutput, fmt.Errorf("configuration is nil")
	}
	if cfg.Static == nil {
		jsonOutput.AddError("config_error", "static configuration section is missing", 1)
		return jsonOutput, fmt.Errorf("static configuration section is missing")
	}
	if len(cfg.StaticTries) == 0 {
		jsonOutput.AddWarning("config_warning", "no static tries configured, analysis may have limited results", 1)
	}

	logFormat := cfg.Static.LogFormat
	if logFormat == "" {
		logFormat = logparser.DefaultLogFormat
	}

	// NewParser revalidates the format as defense-in-depth; for a barrier-passed
	// config this is unreachable (config.Validate ran logparser.ValidateFormat,
	// a total precondition for NewParser success - see ValidateFormat docs), but
	// it stays so a future non-barrier caller of Static() still fails loud.
	parser, err := logparser.NewParser(logFormat)
	if err != nil {
		jsonOutput.AddError("parser_init", fmt.Sprintf("Failed to create parallel parser: %v", err), 1)
		return jsonOutput, err
	}

	// Determine whether any trie needs non-IP fields (filters). This is the same
	// decision made by StaticWithRequests. Only needsNonIPFields drives the branch
	// here: the full path is selected whenever any filter is present, so this fast
	// path never needs to distinguish string fields from other non-IP fields.
	needsNonIPFields := false
	userAgentMatcherForCheck, uaErr := cfg.CreateUserAgentMatcher()
	if uaErr != nil {
		// A configured-but-unreadable UA whitelist/blacklist file is a fatal
		// setup error: silently dropping it would skip ALL UA filtering and
		// produce a wrong ban list. Both static entrypoints fail loud here with
		// identical severity (StaticWithRequestsCtx returns the same error before
		// its trie/jail work). The wrapped loader error already names the file.
		jsonOutput.AddError("useragent_matcher_create", fmt.Sprintf("Failed to create User-Agent matcher: %v", uaErr), 1)
		return jsonOutput, uaErr
	}
	hasGlobalUAFilters := userAgentMatcherForCheck != nil && userAgentMatcherForCheck.Count() > 0
	for _, tc := range cfg.StaticTries {
		if tc == nil {
			continue
		}
		if hasGlobalUAFilters || tc.UserAgentRegex != "" || tc.EndpointRegex != "" {
			needsNonIPFields = true
		}
		if tc.StartTime != nil || tc.EndTime != nil {
			needsNonIPFields = true
		}
	}

	// Filters present: correctness first - delegate to the full path and drop the
	// requests slice.
	if needsNonIPFields {
		result, _, derr := StaticWithRequests(cfg)
		return result, derr
	}

	// IP-only fast path: parse only IPs, no ingestor.Request built.
	parser.SkipStringFields = true
	parser.SkipNonIPFields = true

	parseStart := time.Now()
	ips, invalidCount, perr := parser.ParseFileIPs(cfg.Static.LogFile)
	parseDuration := time.Since(parseStart)
	if perr != nil {
		jsonOutput.AddError("parse_file", fmt.Sprintf("Failed to parse log file %q: %v", cfg.Static.LogFile, perr), 1)
		return jsonOutput, perr
	}

	// Lines longer than logparser.MaxLineLen are skipped by the parser, not
	// analysed: say so instead of dropping them silently.
	if n := parser.Stats().OversizedLines; n > 0 {
		jsonOutput.AddWarning("oversized_lines",
			fmt.Sprintf("%d line(s) longer than %d bytes were skipped", n, logparser.MaxLineLen), 1)
	}

	// TotalRequests must equal len(requests) from the full path: all parsed lines,
	// i.e. nonzero IPs (len(ips)) plus zero-IP lines (invalidCount).
	totalRequests := len(ips) + invalidCount

	jsonOutput.General.LogFile = cfg.Static.LogFile
	jsonOutput.General.TotalRequests = totalRequests
	jsonOutput.General.Parsing.DurationMS = parseDuration.Milliseconds()
	jsonOutput.General.Parsing.RatePerSecond = int64(float64(totalRequests) / parseDuration.Seconds())
	jsonOutput.General.Parsing.Format = logFormat

	if totalRequests == 0 {
		jsonOutput.AddWarning("empty_logfile", "No requests found in logfile", 1)
		// Still run the publish step (expired bans, list edits) - see the same
		// branch in StaticWithRequestsCtx.
		if err := publishJailAndBans(cfg, jsonOutput); err != nil {
			return jsonOutput, err
		}
		return jsonOutput, nil
	}

	// Sort the IPs ONCE - shared across all tries (an extra win vs per-trie sort).
	iputils.RadixSortUint32(ips)

	// True unique-IP count, computed once from the shared sorted slice (single
	// linear pass) and reused by every trie.
	uniqueIPs := iputils.CountDistinctSorted(ips)

	// Process tries in parallel, mirroring StaticWithRequests.
	var trieWG sync.WaitGroup
	var triesMutex sync.Mutex
	trieResults := make([]output.TrieResult, 0, len(cfg.StaticTries))

	type trieWork struct {
		name   string
		config *config.TrieConfig
	}

	trieWorkChan := make(chan trieWork, len(cfg.StaticTries))

	numTrieWorkers := runtime.NumCPU()
	if len(cfg.StaticTries) < numTrieWorkers {
		numTrieWorkers = len(cfg.StaticTries)
	}

	for i := 0; i < numTrieWorkers; i++ {
		trieWG.Add(1)
		go func() {
			defer trieWG.Done()
			for work := range trieWorkChan {
				result := processTrieFromSortedIPs(work.name, work.config, ips, totalRequests, invalidCount, uniqueIPs, jsonOutput)
				triesMutex.Lock()
				trieResults = append(trieResults, result)
				triesMutex.Unlock()
			}
		}()
	}

	for trieName, trieConfig := range cfg.StaticTries {
		trieWorkChan <- trieWork{name: trieName, config: trieConfig}
	}
	close(trieWorkChan)
	trieWG.Wait()

	// Sort results by name for consistency with the sequential/full version.
	sort.Slice(trieResults, func(i, j int) bool {
		return trieResults[i].Name < trieResults[j].Name
	})

	jsonOutput.Tries = trieResults

	// Record the global whitelist entry counts (same as the full path). Only
	// the IP whitelist can be configured here - any UA list forces the full
	// path (needsNonIPFields above) - and it drops nothing from the analysis,
	// so this only feeds the informational JSON count, never an active filter.
	jsonOutput.GlobalFilters = computeGlobalFilters(cfg)

	// General.UniqueIPs is the distinct-IP count of the whole log - here the
	// same number every (unfiltered) trie reports.
	jsonOutput.General.UniqueIPs = uniqueIPs

	// No filters => no User-Agent derived IP sets; UserAgentWhitelistIPs /
	// UserAgentBlacklistIPs stay empty, exactly as the full path produces here.

	// Process jail with whitelist/blacklist if configured.
	if err := publishJailAndBans(cfg, jsonOutput); err != nil {
		return jsonOutput, err
	}

	jsonOutput.UpdateDuration(analysisStart)
	return jsonOutput, nil
}

// processTrieFromSortedIPs builds a single trie from a shared, already
// ascending-sorted slice of nonzero IPs and populates the TrieResult identically
// to processTrie's unfiltered branch (no filters => no UA IP sets, so it
// returns no whitelist/blacklist IPs). sortedIPs is read-only and shared across
// tries; it must not be mutated. totalRequests is the full-path TotalRequests
// (len(ips)+invalidCount) used as the denominator for the invalid-IP warning;
// invalidCount is the number of zero-IP lines skipped during parsing.
// uniqueIPs is the number of distinct values in sortedIPs, computed once by the
// caller (the slice is shared across tries, so per-trie recounting would waste work).
func processTrieFromSortedIPs(trieName string, trieConfig *config.TrieConfig, sortedIPs []uint32,
	totalRequests, invalidCount, uniqueIPs int, jsonOutput *output.JSONOutput) output.TrieResult {

	insertStart := time.Now()

	trieResult := output.TrieResult{
		Name:       trieName,
		Parameters: output.TrieParameters{},
		Stats:      output.TrieStats{},
		Data:       []output.ClusterResult{},
	}

	if trieConfig == nil {
		jsonOutput.AddWarning("config_warning", fmt.Sprintf("Trie configuration %q is nil, skipping", trieName), 1)
		return trieResult
	}

	// Malformed startTime/endTime are caught at config load and fail loud at the
	// pre-work barrier (CFG-01) before analysis runs, so the old invalid_time_format
	// warning that used to mirror processTrie here is dead and removed. This
	// unfiltered fast path carries only the CIDRRanges parameter (and UseForJail,
	// which is filter independent).
	trieResult.Parameters.CIDRRanges = trieConfig.CIDRRanges
	if len(trieConfig.UseForJail) > 0 {
		trieResult.Parameters.UseForJail = trieConfig.UseForJail
	}

	// Build the trie from the shared sorted IPs using the seq prefix-stack build.
	trieInstance := trie.NewLockedTrieSeq()
	trieInstance.BuildSorted(sortedIPs)

	insertDuration := time.Since(insertStart)

	// Invalid-IP warning: identical message and denominator (totalRequests ==
	// len(requests) in the full path). Emitted per trie and naming the trie,
	// like processTrie (where the count depends on the trie's filters).
	if invalidCount > 0 {
		percentage := float64(invalidCount) / float64(totalRequests) * 100
		jsonOutput.AddWarning("invalid_ips_skipped",
			fmt.Sprintf("Trie %q: %d requests (%.1f%%) had invalid/missing IPs (nil or 0.0.0.0) and were skipped - check log format", trieName, invalidCount, percentage), 1)
	}

	// Stats: in the unfiltered branch TotalRequestsAfterFiltering == number of
	// nonzero IPs inserted == len(sortedIPs); SkippedInvalidIPs == invalidCount.
	trieResult.Stats = output.TrieStats{
		TotalRequestsAfterFiltering: len(sortedIPs),
		UniqueIPs:                   uniqueIPs,
		SkippedInvalidIPs:           invalidCount,
		InsertTimeMS:                insertDuration.Milliseconds(),
	}

	// CIDR range analysis (identical to processTrie).
	if len(trieConfig.CIDRRanges) > 0 {
		for _, cidrRange := range trieConfig.CIDRRanges {
			count, err := trieInstance.CountInRange(cidrRange)
			if err != nil {
				jsonOutput.AddWarning("invalid_cidr", fmt.Sprintf("Invalid CIDR range %q: %v", cidrRange, err), 1)
				continue
			}
			var percentage float64
			if trieInstance.CountAll() > 0 {
				percentage = float64(count) / float64(trieInstance.CountAll()) * 100
			}
			trieResult.Stats.CIDRAnalysis = append(trieResult.Stats.CIDRAnalysis, output.CIDRRange{
				CIDR:       cidrRange,
				Requests:   count,
				Percentage: percentage,
			})
		}
	}

	// Clustering (identical to processTrie).
	processClustering(trieConfig, trieInstance.Trie, jsonOutput, &trieResult)

	return trieResult
}

func processClustering(trieConfig *config.TrieConfig, trieInstance *trie.Trie,
	jsonOutput *output.JSONOutput, trieResult *output.TrieResult) {
	// Implementation same as original
	if len(trieConfig.ClusterArgSets) == 0 {
		return
	}

	for _, argSet := range trieConfig.ClusterArgSets {
		// TrieResult.Data must hold exactly one entry per configured arg set, in
		// config order: ProcessJailWithWhitelist pairs Data[i] with UseForJail[i]
		// by position (and the renderers number the sets the same way). An
		// invalid set therefore still gets an entry - an empty placeholder with
		// its parameters - instead of being skipped, which would shift every
		// later set onto its left neighbour's useForJail flag.
		clusterResult := output.ClusterResult{
			Parameters: output.ClusterParameters{
				MinClusterSize:       argSet.MinClusterSize,
				MinDepth:             argSet.MinDepth,
				MaxDepth:             argSet.MaxDepth,
				MeanSubnetDifference: argSet.MeanSubnetDifference,
			},
			DetectedRanges: []output.CIDRRange{},
			MergedRanges:   []output.CIDRRange{},
		}

		if argSet.MinDepth > argSet.MaxDepth {
			jsonOutput.AddError("invalid_depth_params",
				fmt.Sprintf("minDepth (%d) must be <= maxDepth (%d)", argSet.MinDepth, argSet.MaxDepth), 1)
			trieResult.Data = append(trieResult.Data, clusterResult)
			continue
		}
		if argSet.MaxDepth > 32 {
			jsonOutput.AddError("invalid_depth_params",
				fmt.Sprintf("maxDepth (%d) must be <= 32", argSet.MaxDepth), 1)
			trieResult.Data = append(trieResult.Data, clusterResult)
			continue
		}

		clusterStart := time.Now()
		cidrs := trieInstance.CollectCIDRs(argSet.MinClusterSize, argSet.MinDepth, argSet.MaxDepth, argSet.MeanSubnetDifference)
		clusterResult.ExecutionTimeUS = time.Since(clusterStart).Microseconds()

		// Parse CIDRs once for reuse across operations
		var cidrIPNets []*net.IPNet
		// CountAll counts every insertion (duplicate IPs included), so this is
		// the request total - percentages below are percent-of-requests.
		totalRequests := float64(trieInstance.CountAll())

		for _, cidrStr := range cidrs {
			_, ipNet, err := net.ParseCIDR(cidrStr)
			if err != nil {
				jsonOutput.AddWarning("cidr_parse_error",
					fmt.Sprintf("Error parsing CIDR %q: %v", cidrStr, err), 1)
				continue
			}
			cidrIPNets = append(cidrIPNets, ipNet)

			// Use IPNet-native count function for speed
			count := trieInstance.CountInRangeIPNet(ipNet)
			var percentage float64
			if totalRequests > 0 {
				percentage = float64(count) / totalRequests * 100
			}

			clusterResult.DetectedRanges = append(clusterResult.DetectedRanges, output.CIDRRange{
				CIDR:       cidrStr,
				Requests:   count,
				Percentage: percentage,
			})
		}

		// Use IPNet-native merge function to avoid re-parsing
		mergedIPNets := cidr.MergeIPNets(cidrIPNets)
		for _, mergedIPNet := range mergedIPNets {
			count := trieInstance.CountInRangeIPNet(mergedIPNet)
			var percentage float64
			if totalRequests > 0 {
				percentage = float64(count) / totalRequests * 100
			}

			clusterResult.MergedRanges = append(clusterResult.MergedRanges, output.CIDRRange{
				CIDR:       mergedIPNet.String(),
				Requests:   count,
				Percentage: percentage,
			})
		}

		trieResult.Data = append(trieResult.Data, clusterResult)
	}
}
