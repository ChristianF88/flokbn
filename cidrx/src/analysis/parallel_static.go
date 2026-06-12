package analysis

import (
	"fmt"
	"net"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/ChristianF88/cidrx/cidr"
	"github.com/ChristianF88/cidrx/config"
	"github.com/ChristianF88/cidrx/ingestor"
	"github.com/ChristianF88/cidrx/iputils"
	"github.com/ChristianF88/cidrx/jail"
	"github.com/ChristianF88/cidrx/logparser"
	"github.com/ChristianF88/cidrx/output"
	"github.com/ChristianF88/cidrx/pools"
	"github.com/ChristianF88/cidrx/trie"
)

// ParallelStaticFromConfigWithRequests runs parallel static analysis
func ParallelStaticFromConfigWithRequests(cfg *config.Config) (*output.JSONOutput, []ingestor.Request, error) {
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

	if len(cfg.StaticTries) == 0 {
		jsonOutput.AddWarning("config_warning", "no static tries configured, analysis may have limited results", 1)
	}

	// Parse requests once
	logFormat := cfg.Static.LogFormat
	if logFormat == "" {
		logFormat = "%^ %^ %^ [%t] \"%r\" %s %b %^ \"%u\" \"%h\""
	}

	// Create parser
	parser, err := logparser.NewParser(logFormat)
	if err != nil {
		jsonOutput.AddError("parser_init", fmt.Sprintf("failed to create parallel parser: %v", err), 1)
		return jsonOutput, nil, err
	}

	// Check if any trie config requires string fields (URI/UserAgent) or non-IP fields
	needsStringFields := false
	needsNonIPFields := false
	userAgentMatcherForCheck, _ := cfg.CreateUserAgentMatcher()
	hasGlobalUAFilters := userAgentMatcherForCheck != nil && userAgentMatcherForCheck.Count() > 0
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
		jsonOutput.AddError("parse_file", fmt.Sprintf("failed to parse log file %s: %v", cfg.Static.LogFile, err), 1)
		return jsonOutput, nil, err
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

	// Accumulate User-Agent derived IPs across all tries (thread-safe via triesMutex)
	globalUserAgentWhitelistIPSet := make(map[string]bool)
	globalUserAgentBlacklistIPSet := make(map[string]bool)

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
				result, whitelistIPs, blacklistIPs := processTrieParallel(work.name, work.config, requests, cfg, jsonOutput)

				// Thread-safe append to results and merge UA IPs
				triesMutex.Lock()
				trieResults = append(trieResults, result)
				for _, ip := range whitelistIPs {
					globalUserAgentWhitelistIPSet[ip] = true
				}
				for _, ip := range blacklistIPs {
					globalUserAgentBlacklistIPSet[ip] = true
				}
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

	// Sort results by name for consistency with sequential version
	sort.Slice(trieResults, func(i, j int) bool {
		return trieResults[i].Name < trieResults[j].Name
	})

	// Add results to output
	jsonOutput.Tries = trieResults

	// Set General.UniqueIPs to the max across all tries
	for _, tr := range trieResults {
		if tr.Stats.UniqueIPs > jsonOutput.General.UniqueIPs {
			jsonOutput.General.UniqueIPs = tr.Stats.UniqueIPs
		}
	}

	// Convert global User-Agent IP sets to slices for jail processing
	for ip := range globalUserAgentWhitelistIPSet {
		jsonOutput.UserAgentWhitelistIPs = append(jsonOutput.UserAgentWhitelistIPs, ip)
	}
	for ip := range globalUserAgentBlacklistIPSet {
		jsonOutput.UserAgentBlacklistIPs = append(jsonOutput.UserAgentBlacklistIPs, ip)
	}

	// Process jail with whitelist/blacklist if configured
	if cfg.Global != nil && cfg.Global.JailFile != "" && cfg.Global.BanFile != "" {
		if err := ProcessJailWithWhitelist(cfg, jsonOutput); err != nil {
			jsonOutput.AddError("jail_processing", fmt.Sprintf("failed to process jail with whitelist/blacklist: %v", err), 1)
		}
	}

	jsonOutput.UpdateDuration(analysisStart)
	return jsonOutput, requests, nil
}

// processTrieParallel processes a single trie with parallel insertion.
// Returns the trie result along with collected User-Agent whitelist/blacklist IPs.
func processTrieParallel(trieName string, trieConfig *config.TrieConfig, requests []ingestor.Request,
	cfg *config.Config, jsonOutput *output.JSONOutput) (output.TrieResult, []string, []string) {

	insertStart := time.Now()

	trieResult := output.TrieResult{
		Name:       trieName,
		Parameters: output.TrieParameters{},
		Stats:      output.TrieStats{},
		Data:       []output.ClusterResult{},
	}

	if trieConfig == nil {
		jsonOutput.AddWarning("config_warning", fmt.Sprintf("trie configuration '%s' is nil, skipping", trieName), 1)
		return trieResult, nil, nil
	}

	// Warn if time parsing failed
	if trieConfig.StartTimeRaw != "" && trieConfig.StartTime == nil {
		jsonOutput.AddWarning("invalid_time_format",
			fmt.Sprintf("Trie '%s': Failed to parse startTime '%s' - expected RFC3339 format (e.g., 2025-01-01T00:00:00Z)",
				trieName, trieConfig.StartTimeRaw), 1)
	}
	if trieConfig.EndTimeRaw != "" && trieConfig.EndTime == nil {
		jsonOutput.AddWarning("invalid_time_format",
			fmt.Sprintf("Trie '%s': Failed to parse endTime '%s' - expected RFC3339 format (e.g., 2025-01-01T00:00:00Z)",
				trieName, trieConfig.EndTimeRaw), 1)
	}

	// Warn if endTime is before startTime (invalid time range)
	if trieConfig.StartTime != nil && trieConfig.EndTime != nil && trieConfig.EndTime.Before(*trieConfig.StartTime) {
		jsonOutput.AddWarning("invalid_time_range",
			fmt.Sprintf("Trie '%s': endTime (%s) is before startTime (%s) - no requests can match this range",
				trieName, trieConfig.EndTime.Format(time.RFC3339), trieConfig.StartTime.Format(time.RFC3339)), 1)
	}

	// Set CIDRRanges after null check
	trieResult.Parameters.CIDRRanges = trieConfig.CIDRRanges

	// Create parallel trie backed by the seq allocator: this trie is built by a
	// single goroutine via BuildSorted (one of the radix-sorted branches
	// below), so the lock-free sequential allocator is safe here.
	trieInstance := trie.NewLockedTrieSeq()

	// Apply filtering and collect IPs for parallel insertion
	var startTime, endTime time.Time
	if trieConfig.StartTime != nil {
		startTime = *trieConfig.StartTime
	}
	if trieConfig.EndTime != nil {
		endTime = *trieConfig.EndTime
	}

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

	// Create User-Agent matcher
	userAgentMatcher, err := cfg.CreateUserAgentMatcher()
	if err != nil {
		jsonOutput.AddError("useragent_matcher_create", fmt.Sprintf("failed to create User-Agent matcher: %v", err), 1)
		userAgentMatcher = nil
	}

	// Filter requests and collect IPs for batch insertion
	filteredRequests := make([]ingestor.Request, 0, len(requests))
	var ipsToInsertUint32 []uint32

	// User-Agent tracking
	userAgentWhitelistIPs := make([]string, 0)
	userAgentBlacklistIPs := make([]string, 0)
	userAgentWhitelistIPSet := make(map[string]bool)
	userAgentBlacklistIPSet := make(map[string]bool)

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

	// True unique-IP count, derived from the sorted insert slice in a single
	// linear pass — keeps the trie insert hot path untouched.
	var uniqueIPs int

	// Fast path for unfiltered data: use sorted insertion optimization
	if !hasFilters {
		// Use IPUint32 directly — no conversion needed (parsed directly to uint32)
		ipUints := make([]uint32, 0, len(requests))
		for _, r := range requests {
			// Skip 0 IPs (invalid or failed to parse)
			if r.IPUint32 == 0 {
				invalidIPCount++
				continue
			}
			ipUints = append(ipUints, r.IPUint32)
			filteredRequests = append(filteredRequests, r)
		}

		// Radix sort: O(n) vs sort.Slice O(n log n) — 10-15x faster for large arrays
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
			err = processRequestsConcurrentlyParallel(
				requests, trieConfig, startTime, endTime,
				userAgentMatcher,
				userAgentWhitelistIPSet, userAgentBlacklistIPSet,
				&userAgentWhitelistIPs, &userAgentBlacklistIPs,
				&filteredRequests, &ipsToInsertUint32, &invalidIPCount)
			if err != nil {
				jsonOutput.AddError("concurrent_filtering", fmt.Sprintf("failed to process requests concurrently: %v", err), 1)
			}
		} else {
			// Sequential filtering for simple cases (faster for small datasets)
			processRequestsSequentiallyParallel(
				requests, trieConfig, startTime, endTime,
				userAgentMatcher,
				userAgentWhitelistIPSet, userAgentBlacklistIPSet,
				&userAgentWhitelistIPs, &userAgentBlacklistIPs,
				&filteredRequests, &ipsToInsertUint32, &invalidIPCount)
		}

		// Radix sort + batch sorted insert — same optimization as unfiltered fast path
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
			fmt.Sprintf("%d requests (%.1f%%) had invalid/missing IPs (nil or 0.0.0.0) and were skipped - check log format", invalidIPCount, percentage), 1)
	}

	// Set trie stats
	trieResult.Stats = output.TrieStats{
		TotalRequestsAfterFiltering: len(filteredRequests),
		UniqueIPs:                   uniqueIPs,
		SkippedInvalidIPs:           invalidIPCount,
		InsertTimeMS:                insertDuration.Milliseconds(),
	}

	// Warn if time filter resulted in zero requests (non-overlapping time range)
	if len(filteredRequests) == 0 && (!startTime.IsZero() || !endTime.IsZero()) {
		var timeRangeStr string
		if !startTime.IsZero() && !endTime.IsZero() {
			timeRangeStr = fmt.Sprintf("%s to %s", startTime.Format(time.RFC3339), endTime.Format(time.RFC3339))
		} else if !startTime.IsZero() {
			timeRangeStr = fmt.Sprintf("after %s", startTime.Format(time.RFC3339))
		} else {
			timeRangeStr = fmt.Sprintf("before %s", endTime.Format(time.RFC3339))
		}
		jsonOutput.AddWarning("time_filter_no_results",
			fmt.Sprintf("Trie '%s': Time filter (%s) resulted in 0 requests - the time range may not overlap with log data",
				trieName, timeRangeStr), 1)
	}

	// CIDR range analysis (same as original but with parallel trie)
	if len(trieConfig.CIDRRanges) > 0 {
		for _, cidrRange := range trieConfig.CIDRRanges {
			count, err := trieInstance.CountInRange(cidrRange)
			if err != nil {
				jsonOutput.AddWarning("invalid_cidr", fmt.Sprintf("Invalid CIDR range '%s': %v", cidrRange, err), 1)
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

	return trieResult, userAgentWhitelistIPs, userAgentBlacklistIPs
}

// ParallelStaticFromConfigNoRequests runs parallel static analysis and returns
// the same *output.JSONOutput as ParallelStaticFromConfigWithRequests, but never
// returns the parsed []ingestor.Request. For the common unfiltered case (no
// UA/endpoint/time filters on any trie) it takes an IP-only parse fast path that
// never materialises ingestor.Request structs, cutting allocations sharply.
//
// When any trie requires non-IP fields (filters present) it delegates to
// ParallelStaticFromConfigWithRequests and drops the requests, since correct
// filtering needs the full request fields.
func ParallelStaticFromConfigNoRequests(cfg *config.Config) (*output.JSONOutput, error) {
	analysisStart := time.Now()
	jsonOutput := output.NewJSONOutput("static", analysisStart)

	// Validate config (mirror ParallelStaticFromConfigWithRequests exactly).
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
		logFormat = "%^ %^ %^ [%t] \"%r\" %s %b %^ \"%u\" \"%h\""
	}

	parser, err := logparser.NewParser(logFormat)
	if err != nil {
		jsonOutput.AddError("parser_init", fmt.Sprintf("failed to create parallel parser: %v", err), 1)
		return jsonOutput, err
	}

	// Determine whether any trie needs non-IP fields (filters). This is the same
	// decision made by ParallelStaticFromConfigWithRequests.
	needsStringFields := false
	needsNonIPFields := false
	userAgentMatcherForCheck, _ := cfg.CreateUserAgentMatcher()
	hasGlobalUAFilters := userAgentMatcherForCheck != nil && userAgentMatcherForCheck.Count() > 0
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

	// Filters present: correctness first — delegate to the full path and drop the
	// requests slice.
	if needsNonIPFields {
		_ = needsStringFields
		result, _, derr := ParallelStaticFromConfigWithRequests(cfg)
		return result, derr
	}

	// IP-only fast path: parse only IPs, no ingestor.Request built.
	parser.SkipStringFields = true
	parser.SkipNonIPFields = true

	parseStart := time.Now()
	ips, invalidCount, perr := parser.ParseFileIPs(cfg.Static.LogFile)
	parseDuration := time.Since(parseStart)
	if perr != nil {
		jsonOutput.AddError("parse_file", fmt.Sprintf("failed to parse log file %s: %v", cfg.Static.LogFile, perr), 1)
		return jsonOutput, perr
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
		return jsonOutput, nil
	}

	// Sort the IPs ONCE — shared across all tries (an extra win vs per-trie sort).
	iputils.RadixSortUint32(ips)

	// True unique-IP count, computed once from the shared sorted slice (single
	// linear pass) and reused by every trie.
	uniqueIPs := iputils.CountDistinctSorted(ips)

	// Process tries in parallel, mirroring ParallelStaticFromConfigWithRequests.
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

	// Set General.UniqueIPs to the max across all tries.
	for _, tr := range trieResults {
		if tr.Stats.UniqueIPs > jsonOutput.General.UniqueIPs {
			jsonOutput.General.UniqueIPs = tr.Stats.UniqueIPs
		}
	}

	// No filters => no User-Agent derived IP sets; UserAgentWhitelistIPs /
	// UserAgentBlacklistIPs stay empty, exactly as the full path produces here.

	// Process jail with whitelist/blacklist if configured.
	if cfg.Global != nil && cfg.Global.JailFile != "" && cfg.Global.BanFile != "" {
		if err := ProcessJailWithWhitelist(cfg, jsonOutput); err != nil {
			jsonOutput.AddError("jail_processing", fmt.Sprintf("failed to process jail with whitelist/blacklist: %v", err), 1)
		}
	}

	jsonOutput.UpdateDuration(analysisStart)
	return jsonOutput, nil
}

// processTrieFromSortedIPs builds a single trie from a shared, already
// ascending-sorted slice of nonzero IPs and populates the TrieResult identically
// to processTrieParallel's unfiltered branch (no filters => no UA IP sets, so it
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
		jsonOutput.AddWarning("config_warning", fmt.Sprintf("trie configuration '%s' is nil, skipping", trieName), 1)
		return trieResult
	}

	// Warn if time parsing failed (mirrors processTrieParallel). A trie whose
	// StartTimeRaw/EndTimeRaw failed to parse has nil StartTime/EndTime and thus
	// reaches this unfiltered fast path — the warning must still fire.
	if trieConfig.StartTimeRaw != "" && trieConfig.StartTime == nil {
		jsonOutput.AddWarning("invalid_time_format",
			fmt.Sprintf("Trie '%s': Failed to parse startTime '%s' - expected RFC3339 format (e.g., 2025-01-01T00:00:00Z)",
				trieName, trieConfig.StartTimeRaw), 1)
	}
	if trieConfig.EndTimeRaw != "" && trieConfig.EndTime == nil {
		jsonOutput.AddWarning("invalid_time_format",
			fmt.Sprintf("Trie '%s': Failed to parse endTime '%s' - expected RFC3339 format (e.g., 2025-01-01T00:00:00Z)",
				trieName, trieConfig.EndTimeRaw), 1)
	}

	// The time-range warning in processTrieParallel needs both StartTime and
	// EndTime non-nil, which forces the full (filtered) path, so it can never
	// fire here; we mirror that by only carrying the CIDRRanges parameter (and
	// UseForJail, which is filter independent).
	trieResult.Parameters.CIDRRanges = trieConfig.CIDRRanges
	if len(trieConfig.UseForJail) > 0 {
		trieResult.Parameters.UseForJail = trieConfig.UseForJail
	}

	// Build the trie from the shared sorted IPs using the seq prefix-stack build.
	trieInstance := trie.NewLockedTrieSeq()
	trieInstance.BuildSorted(sortedIPs)

	insertDuration := time.Since(insertStart)

	// Invalid-IP warning: identical message and denominator (totalRequests ==
	// len(requests) in the full path).
	if invalidCount > 0 {
		percentage := float64(invalidCount) / float64(totalRequests) * 100
		jsonOutput.AddWarning("invalid_ips_skipped",
			fmt.Sprintf("%d requests (%.1f%%) had invalid/missing IPs (nil or 0.0.0.0) and were skipped - check log format", invalidCount, percentage), 1)
	}

	// Stats: in the unfiltered branch TotalRequestsAfterFiltering == number of
	// nonzero IPs inserted == len(sortedIPs); SkippedInvalidIPs == invalidCount.
	trieResult.Stats = output.TrieStats{
		TotalRequestsAfterFiltering: len(sortedIPs),
		UniqueIPs:                   uniqueIPs,
		SkippedInvalidIPs:           invalidCount,
		InsertTimeMS:                insertDuration.Milliseconds(),
	}

	// CIDR range analysis (identical to processTrieParallel).
	if len(trieConfig.CIDRRanges) > 0 {
		for _, cidrRange := range trieConfig.CIDRRanges {
			count, err := trieInstance.CountInRange(cidrRange)
			if err != nil {
				jsonOutput.AddWarning("invalid_cidr", fmt.Sprintf("Invalid CIDR range '%s': %v", cidrRange, err), 1)
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

	// Clustering (identical to processTrieParallel).
	processClustering(trieConfig, trieInstance.Trie, jsonOutput, &trieResult)

	return trieResult
}

// processRequestsConcurrentlyParallel implements high-performance concurrent filtering
func processRequestsConcurrentlyParallel(
	requests []ingestor.Request,
	trieConfig *config.TrieConfig,
	startTime, endTime time.Time,
	userAgentMatcher *cidr.UserAgentMatcher,
	userAgentWhitelistIPSet, userAgentBlacklistIPSet map[string]bool,
	userAgentWhitelistIPs, userAgentBlacklistIPs *[]string,
	filteredRequests *[]ingestor.Request,
	ipsToInsert *[]uint32,
	invalidIPCount *int) error {

	// Determine optimal worker count for filtering
	numWorkers := runtime.NumCPU()
	if numWorkers > 8 {
		numWorkers = 8 // Cap at 8 to reduce contention and mutex overhead
	}
	if len(requests) < 50000 {
		numWorkers = 4 // Use fewer workers for smaller datasets
	}

	// Pre-allocate result slice with estimated capacity
	resultCapacity := len(requests) / 2 // Estimate 50% will pass filtering
	if resultCapacity < 1000 {
		resultCapacity = 1000
	}

	// Channels for work distribution - smaller buffers reduce memory overhead
	requestChan := make(chan requestChunk, numWorkers)
	resultChan := make(chan filterResult, numWorkers*4)

	// Worker synchronization
	var wg sync.WaitGroup

	// Start filter workers
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			filterWorker(requestChan, resultChan, trieConfig, startTime, endTime,
				userAgentMatcher)
		}()
	}

	// Start result collector
	var collectorWG sync.WaitGroup

	// Collect User-Agent whitelist/blacklist results
	var whitelistMutex, blacklistMutex sync.Mutex

	// Track invalid IPs in collector
	var localInvalidCount int

	collectorWG.Add(1)
	go func() {
		defer collectorWG.Done()
		for result := range resultChan {
			if result.shouldInclude {
				// Skip 0 IPs (invalid or failed to parse)
				if result.request.IPUint32 == 0 {
					localInvalidCount++
					continue
				}
				*filteredRequests = append(*filteredRequests, result.request)
				*ipsToInsert = append(*ipsToInsert, result.request.IPUint32)
			}

			// Collect User-Agent whitelist IPs (only if IP is valid)
			if result.isWhitelistedUA && result.request.IPUint32 != 0 {
				whitelistMutex.Lock()
				ipStr := ingestor.Uint32ToIPString(result.request.IPUint32)
				if !userAgentWhitelistIPSet[ipStr] {
					userAgentWhitelistIPSet[ipStr] = true
					*userAgentWhitelistIPs = append(*userAgentWhitelistIPs, ipStr)
				}
				whitelistMutex.Unlock()
			}

			// Collect User-Agent blacklist IPs (only if IP is valid)
			if result.isBlacklistedUA && result.request.IPUint32 != 0 {
				blacklistMutex.Lock()
				ipStr := ingestor.Uint32ToIPString(result.request.IPUint32)
				if !userAgentBlacklistIPSet[ipStr] {
					userAgentBlacklistIPSet[ipStr] = true
					*userAgentBlacklistIPs = append(*userAgentBlacklistIPs, ipStr)
				}
				blacklistMutex.Unlock()
			}
		}
		// Update the shared invalid count
		*invalidIPCount += localInvalidCount
	}()

	// Distribute work in larger chunks to reduce overhead
	chunkSize := len(requests) / (numWorkers * 2) // 2 chunks per worker for better efficiency
	if chunkSize < 5000 {
		chunkSize = 5000 // Larger minimum chunk size
	}
	if chunkSize > 50000 {
		chunkSize = 50000 // Larger maximum chunk size
	}

	for i := 0; i < len(requests); i += chunkSize {
		end := i + chunkSize
		if end > len(requests) {
			end = len(requests)
		}

		requestChan <- requestChunk{
			requests: requests[i:end],
			start:    i,
			end:      end,
		}
	}
	close(requestChan)

	// Wait for all workers to complete
	wg.Wait()
	close(resultChan)

	// Wait for result collection to complete
	collectorWG.Wait()

	return nil
}

// processRequestsSequentiallyParallel provides optimized sequential processing for simple filtering cases
func processRequestsSequentiallyParallel(
	requests []ingestor.Request,
	trieConfig *config.TrieConfig,
	startTime, endTime time.Time,
	userAgentMatcher *cidr.UserAgentMatcher,
	userAgentWhitelistIPSet, userAgentBlacklistIPSet map[string]bool,
	userAgentWhitelistIPs, userAgentBlacklistIPs *[]string,
	filteredRequests *[]ingestor.Request,
	ipsToInsert *[]uint32,
	invalidIPCount *int) {

	// Single pass through requests with optimized filtering
	for _, r := range requests {
		// Apply time filtering
		if !startTime.IsZero() && r.Timestamp.Before(startTime) {
			continue
		}
		if !endTime.IsZero() && r.Timestamp.After(endTime) {
			continue
		}

		// Apply regex filtering
		if !trieConfig.ShouldIncludeRequest(r) {
			continue
		}

		// Skip 0 IPs (invalid or failed to parse)
		if r.IPUint32 == 0 {
			*invalidIPCount++
			continue
		}

		// Only convert IP to string if we need it for User-Agent pattern processing
		var ipStr string
		var ipStrComputed bool
		isWhitelistedUA := false
		isBlacklistedUA := false

		// Check User-Agent patterns using ultra-fast exact matching
		if userAgentMatcher != nil {
			uaResult := userAgentMatcher.CheckUserAgent(r.UserAgent)
			isWhitelistedUA = (uaResult == cidr.UserAgentWhitelist)
			isBlacklistedUA = (uaResult == cidr.UserAgentBlacklist)

			if isWhitelistedUA {
				if !ipStrComputed {
					ipStr = ingestor.Uint32ToIPString(r.IPUint32)
					ipStrComputed = true
				}
				if !userAgentWhitelistIPSet[ipStr] {
					userAgentWhitelistIPSet[ipStr] = true
					*userAgentWhitelistIPs = append(*userAgentWhitelistIPs, ipStr)
				}
			}

			if isBlacklistedUA {
				if !ipStrComputed {
					ipStr = ingestor.Uint32ToIPString(r.IPUint32)
					ipStrComputed = true
				}
				if !userAgentBlacklistIPSet[ipStr] {
					userAgentBlacklistIPSet[ipStr] = true
					*userAgentBlacklistIPs = append(*userAgentBlacklistIPs, ipStr)
				}
			}
		}

		// Include in trie if not whitelisted by User-Agent
		if !isWhitelistedUA {
			*filteredRequests = append(*filteredRequests, r)
			*ipsToInsert = append(*ipsToInsert, r.IPUint32)
		}
	}
}

func processClustering(trieConfig *config.TrieConfig, trieInstance *trie.Trie,
	jsonOutput *output.JSONOutput, trieResult *output.TrieResult) {
	// Implementation same as original
	if len(trieConfig.ClusterArgSets) == 0 {
		return
	}

	for _, argSet := range trieConfig.ClusterArgSets {
		if argSet.MinDepth > argSet.MaxDepth {
			jsonOutput.AddError("invalid_depth_params",
				fmt.Sprintf("minDepth (%d) must be <= maxDepth (%d)", argSet.MinDepth, argSet.MaxDepth), 1)
			continue
		}

		clusterStart := time.Now()
		cidrs := trieInstance.CollectCIDRs(argSet.MinClusterSize, argSet.MinDepth, argSet.MaxDepth, argSet.MeanSubnetDifference)
		clusterDuration := time.Since(clusterStart)

		clusterResult := output.ClusterResult{
			Parameters: output.ClusterParameters{
				MinClusterSize:       argSet.MinClusterSize,
				MinDepth:             argSet.MinDepth,
				MaxDepth:             argSet.MaxDepth,
				MeanSubnetDifference: argSet.MeanSubnetDifference,
			},
			ExecutionTimeUS: clusterDuration.Microseconds(),
			DetectedRanges:  []output.CIDRRange{},
			MergedRanges:    []output.CIDRRange{},
		}

		// Parse CIDRs once for reuse across operations
		var cidrIPNets []*net.IPNet
		// CountAll counts every insertion (duplicate IPs included), so this is
		// the request total — percentages below are percent-of-requests.
		totalRequests := float64(trieInstance.CountAll())

		for _, cidrStr := range cidrs {
			_, ipNet, err := net.ParseCIDR(cidrStr)
			if err != nil {
				jsonOutput.AddWarning("cidr_parse_error",
					fmt.Sprintf("error parsing CIDR %s: %v", cidrStr, err), 1)
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

// ProcessJailWithWhitelist processes jail updates with whitelist/blacklist filtering
func ProcessJailWithWhitelist(cfg *config.Config, jsonOutput *output.JSONOutput) error {
	if cfg.Global == nil {
		return fmt.Errorf("global configuration is required for jail processing")
	}

	// Load whitelist and blacklist
	whitelistCIDRs, err := cfg.LoadWhitelistCIDRs()
	if err != nil {
		jsonOutput.AddError("whitelist_load", fmt.Sprintf("failed to load whitelist: %v", err), 1)
		return err
	}
	blacklistCIDRs, err := cfg.LoadBlacklistCIDRs()
	if err != nil {
		jsonOutput.AddError("blacklist_load", fmt.Sprintf("failed to load blacklist: %v", err), 1)
		return err
	}

	// Collect all CIDRs from all tries that are marked for jail
	allJailCIDRs := pools.Pools.GetStringSlice()
	defer pools.Pools.ReturnStringSlice(allJailCIDRs)
	for _, trieResult := range jsonOutput.Tries {
		for i, clusterResult := range trieResult.Data {
			if len(trieResult.Parameters.UseForJail) > i && trieResult.Parameters.UseForJail[i] {
				for _, mergedRange := range clusterResult.MergedRanges {
					allJailCIDRs = append(allJailCIDRs, mergedRange.CIDR)
				}
			}
		}
	}

	// Combine CIDR whitelist and User-Agent-whitelisted IPs into one list:
	// every whitelist source must win everywhere (pre-jail filter and the
	// final publish pass below).
	allWhitelists := pools.Pools.GetStringSlice()
	defer pools.Pools.ReturnStringSlice(allWhitelists)
	allWhitelists = append(allWhitelists, whitelistCIDRs...)
	for _, ip := range jsonOutput.UserAgentWhitelistIPs {
		allWhitelists = append(allWhitelists, ip+"/32")
	}

	// Apply whitelist filtering
	filteredJailCIDRs := cidr.RemoveWhitelisted(allJailCIDRs, allWhitelists)

	// Log whitelist filtering results
	if len(whitelistCIDRs) > 0 {
		removedCount := len(allJailCIDRs) - len(filteredJailCIDRs)
		jsonOutput.AddWarning("whitelist_applied", fmt.Sprintf("Whitelist filtering prevented %d CIDRs from being added to jail", removedCount), 0)
	}

	// Load existing jail
	jailInstance, err := jail.FileToJail(cfg.GetJailFile())
	if err != nil {
		jsonOutput.AddError("jail_load", fmt.Sprintf("failed to load jail: %v", err), 1)
		return err
	}

	// Add User-Agent blacklisted IPs to jail
	userAgentBlacklistCIDRs := pools.Pools.GetStringSlice()
	defer pools.Pools.ReturnStringSlice(userAgentBlacklistCIDRs)
	if len(jsonOutput.UserAgentBlacklistIPs) > 0 {
		for _, ip := range jsonOutput.UserAgentBlacklistIPs {
			userAgentBlacklistCIDRs = append(userAgentBlacklistCIDRs, ip+"/32")
		}
		filteredJailCIDRs = append(filteredJailCIDRs, userAgentBlacklistCIDRs...)
	}

	// Update jail with filtered CIDRs
	if len(filteredJailCIDRs) > 0 {
		if err := jailInstance.Update(filteredJailCIDRs); err != nil {
			jsonOutput.AddWarning("jail_update", fmt.Sprintf("some CIDRs failed during jail update: %v", err), 1)
		}

		err = jail.JailToFile(jailInstance, cfg.GetJailFile())
		if err != nil {
			jsonOutput.AddError("jail_save", fmt.Sprintf("failed to save jail: %v", err), 1)
			return err
		}
	}

	// Always generate ban file from jail. ComposeBanLists is the publish
	// choke point: whitelists win over active bans AND the manual blacklist.
	activeBans := jailInstance.ListActiveBans()
	publishBans, publishBlacklist := cidr.ComposeBanLists(activeBans, blacklistCIDRs, allWhitelists)

	err = jail.WriteBanFileWithBlacklist(cfg.GetBanFile(), publishBans, publishBlacklist)
	if err != nil {
		jsonOutput.AddError("banfile_write", fmt.Sprintf("failed to write ban file: %v", err), 1)
		return err
	}

	if len(publishBlacklist) > 0 {
		jsonOutput.AddWarning("blacklist_applied", fmt.Sprintf("Added %d manual blacklist entries to ban file", len(publishBlacklist)), 0)
	}

	return nil
}
